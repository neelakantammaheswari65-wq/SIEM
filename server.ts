import http from 'http';
import express, { Request, Response, NextFunction } from 'express';
import path from 'path';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import dotenv from 'dotenv';
import { createServer as createViteServer } from 'vite';
import { db, DBUser } from './server/db/database';
import { siemServer } from './server/services/siemServerEngine';
import { securityAbuse } from './server/services/securityAbuseService';
import { wsManager } from './server/services/wsServer';
import { UserRole } from './src/types/siem';
import { demoDataset, SEVEN_DETECTION_RULES } from './server/services/demoDatasetService';

// Load environment variables
dotenv.config();

const app = express();
const PORT = 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'siem_soc_jwt_secure_secret_key_2026';

app.use(express.json());

// Helper to strip sensitive passwordHash
function sanitizeUser(user: DBUser) {
  const { passwordHash, ...sanitized } = user;
  return sanitized;
}

// Authentication Middleware
export function authenticateJWT(req: Request, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized: Missing or malformed token' });
  }

  const token = authHeader.substring(7);

  // Support local demo tokens (e.g. demo_token_schen, demo_token_dkim, demo_token_amercer, demo_token_admin)
  if (token.startsWith('demo_token_')) {
    const uname = token.split('_')[2];
    const user =
      (uname ? db.getUserByUsername(uname) : undefined) ||
      (uname === 'admin' ? db.getUserByUsername('admin') : undefined) ||
      db.getUsers().find((u) => u.username.toLowerCase() === (uname || '').toLowerCase());
    if (user && user.status === 'ACTIVE') {
      (req as any).user = user;
      return next();
    }
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET) as { id: number; username: string };
    const user = (decoded.username ? db.getUserByUsername(decoded.username) : undefined) || db.getUserById(decoded.id);
    if (!user || user.status !== 'ACTIVE') {
      return res.status(401).json({ error: 'Unauthorized: User not found or inactive' });
    }
    (req as any).user = user;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Unauthorized: Invalid or expired token' });
  }
}

// Strict Role-Based Access Control (RBAC) Middleware
export function requireRoles(...allowedRoles: string[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    const user = (req as any).user as DBUser | undefined;
    if (!user) {
      return res.status(401).json({ error: 'Unauthorized: Authentication required.' });
    }

    const userRole = user.role;
    const normalizedUserRole = userRole === 'EMPLOYEE' ? 'VIEWER' : userRole;
    const isAllowed = allowedRoles.some((r) => {
      const normalizedR = r === 'EMPLOYEE' ? 'VIEWER' : r;
      return normalizedR === normalizedUserRole || r === userRole;
    });

    if (!isAllowed) {
      const clientIp = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '127.0.0.1';
      const resource = req.originalUrl || req.path || 'PROTECTED_RESOURCE';
      const empId = user.employeeId || user.username || `EMP-${user.id}`;
      const reason = `User ${empId} (Role: ${user.role}) attempted unauthorized access to resource: ${resource}`;

      // 1. Generate Security Event
      db.addSecurityEvent({
        id: db.getSecurityEvents().length + 1,
        eventType: 'UNAUTHORIZED_ACCESS',
        userId: user.id,
        username: user.username,
        identifier: empId,
        ipAddress: clientIp,
        timestamp: new Date().toISOString(),
        attemptCount: 1,
        threshold: 1,
        severity: 'HIGH',
        description: `Access Denied (403 Forbidden): Role '${user.role}' attempted unauthorized access to protected resource '${resource}'.`,
        status: 'OPEN',
        metadata: {
          employeeId: empId,
          userRole: user.role,
          resource,
          requiredRoles: allowedRoles,
          reason,
        },
      });

      // 2. Feed into SIEM Server Engine for RULE-002
      siemServer.ingestLog({
        timestamp: new Date().toISOString(),
        userId: user.id,
        username: user.username,
        source: 'rbac-enforcer',
        eventType: 'UNAUTHORIZED_ACCESS',
        action: 'ACCESS_DENIED',
        resource,
        ipAddress: clientIp,
        severity: 'HIGH',
        details: {
          resource,
          userRole: user.role,
          employeeId: empId,
          requiredRoles: allowedRoles,
          reason,
          statusCode: 403,
        },
      });

      // 3. Record Audit Log
      db.addAuditLog({
        id: db.getAuditLogs().length + 1,
        actor: user.username,
        userId: user.id,
        action: 'UNAUTHORIZED_ACCESS_ATTEMPT',
        resource,
        details: `Blocked 403 Forbidden: ${empId} (${user.role}) attempted unauthorized access to ${resource}. Required: ${allowedRoles.join(', ')}`,
        ipAddress: clientIp,
        timestamp: new Date().toISOString(),
      });

      return res.status(403).json({
        error: `Forbidden: Access denied. Role '${user.role}' does not have permission to access this resource.`,
        requiredRoles: allowedRoles,
        ruleId: 'RULE-002',
      });
    }

    next();
  };
}

// ==========================================
// 0. HEALTH & DIAGNOSTICS APIS (Phase 8)
// ==========================================

// GET /api/health - Diagnostic endpoint verifying all platform subsystems
app.get('/api/health', (req: Request, res: Response) => {
  try {
    const users = db.getUsers();
    const files = db.getFiles();
    const rules = db.getRules();
    const logs = db.getSecurityLogs();
    const events = db.getNormalizedEvents();
    const alerts = db.getAlerts();
    const findings = db.getFindings();
    const riskScores = db.getRiskScores ? (db as any).data.riskScores : [];

    const isDbConnected = Array.isArray(users) && users.length > 0;
    const isAuthOperational = !!JWT_SECRET;
    const isFileRepoOperational = Array.isArray(files) && files.length > 0;
    const isEventIngestionOperational = Array.isArray(logs) && Array.isArray(events);
    const isRuleEngineOperational = Array.isArray(rules) && rules.some((r) => r.enabled);
    const isAlertCreationOperational = Array.isArray(alerts);

    const overallHealthy =
      isDbConnected &&
      isAuthOperational &&
      isFileRepoOperational &&
      isEventIngestionOperational &&
      isRuleEngineOperational &&
      isAlertCreationOperational;

    return res.json({
      status: overallHealthy ? 'HEALTHY' : 'DEGRADED',
      timestamp: new Date().toISOString(),
      uptimeSeconds: process.uptime(),
      diagnostics: {
        api: {
          status: 'OPERATIONAL',
          version: '2.5.0-production',
          port: PORT,
        },
        database: {
          status: isDbConnected ? 'CONNECTED' : 'DISCONNECTED',
          totalUsers: users.length,
          totalFiles: files.length,
          totalEvents: events.length,
          totalLogs: logs.length,
          totalFindings: findings.length,
        },
        authentication: {
          status: isAuthOperational ? 'OPERATIONAL' : 'ERROR',
          mechanism: 'JWT (RS256/HS256 compliant)',
          activeUsers: users.filter((u) => u.status === 'ACTIVE').length,
        },
        fileRepository: {
          status: isFileRepoOperational ? 'OPERATIONAL' : 'ERROR',
          catalogedFiles: files.length,
          classificationsSupported: [
            'PUBLIC',
            'INTERNAL',
            'CONFIDENTIAL',
            'RESTRICTED',
            'HIGHLY_CONFIDENTIAL',
          ],
        },
        eventIngestion: {
          status: isEventIngestionOperational ? 'OPERATIONAL' : 'ERROR',
          ingestedLogsCount: logs.length,
          normalizedEventsCount: events.length,
        },
        ruleEngine: {
          status: isRuleEngineOperational ? 'OPERATIONAL' : 'ERROR',
          totalRules: rules.length,
          activeRules: rules.filter((r) => r.enabled).length,
        },
        alertCreation: {
          status: isAlertCreationOperational ? 'OPERATIONAL' : 'ERROR',
          totalAlerts: alerts.length,
          openAlerts: alerts.filter((a) => a.status === 'OPEN').length,
          criticalAlerts: alerts.filter((a) => a.severity === 'CRITICAL').length,
        },
      },
    });
  } catch (error: any) {
    console.error('Health check failure:', error);
    return res.status(500).json({
      status: 'UNHEALTHY',
      error: error?.message || 'Subsystem check failed',
      timestamp: new Date().toISOString(),
    });
  }
});

// GET /api/diagnostics - Alias for SOC monitoring
app.get('/api/diagnostics', (req: Request, res: Response) => {
  return res.redirect('/api/health');
});

// ==========================================
// 1. AUTHENTICATION & IDENTITY APIS
// ==========================================

// POST /api/auth/login
app.post('/api/auth/login', (req: Request, res: Response) => {
  try {
    const { username, usernameOrEmail, email, employeeId, password } = req.body;
    const loginIdentifier = (username || usernameOrEmail || email || employeeId || '').trim().toLowerCase();
    const clientIp = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '127.0.0.1';

    if (!loginIdentifier || !password) {
      return res.status(400).json({ error: 'Username/Email/Employee ID and Password are required.' });
    }

    const user =
      db.getUserByUsername(loginIdentifier) ||
      db.getUserByEmail(loginIdentifier) ||
      db.getUserByEmployeeId(loginIdentifier);

    if (!user) {
      // Ingest failed login log into SIEM
      siemServer.ingestLog({
        timestamp: new Date().toISOString(),
        userId: 0,
        username: loginIdentifier,
        source: 'auth-service',
        eventType: 'FAILED_LOGIN',
        action: 'AUTH_FAILED',
        resource: 'Web-Login-Gateway',
        ipAddress: clientIp,
        severity: 'MEDIUM',
        details: { reason: 'USER_NOT_FOUND', attempted_identifier: loginIdentifier },
      });
      db.addAuditLog({
        id: db.getAuditLogs().length + 1,
        actor: loginIdentifier,
        userId: 0,
        action: 'FAILED_LOGIN',
        resource: 'AuthGateway',
        details: `Failed login attempt: Unknown username/email '${loginIdentifier}'`,
        timestamp: new Date().toISOString(),
      });
      return res.status(401).json({ error: 'Invalid username/email or password.' });
    }

    const isValidPassword = bcrypt.compareSync(password, user.passwordHash);
    if (!isValidPassword) {
      siemServer.ingestLog({
        timestamp: new Date().toISOString(),
        userId: user.id,
        username: user.username,
        source: 'auth-service',
        eventType: 'FAILED_LOGIN',
        action: 'AUTH_FAILED',
        resource: 'Web-Login-Gateway',
        ipAddress: clientIp,
        severity: 'MEDIUM',
        details: { reason: 'BAD_PASSWORD', user_id: user.id },
      });
      db.addAuditLog({
        id: db.getAuditLogs().length + 1,
        actor: user.username,
        userId: user.id,
        action: 'FAILED_LOGIN',
        resource: 'AuthGateway',
        details: `Failed login attempt for user '${user.username}' (invalid password)`,
        timestamp: new Date().toISOString(),
      });
      return res.status(401).json({ error: 'Invalid username/email or password.' });
    }

    if (user.status !== 'ACTIVE') {
      return res.status(403).json({ error: `Account is ${user.status}. Please contact SOC Administration.` });
    }

    // Update last login
    db.updateUser(user.id, {
      lastLogin: new Date().toISOString(),
      ipAddress: clientIp,
    });

    // Server-side logging for LOGIN
    console.log(
      `[LOGIN] User: ${user.username} (${user.role}) authenticated successfully from IP: ${clientIp} at ${new Date().toISOString()}`
    );

    db.addAuditLog({
      id: db.getAuditLogs().length + 1,
      actor: user.username,
      userId: user.id,
      action: 'LOGIN',
      resource: 'AuthGateway',
      details: `User ${user.fullName} (${user.employeeId || user.username}) authenticated as ${user.role}`,
      timestamp: new Date().toISOString(),
    });

    // Ingest successful login log
    siemServer.ingestLog({
      timestamp: new Date().toISOString(),
      userId: user.id,
      username: user.username,
      source: 'auth-service',
      eventType: 'LOGIN',
      action: 'AUTH_SUCCESS',
      resource: 'Web-Login-Gateway',
      ipAddress: clientIp,
      severity: 'LOW',
      details: { role: user.role, department: user.department },
    });

    // Issue JWT
    const token = jwt.sign(
      {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
      },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    return res.json({
      message: 'Authentication successful',
      token,
      user: sanitizeUser(user),
    });
  } catch (error: any) {
    console.error('Login error:', error);
    return res.status(500).json({ error: 'Internal server error during authentication.' });
  }
});

// POST /api/auth/register (Includes abuse / repeated sign-up monitoring)
app.post('/api/auth/register', (req: Request, res: Response) => {
  try {
    const { username, email, password, fullName, department, role } = req.body;
    const clientIp = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '127.0.0.1';

    const cleanUsername = (username || '').trim().toLowerCase();
    const cleanEmail = (email || '').trim().toLowerCase();
    const targetIdentifier = cleanUsername || cleanEmail || 'anonymous_signup';

    // 1. Validation checks
    if (!username || !email || !password) {
      securityAbuse.recordSignupAttempt(targetIdentifier, clientIp, false, 'Missing required fields');
      return res.status(400).json({ error: 'Username, Email, and Password are required.' });
    }

    if (cleanUsername.length < 3) {
      securityAbuse.recordSignupAttempt(cleanUsername, clientIp, false, 'Username under 3 chars');
      return res.status(400).json({ error: 'Username must be at least 3 characters long.' });
    }

    if (password.length < 6) {
      securityAbuse.recordSignupAttempt(cleanUsername, clientIp, false, 'Password under 6 chars');
      return res.status(400).json({ error: 'Password must be at least 6 characters long.' });
    }

    // Check existing
    const existingUser = db.getUserByUsername(cleanUsername) || db.getUserByEmail(cleanEmail);
    if (existingUser) {
      // Record failed/duplicate attempt & check abuse threshold
      const abuseResult = securityAbuse.recordSignupAttempt(
        cleanUsername,
        clientIp,
        false,
        'Duplicate user conflict'
      );

      return res.status(409).json({
        error: 'A user with this username or email already exists.',
        abuseFlagged: abuseResult.abuseDetected,
      });
    }

    // 2. Track successful signup attempt in abuse monitoring
    const abuseResult = securityAbuse.recordSignupAttempt(cleanUsername, clientIp, true, 'Account created');

    const salt = bcrypt.genSaltSync(10);
    const passwordHash = bcrypt.hashSync(password, salt);

    const newUser: DBUser = {
      id: Math.max(...db.getUsers().map((u) => u.id), 100) + 1,
      username: cleanUsername,
      email: cleanEmail,
      passwordHash,
      fullName: (fullName || cleanUsername).trim(),
      department: (department || 'Cyber Operations').trim(),
      role: (['ADMIN', 'SECURITY_ANALYST', 'VIEWER', 'EMPLOYEE'].includes(role)
        ? role === 'EMPLOYEE'
          ? 'VIEWER'
          : role
        : 'VIEWER') as any,
      status: 'ACTIVE',
      createdAt: new Date().toISOString(),
      lastLogin: new Date().toISOString(),
      ipAddress: clientIp,
    };

    db.addUser(newUser);

    // Record audit log
    db.addAuditLog({
      id: db.getAuditLogs().length + 1,
      actor: cleanUsername,
      userId: newUser.id,
      action: 'USER_REGISTERED',
      resource: `user:${newUser.username}`,
      details: `User registered with role ${newUser.role} in department ${newUser.department}`,
      ipAddress: clientIp,
      timestamp: new Date().toISOString(),
    });

    const token = jwt.sign(
      {
        id: newUser.id,
        username: newUser.username,
        email: newUser.email,
        role: newUser.role,
      },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    return res.status(201).json({
      message: 'User registered successfully',
      token,
      user: sanitizeUser(newUser),
      abuseAlertGenerated: abuseResult.abuseDetected,
    });
  } catch (error: any) {
    console.error('Registration error:', error);
    return res.status(500).json({ error: 'Internal server error during registration.' });
  }
});

// GET /api/auth/me
app.get('/api/auth/me', authenticateJWT, (req: Request, res: Response) => {
  const user = (req as any).user as DBUser;
  return res.json({ user: sanitizeUser(user) });
});

// GET /api/users (Admin & Security Analyst) - Retained for backward compatibility
app.get('/api/users', authenticateJWT, requireRoles('ADMIN', 'SECURITY_ANALYST'), (req: Request, res: Response) => {
  const users = db.getUsers().map(sanitizeUser);
  return res.json({ users, employees: users });
});

// GET /api/employees (Admin & Security Analyst) - Load real employee directory / demo dataset
app.get('/api/employees', authenticateJWT, requireRoles('ADMIN', 'SECURITY_ANALYST'), (req: Request, res: Response) => {
  try {
    const datasetParam = (req.query.dataset as string || 'production').toLowerCase();
    const page = Math.max(1, parseInt(req.query.page as string || '1', 10));
    const limit = Math.min(200, Math.max(1, parseInt(req.query.limit as string || '50', 10)));
    const search = (req.query.search as string || '').toLowerCase().trim();
    const department = (req.query.department as string || '').trim();

    // Production / Manual records (Keep unchanged)
    const productionEmployees = db.getEmployees().map(sanitizeUser);

    if (datasetParam === 'demo') {
      const demoData = demoDataset.getOrCreateDataset();
      let filtered = demoData.employees.map(sanitizeUser);
      if (search) {
        filtered = filtered.filter(
          (u) =>
            u.fullName.toLowerCase().includes(search) ||
            u.username.toLowerCase().includes(search) ||
            (u.employeeId && u.employeeId.toLowerCase().includes(search)) ||
            u.email.toLowerCase().includes(search) ||
            u.department.toLowerCase().includes(search) ||
            (u.designation && u.designation.toLowerCase().includes(search))
        );
      }
      if (department && department !== 'ALL') {
        filtered = filtered.filter((u) => u.department === department);
      }
      const total = filtered.length;
      const start = (page - 1) * limit;
      const paginated = filtered.slice(start, start + limit);

      return res.json({
        employees: paginated,
        users: paginated,
        total,
        page,
        limit,
        totalPages: Math.ceil(total / limit),
        totalProduction: productionEmployees.length,
        totalDemo: demoData.employees.length,
        dataset: 'demo',
      });
    }

    if (datasetParam === 'all') {
      const demoData = demoDataset.getOrCreateDataset();
      const all = [...productionEmployees, ...demoData.employees.map(sanitizeUser)];
      return res.json({
        employees: all,
        users: all,
        totalProduction: productionEmployees.length,
        totalDemo: demoData.employees.length,
        total: all.length,
        dataset: 'all',
      });
    }

    // Default: 'production' - Verified manually created employees (Keep unchanged)
    let filtered = [...productionEmployees];
    if (search) {
      filtered = filtered.filter(
        (u) =>
          u.fullName.toLowerCase().includes(search) ||
          u.username.toLowerCase().includes(search) ||
          (u.employeeId && u.employeeId.toLowerCase().includes(search)) ||
          u.email.toLowerCase().includes(search) ||
          u.department.toLowerCase().includes(search) ||
          (u.designation && u.designation.toLowerCase().includes(search))
      );
    }
    return res.json({
      employees: filtered,
      users: filtered,
      totalProduction: productionEmployees.length,
      totalDemo: 1000,
      total: filtered.length,
      dataset: 'production',
    });
  } catch (err: any) {
    console.error('Error fetching employees:', err);
    return res.status(500).json({ error: 'Internal server error loading employee directory.' });
  }
});

// Helper to resolve employee target by Employee ID, numeric primary key, username, or email
function resolveTargetEmployee(param: string): DBUser | undefined {
  if (!param) return undefined;
  const clean = String(param).trim();

  // 1. Employee ID match (e.g. 'EMP-106', 'TEST-EMP-DELETE-001')
  let user = db.getUserByEmployeeId(clean);
  if (user) return user;

  // 2. Numeric database primary key ID
  if (!isNaN(Number(clean))) {
    user = db.getUserById(Number(clean));
    if (user) return user;
  }

  // 3. Username or corporate email
  user = db.getUserByUsername(clean) || db.getUserByEmail(clean);
  if (user) return user;

  // 4. Prefix fallback: if pure digits, try EMP-<digits>; if EMP-<digits>, try numeric ID
  if (/^\d+$/.test(clean)) {
    user = db.getUserByEmployeeId(`EMP-${clean}`);
    if (user) return user;
  } else if (/^emp-\d+$/i.test(clean)) {
    const numericId = parseInt(clean.replace(/^emp-/i, ''), 10);
    user = db.getUserById(numericId);
    if (user) return user;
  }

  return undefined;
}

// Helper to determine if target employee is the authenticated admin's own account
function isSelfAdminAccount(targetUser: DBUser, adminUser: DBUser): boolean {
  if (!targetUser || !adminUser) return false;
  if (targetUser.id === adminUser.id) return true;
  if (
    targetUser.username &&
    adminUser.username &&
    targetUser.username.trim().toLowerCase() === adminUser.username.trim().toLowerCase()
  ) {
    return true;
  }
  if (
    targetUser.employeeId &&
    adminUser.employeeId &&
    targetUser.employeeId.trim().toLowerCase() === adminUser.employeeId.trim().toLowerCase()
  ) {
    return true;
  }
  if (
    targetUser.email &&
    adminUser.email &&
    targetUser.email.trim().toLowerCase() === adminUser.email.trim().toLowerCase()
  ) {
    return true;
  }
  return false;
}

// PATCH /api/employees/:id/status - Admin Toggle Employee Status
app.patch('/api/employees/:id/status', authenticateJWT, requireRoles('ADMIN'), (req: Request, res: Response) => {
  try {
    const adminUser = (req as any).user as DBUser;
    const targetParam = req.params.id;
    const { status } = req.body;

    if (!['ACTIVE', 'DISABLED', 'SUSPENDED', 'INVITED'].includes(status)) {
      return res.status(400).json({ error: 'Status must be ACTIVE, DISABLED, SUSPENDED, or INVITED.' });
    }

    const user = resolveTargetEmployee(targetParam);
    if (!user) {
      return res.status(404).json({ error: 'Employee not found.' });
    }

    // Admin self-protection: Cannot disable own administrator account
    if (status === 'DISABLED' && isSelfAdminAccount(user, adminUser)) {
      return res.status(403).json({ error: 'Cannot disable or delete your own administrator account.' });
    }

    const oldStatus = user.status;
    user.status = status;
    db.updateUser(user.id, { status });

    db.addAuditLog({
      id: db.getAuditLogs().length + 1,
      actor: adminUser.username,
      userId: user.id,
      action: status === 'DISABLED' ? 'EMPLOYEE_DISABLED' : 'EMPLOYEE_STATUS_CHANGED',
      resource: `user:${user.username}`,
      details: `Admin ${adminUser.username} updated employee [${user.employeeId || `EMP-${user.id}`}] ${user.fullName} status from ${oldStatus} to ${status}`,
      timestamp: new Date().toISOString(),
    });

    console.log(`[EMPLOYEE_STATUS] Admin ${adminUser.username} updated employee ${user.fullName} (${user.employeeId || `EMP-${user.id}`}) to ${status}`);

    return res.status(200).json({
      message: `Employee ${user.fullName} status updated to ${status}.`,
      employee: sanitizeUser(user),
    });
  } catch (err: any) {
    console.error('Error updating employee status:', err);
    return res.status(500).json({ error: 'Internal server error updating employee status.' });
  }
});

// PUT /api/employees/:id - Admin Update Employee Details
app.put('/api/employees/:id', authenticateJWT, requireRoles('ADMIN'), (req: Request, res: Response) => {
  try {
    const adminUser = (req as any).user as DBUser;
    const targetParam = req.params.id;
    const { fullName, email, department, designation, clearanceLevel, status } = req.body;

    const user = resolveTargetEmployee(targetParam);
    if (!user) {
      return res.status(404).json({ error: 'Employee not found.' });
    }

    const updates: Partial<DBUser> = {};
    if (fullName && String(fullName).trim()) updates.fullName = String(fullName).trim();
    if (department && String(department).trim()) updates.department = String(department).trim();
    if (designation && String(designation).trim()) updates.designation = String(designation).trim();
    if (clearanceLevel && String(clearanceLevel).trim()) updates.clearanceLevel = String(clearanceLevel).trim();
    if (status && ['ACTIVE', 'DISABLED', 'SUSPENDED'].includes(status)) {
      if (status === 'DISABLED' && isSelfAdminAccount(user, adminUser)) {
        return res.status(403).json({ error: 'Cannot disable or delete your own administrator account.' });
      }
      updates.status = status;
    }

    if (email && String(email).trim().toLowerCase() !== user.email.toLowerCase()) {
      const cleanEmail = String(email).trim().toLowerCase();
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(cleanEmail)) {
        return res.status(400).json({ error: 'Invalid corporate email format.' });
      }
      const conflict = db.getUserByEmail(cleanEmail);
      if (conflict && conflict.id !== user.id) {
        return res.status(409).json({ error: 'Corporate email already exists.' });
      }
      updates.email = cleanEmail;
    }

    // Role MUST remain unchanged / EMPLOYEE - Admin cannot arbitrarily create another admin through this route
    if (user.role !== 'ADMIN') {
      updates.role = 'EMPLOYEE';
    }

    db.updateUser(user.id, updates);

    db.addAuditLog({
      id: db.getAuditLogs().length + 1,
      actor: adminUser.username,
      userId: user.id,
      action: 'EMPLOYEE_UPDATED',
      resource: `user:${user.username}`,
      details: `Admin ${adminUser.username} updated employee details for [${user.employeeId || `EMP-${user.id}`}] ${user.fullName}`,
      timestamp: new Date().toISOString(),
    });

    return res.status(200).json({
      message: 'Employee updated successfully.',
      employee: sanitizeUser(user),
    });
  } catch (err: any) {
    console.error('Error updating employee:', err);
    return res.status(500).json({ error: 'Internal server error updating employee.' });
  }
});

// DELETE /api/employees/:id - Admin Safe Deactivation / Removal
app.delete('/api/employees/:id', authenticateJWT, requireRoles('ADMIN'), (req: Request, res: Response) => {
  try {
    const adminUser = (req as any).user as DBUser;
    const targetParam = req.params.id;
    const isPermanent = req.query.permanent === 'true';

    console.log(`[EMPLOYEE_OPERATION] Authenticated Admin: ${adminUser.username} (${adminUser.id}), Request target: '${targetParam}'`);

    const user = resolveTargetEmployee(targetParam);
    if (!user) {
      return res.status(404).json({ error: 'Employee not found.' });
    }

    console.log(`[EMPLOYEE_OPERATION] Target resolved: ${user.fullName} [${user.employeeId || `EMP-${user.id}`}] (${user.id})`);

    // Admin Self-Protection: An administrator cannot disable or delete their own account
    if (isSelfAdminAccount(user, adminUser)) {
      console.warn(`[SECURITY_BLOCKED] Admin ${adminUser.username} attempted to disable/delete self account [${user.employeeId || user.username}].`);
      return res.status(403).json({ error: 'Cannot disable or delete your own administrator account.' });
    }

    if (isPermanent) {
      const removed = db.deleteUser(user.id);
      db.addAuditLog({
        id: db.getAuditLogs().length + 1,
        actor: adminUser.username,
        userId: user.id,
        action: 'EMPLOYEE_DELETED',
        resource: `user:${user.username}`,
        details: `Admin ${adminUser.username} permanently deleted employee [${user.employeeId || `EMP-${user.id}`}] ${user.fullName}`,
        timestamp: new Date().toISOString(),
      });
      return res.status(200).json({
        message: `Employee ${user.fullName} (${user.employeeId || `EMP-${user.id}`}) deleted successfully.`,
        employee: sanitizeUser(removed || user),
      });
    }

    // Default: Safe deactivation preserving SIEM historical audit/security integrity
    user.status = 'DISABLED';
    db.updateUser(user.id, { status: 'DISABLED' });

    db.addAuditLog({
      id: db.getAuditLogs().length + 1,
      actor: adminUser.username,
      userId: user.id,
      action: 'EMPLOYEE_DISABLED',
      resource: `user:${user.username}`,
      details: `Admin ${adminUser.username} disabled employee [${user.employeeId || `EMP-${user.id}`}] ${user.fullName}`,
      timestamp: new Date().toISOString(),
    });

    console.log(`[EMPLOYEE_DISABLED] Admin: ${adminUser.username} disabled Employee: ${user.fullName} (${user.employeeId || `EMP-${user.id}`})`);

    return res.status(200).json({
      message: 'Employee disabled successfully.',
      employee: sanitizeUser(user),
    });
  } catch (err: any) {
    console.error('Error disabling employee:', err);
    return res.status(500).json({ error: 'Internal server error disabling employee.' });
  }
});

// POST /api/employees - Admin-Only Employee Account Provisioning
// Strictly enforces: role=EMPLOYEE (Never trusts role sent by caller)
const createEmployeeHandler = (req: Request, res: Response) => {
  try {
    const adminUser = (req as any).user as DBUser;
    const {
      employeeId,
      fullName,
      email,
      department,
      designation,
      clearanceLevel,
      status = 'ACTIVE',
      password = 'password123',
    } = req.body;

    const clientIp = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '127.0.0.1';

    // Strict Field Validations per requirements
    if (!employeeId || !String(employeeId).trim()) {
      return res.status(400).json({ error: 'Employee ID is required.' });
    }
    if (!fullName || !String(fullName).trim()) {
      return res.status(400).json({ error: 'Full name is required.' });
    }
    if (!email || !String(email).trim()) {
      return res.status(400).json({ error: 'Corporate email is required.' });
    }

    const cleanEmail = String(email).trim().toLowerCase();
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(cleanEmail)) {
      return res.status(400).json({ error: 'Invalid corporate email format.' });
    }

    const cleanEmployeeId = String(employeeId).trim().toUpperCase();

    // Unique Employee ID check (409 Conflict)
    if (db.getUserByEmployeeId(cleanEmployeeId)) {
      return res.status(409).json({
        error: 'Employee ID already exists.',
      });
    }

    // Unique Corporate Email check (409 Conflict)
    if (db.getUserByEmail(cleanEmail)) {
      return res.status(409).json({
        error: 'Corporate email already exists.',
      });
    }

    const cleanFullName = String(fullName).trim();
    const cleanDept = department && String(department).trim() ? String(department).trim() : 'Engineering';
    const cleanDesignation = designation && String(designation).trim() ? String(designation).trim() : 'Staff Associate';
    const validClearances = ['PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'RESTRICTED', 'STANDARD'];
    const cleanClearance = clearanceLevel && validClearances.includes(String(clearanceLevel).trim().toUpperCase())
      ? String(clearanceLevel).trim().toUpperCase()
      : 'STANDARD';

    // Derive or sanitize unique username
    let derivedUsername = cleanEmail.split('@')[0].toLowerCase().replace(/[^a-z0-9_]/g, '') || cleanEmployeeId.toLowerCase();
    if (db.getUserByUsername(derivedUsername)) {
      derivedUsername = `${derivedUsername}_${Math.floor(100 + Math.random() * 900)}`;
    }

    const salt = bcrypt.genSaltSync(10);
    const passwordHash = bcrypt.hashSync(password, salt);

    // FORCED ROLE: The backend strictly forces role=EMPLOYEE. Never trusts any role passed in request!
    const newEmployee: DBUser = {
      id: Math.max(...db.getUsers().map((u) => u.id), 100) + 1,
      username: derivedUsername,
      email: cleanEmail,
      passwordHash,
      fullName: cleanFullName,
      department: cleanDept,
      designation: cleanDesignation,
      employeeId: cleanEmployeeId,
      clearanceLevel: cleanClearance,
      role: 'EMPLOYEE', // Strictly enforced backend constraint
      status: ['ACTIVE', 'DISABLED', 'SUSPENDED'].includes(status) ? status : 'ACTIVE',
      createdAt: new Date().toISOString(),
      lastLogin: undefined,
      ipAddress: clientIp,
      isManual: true,
    };

    db.addUser(newEmployee);

    // Server-side audit log
    db.addAuditLog({
      id: db.getAuditLogs().length + 1,
      actor: adminUser.username,
      userId: newEmployee.id,
      action: 'EMPLOYEE_PROVISIONED',
      resource: `user:${newEmployee.username}`,
      details: `Admin ${adminUser.username} provisioned employee account [${newEmployee.employeeId}] ${newEmployee.fullName} (${newEmployee.role}) in ${newEmployee.department}`,
      ipAddress: clientIp,
      timestamp: new Date().toISOString(),
    });

    console.log(
      `[EMPLOYEE_CREATED] Admin: ${adminUser.username} provisioned Employee: ${newEmployee.fullName} (ID: ${newEmployee.employeeId}, Role: EMPLOYEE, Clearance: ${newEmployee.clearanceLevel})`
    );

    return res.status(201).json({
      message: 'Employee created successfully.',
      employee: sanitizeUser(newEmployee),
    });
  } catch (err: any) {
    console.error('Error provisioning employee:', err);
    return res.status(500).json({ error: 'Internal server error provisioning employee account.' });
  }
};

app.post('/api/employees', authenticateJWT, requireRoles('ADMIN'), createEmployeeHandler);
app.post('/api/admin/employees', authenticateJWT, requireRoles('ADMIN'), createEmployeeHandler);

// ==========================================
// 2. CORPORATE FILE REPOSITORY & DLP APIS
// ==========================================

// GET /api/files - List files from database
app.get('/api/files', authenticateJWT, (req: Request, res: Response) => {
  const files = db.getFiles();
  return res.json({ files });
});

// GET /api/files/:id - Get single file
app.get('/api/files/:id', authenticateJWT, (req: Request, res: Response) => {
  const file = db.getFileById(req.params.id);
  if (!file) {
    return res.status(404).json({ error: `File '${req.params.id}' not found.` });
  }
  return res.json({ file });
});

// POST /api/files/:id/access - Access/Open document
app.post('/api/files/:id/access', authenticateJWT, (req: Request, res: Response) => {
  const fileId = req.params.id;
  const { action = 'OPEN' } = req.body;
  const user = (req as any).user as DBUser;

  const result = siemServer.accessFile(fileId, action, user);
  if (!result.success) {
    return res.status(404).json({ error: result.message });
  }

  return res.json({
    success: true,
    message: result.message,
    file: result.file,
    action,
    timestamp: new Date().toISOString(),
  });
});

// POST /api/files/:id/download - File Download (With Failed Download Abuse Detection)
app.post('/api/files/:id/download', authenticateJWT, (req: Request, res: Response) => {
  const fileId = req.params.id;
  const user = (req as any).user as DBUser;
  const clientIp = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '127.0.0.1';

  const file = db.getFileById(fileId);

  // If file not found -> record failed download & check abuse threshold
  if (!file) {
    const abuseResult = securityAbuse.recordFailedDownload(
      fileId,
      'FILE_NOT_FOUND',
      user.id,
      user.username,
      clientIp
    );

    return res.status(404).json({
      error: `File '${fileId}' not found in corporate repository.`,
      failureCount: abuseResult.failureCount,
      abuseAlertGenerated: abuseResult.abuseDetected,
    });
  }

  // Execute download access
  const result = siemServer.accessFile(fileId, 'DOWNLOAD', user);

  return res.json({
    success: true,
    message: result.message,
    file: result.file,
    downloadUrl: `/api/files/${fileId}/stream`,
    timestamp: new Date().toISOString(),
  });
});

// GET /api/my-activity - Personal file access activity for employee view
app.get('/api/my-activity', authenticateJWT, (req: Request, res: Response) => {
  const user = (req as any).user as DBUser;
  const activities = db.getFileActivities(user.id);
  return res.json({ activities });
});

// ==========================================
// 3. SECURITY / ABUSE EVENTS MONITORING API
// ==========================================

// GET /api/security-events - View security abuse events (SOC roles)
app.get(
  '/api/security-events',
  authenticateJWT,
  requireRoles('ADMIN', 'SECURITY_ANALYST'),
  (req: Request, res: Response) => {
    const events = db.getSecurityEvents();
    return res.json({ securityEvents: events });
  }
);

// ==========================================
// 4. SIEM SOC REST APIS (Database Backed)
// ==========================================

// GET /api/soc/snapshot - Consolidated Single-Roundtrip State (Replaces 9-12 parallel HTTP calls)
app.get(
  '/api/soc/snapshot',
  authenticateJWT,
  requireRoles('ADMIN', 'SECURITY_ANALYST'),
  (req: Request, res: Response) => {
    try {
      const demoData = demoDataset.getOrCreateDataset();
      const summary = siemServer.getSOCSummary();
      const dbAlerts = db.getAlerts();
      const combinedAlerts = Array.from(
        new Map([...demoData.alerts, ...dbAlerts].map((a) => [a.alertId, a])).values()
      );

      const dbEvents = db.getNormalizedEvents();
      const events = dbEvents.length > 0 ? [...dbEvents, ...demoData.events.slice(0, 50)] : demoData.events.slice(0, 100);

      const findings = db.getFindings().length > 0 ? db.getFindings() : demoData.findings.slice(0, 100);
      const riskScores = db.getRiskScores().length > 0 ? db.getRiskScores() : demoData.riskScores;
      const rules = db.getRules().length > 0 ? db.getRules() : SEVEN_DETECTION_RULES;
      const usbDevices = db.getUSBDevices();
      const usbTransfers = db.getUSBTransfers();
      const auditLogs = db.getAuditLogs();
      const mlAnomalies = db.getMLAnomalies();
      const employees = db.getEmployees().map(sanitizeUser); // Manually created production employees (Keep unchanged)

      return res.json({
        summary,
        alerts: combinedAlerts,
        events,
        findings,
        riskScores,
        rules,
        usbDevices,
        usbTransfers,
        auditLogs,
        mlAnomalies,
        employees,
        totalDemoEmployees: 1000,
        totalManualEmployees: employees.length,
        datasetStats: {
          demoEmployeesCount: demoData.employees.length,
          demoEventsCount: demoData.totalEvents,
          rulesCount: rules.length,
        },
      });
    } catch (err: any) {
      console.error('[API] Error assembling SOC snapshot:', err);
      return res.status(500).json({ error: 'Failed to assemble SOC snapshot' });
    }
  }
);

// GET /api/summary - Real-time metrics
app.get(
  '/api/summary',
  authenticateJWT,
  requireRoles('ADMIN', 'SECURITY_ANALYST'),
  (req: Request, res: Response) => {
    const summary = siemServer.getSOCSummary();
    return res.json({ summary });
  }
);

// GET /api/alerts - List all alerts (Admin or Security Analyst)
app.get(
  '/api/alerts',
  authenticateJWT,
  requireRoles('ADMIN', 'SECURITY_ANALYST'),
  (req: Request, res: Response) => {
    const alerts = db.getAlerts();
    return res.json({ alerts });
  }
);

// POST /api/alerts/:id/acknowledge (Admin or Security Analyst)
app.post(
  '/api/alerts/:id/acknowledge',
  authenticateJWT,
  requireRoles('ADMIN', 'SECURITY_ANALYST'),
  (req: Request, res: Response) => {
    const alertId = req.params.id;
    const user = (req as any).user as DBUser;
    const alert = db.updateAlert(alertId, {
      status: 'ACKNOWLEDGED',
      assignedTo: user.username,
    });

    if (!alert) {
      return res.status(404).json({ error: `Alert '${alertId}' not found.` });
    }

    db.addAuditLog({
      id: db.getAuditLogs().length + 1,
      actor: user.username,
      userId: user.id,
      action: 'ALERT_ACKNOWLEDGED',
      resource: `alert:${alertId}`,
      details: `Alert ${alertId} acknowledged by ${user.username}`,
      timestamp: new Date().toISOString(),
    });

    return res.json({ message: `Alert ${alertId} acknowledged`, alert });
  }
);

// POST /api/alerts/:id/resolve (Admin or Security Analyst)
app.post(
  '/api/alerts/:id/resolve',
  authenticateJWT,
  requireRoles('ADMIN', 'SECURITY_ANALYST'),
  (req: Request, res: Response) => {
    const alertId = req.params.id;
    const user = (req as any).user as DBUser;
    const alert = db.updateAlert(alertId, {
      status: 'RESOLVED',
      resolvedAt: new Date().toISOString(),
    });

    if (!alert) {
      return res.status(404).json({ error: `Alert '${alertId}' not found.` });
    }

    db.addAuditLog({
      id: db.getAuditLogs().length + 1,
      actor: user.username,
      userId: user.id,
      action: 'ALERT_RESOLVED',
      resource: `alert:${alertId}`,
      details: `Alert ${alertId} marked as RESOLVED by ${user.username}`,
      timestamp: new Date().toISOString(),
    });

    return res.json({ message: `Alert ${alertId} resolved`, alert });
  }
);

// POST /api/alerts/:id/false-positive (Admin or Security Analyst)
app.post(
  '/api/alerts/:id/false-positive',
  authenticateJWT,
  requireRoles('ADMIN', 'SECURITY_ANALYST'),
  (req: Request, res: Response) => {
    const alertId = req.params.id;
    const user = (req as any).user as DBUser;
    const alert = db.updateAlert(alertId, {
      status: 'FALSE_POSITIVE',
      resolvedAt: new Date().toISOString(),
    });

    if (!alert) {
      return res.status(404).json({ error: `Alert '${alertId}' not found.` });
    }

    return res.json({ message: `Alert ${alertId} marked as FALSE_POSITIVE`, alert });
  }
);

// POST /api/soc/alerts/:id/ai-narrative - On-Demand AI Incident Analysis (Optional Gemini Integration with Safe Fallback)
app.post(
  '/api/soc/alerts/:id/ai-narrative',
  authenticateJWT,
  requireRoles('ADMIN', 'SECURITY_ANALYST'),
  async (req: Request, res: Response) => {
    const alertId = req.params.id;
    const alert = db.getAlerts().find((a) => a.alertId === alertId);

    if (!alert) {
      return res.status(404).json({ error: `Alert '${alertId}' not found.` });
    }

    const localPlaybook = [
      `Audit endpoint authentication logs for ${alert.username} across the 24-hour correlation window.`,
      `Verify legitimate business justification with department lead (${alert.userDepartment || 'Corporate Operations'}).`,
      `Analyze network egress packets and USB device serial authorization status.`,
      `If unauthorized, revoke active Kerberos/SSO session tokens and isolate workstation.`,
    ];

    const localNarrative = `Correlated behavioral anomaly investigation for ${alert.username} (${alert.userDepartment || 'Enterprise'}). Identified ${alert.eventCount || alert.evidence.length} correlated telemetry triggers yielding an aggregated risk score of ${alert.riskScore}/100 and ML Isolation Forest deviation score of ${alert.mlAnomalyScore || 75}/100. Primary violation vectors: ${alert.policyViolations?.join(', ') || alert.title}.`;

    // Check if GEMINI_API_KEY is configured
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) {
      return res.json({
        fallback: true,
        source: 'local_detection',
        message: 'AI analysis temporarily unavailable — using local detection.',
        narrative: localNarrative,
        mitreTactics: ['TA0001 Initial Access', 'TA0010 Exfiltration', 'T1052.001 Exfiltration over USB', 'T1078 Valid Accounts'],
        recommendedActions: alert.recommendations && alert.recommendations.length > 0 ? alert.recommendations : localPlaybook,
      });
    }

    try {
      // Lazy load @google/genai SDK
      const { GoogleGenAI } = await import('@google/genai');
      const ai = new GoogleGenAI({ apiKey });

      const prompt = `You are a Tier-3 SOC Security Analyst evaluating an Insider Threat incident.
Alert Details:
- Alert ID: ${alert.alertId}
- Title: ${alert.title}
- Severity: ${alert.severity}
- Suspect: ${alert.username} (${alert.userDepartment || 'General'})
- Risk Score: ${alert.riskScore}/100
- ML Anomaly Score: ${alert.mlAnomalyScore}/100
- Evidence Items: ${alert.evidence.join('; ')}
- Violations: ${alert.policyViolations?.join(', ') || 'N/A'}

Provide a concise 2-paragraph professional SOC incident briefing:
Paragraph 1: Threat narrative, intent analysis, and anomaly evaluation.
Paragraph 2: Strategic containment and forensics guidance.`;

      // Set a 6-second timeout for the AI call to prevent hanging
      const timeoutPromise = new Promise((_, reject) =>
        setTimeout(() => reject(new Error('AI request timeout')), 6000)
      );

      const aiPromise = ai.models.generateContent({
        model: 'gemini-2.5-flash',
        contents: prompt,
      });

      const aiResult: any = await Promise.race([aiPromise, timeoutPromise]);
      const narrativeText = aiResult?.text || localNarrative;

      return res.json({
        fallback: false,
        source: 'gemini_ai',
        message: 'Gemini AI threat narrative generated successfully.',
        narrative: narrativeText,
        mitreTactics: ['TA0001 Initial Access', 'TA0010 Exfiltration', 'T1052.001 Exfiltration over USB', 'T1078 Valid Accounts'],
        recommendedActions: alert.recommendations && alert.recommendations.length > 0 ? alert.recommendations : localPlaybook,
      });
    } catch (aiErr: any) {
      console.warn('[Gemini AI] Analysis unavailable (rate limit or network timeout), switching cleanly to local detection:', aiErr?.message || aiErr);
      return res.json({
        fallback: true,
        source: 'local_detection',
        message: 'AI analysis temporarily unavailable — using local detection.',
        narrative: localNarrative,
        mitreTactics: ['TA0001 Initial Access', 'TA0010 Exfiltration', 'T1052.001 Exfiltration over USB', 'T1078 Valid Accounts'],
        recommendedActions: alert.recommendations && alert.recommendations.length > 0 ? alert.recommendations : localPlaybook,
      });
    }
  }
);

// GET /api/rules
app.get(
  '/api/rules',
  authenticateJWT,
  requireRoles('ADMIN', 'SECURITY_ANALYST'),
  (req: Request, res: Response) => {
    const rules = db.getRules();
    return res.json({ rules });
  }
);

// POST /api/rules (Admin or Security Analyst)
app.post('/api/rules', authenticateJWT, requireRoles('ADMIN', 'SECURITY_ANALYST'), (req: Request, res: Response) => {
  const user = (req as any).user as DBUser;
  const { ruleCode, name, description, eventType, severity, conditions, riskWeight } = req.body;

  if (!name || !eventType || !conditions) {
    return res.status(400).json({ error: 'Name, eventType, and conditions are required.' });
  }

  const newRule = {
    id: db.getRules().length + 1,
    ruleCode: ruleCode || `RULE_${Date.now().toString(36).toUpperCase()}`,
    name,
    description: description || 'Custom detection rule',
    eventType,
    severity: severity || 'MEDIUM',
    enabled: true,
    conditions: Array.isArray(conditions) ? conditions : [],
    riskWeight: riskWeight || 25,
    createdAt: new Date().toISOString(),
  };

  db.addRule(newRule);

  db.addAuditLog({
    id: db.getAuditLogs().length + 1,
    actor: user.username,
    userId: user.id,
    action: 'RULE_CREATED',
    resource: `rule:${newRule.ruleCode}`,
    details: `Created rule ${newRule.name} (Code: ${newRule.ruleCode})`,
    timestamp: new Date().toISOString(),
  });

  return res.status(201).json({ message: 'Rule created successfully', rule: newRule });
});

// PUT /api/rules/:id (Admin or Security Analyst)
app.put('/api/rules/:id', authenticateJWT, requireRoles('ADMIN', 'SECURITY_ANALYST'), (req: Request, res: Response) => {
  const ruleId = parseInt(req.params.id, 10);
  const user = (req as any).user as DBUser;
  const updates = req.body;

  const rule = db.updateRule(ruleId, updates);
  if (!rule) {
    return res.status(404).json({ error: `Rule '${ruleId}' not found.` });
  }

  db.addAuditLog({
    id: db.getAuditLogs().length + 1,
    actor: user.username,
    userId: user.id,
    action: 'RULE_UPDATED',
    resource: `rule:${rule.ruleCode}`,
    details: `Updated rule ${rule.ruleCode} (Enabled: ${rule.enabled})`,
    timestamp: new Date().toISOString(),
  });

  return res.json({ message: `Rule ${ruleId} updated`, rule });
});

// GET /api/events
app.get(
  '/api/events',
  authenticateJWT,
  requireRoles('ADMIN', 'SECURITY_ANALYST'),
  (req: Request, res: Response) => {
    const demoData = demoDataset.getOrCreateDataset();
    const dbEvents = db.getNormalizedEvents();
    const combinedEvents = [...dbEvents, ...demoData.events];

    const page = Math.max(1, parseInt(req.query.page as string || '1', 10));
    const limit = Math.min(200, Math.max(1, parseInt(req.query.limit as string || '50', 10)));
    const search = (req.query.search as string || '').toLowerCase().trim();
    const type = (req.query.type as string || '').trim();
    const severity = (req.query.severity as string || '').trim();

    let filtered = combinedEvents;
    if (type && type !== 'ALL') {
      filtered = filtered.filter((e) => e.eventType === type);
    }
    if (severity && severity !== 'ALL') {
      filtered = filtered.filter((e) => (e.normalizedData?.severity === severity || (e as any).severity === severity));
    }
    if (search) {
      filtered = filtered.filter(
        (e) =>
          (e.username && e.username.toLowerCase().includes(search)) ||
          (e.normalizedData?.action && e.normalizedData.action.toLowerCase().includes(search)) ||
          (e.normalizedData?.resource && e.normalizedData.resource.toLowerCase().includes(search)) ||
          (e.normalizedData?.source && String(e.normalizedData.source).toLowerCase().includes(search)) ||
          (e.normalizedData?.ipAddress && String(e.normalizedData.ipAddress).toLowerCase().includes(search)) ||
          String(e.id).includes(search)
      );
    }

    const total = filtered.length;
    const start = (page - 1) * limit;
    const paginated = filtered.slice(start, start + limit);

    return res.json({
      events: paginated,
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit),
    });
  }
);

// GET /api/logs
app.get(
  '/api/logs',
  authenticateJWT,
  requireRoles('ADMIN', 'SECURITY_ANALYST'),
  (req: Request, res: Response) => {
    const logs = db.getSecurityLogs();
    return res.json({ logs });
  }
);

// GET /api/findings
app.get(
  '/api/findings',
  authenticateJWT,
  requireRoles('ADMIN', 'SECURITY_ANALYST'),
  (req: Request, res: Response) => {
    const findings = db.getFindings();
    return res.json({ findings });
  }
);

// GET /api/risk/users
app.get(
  '/api/risk/users',
  authenticateJWT,
  requireRoles('ADMIN', 'SECURITY_ANALYST'),
  (req: Request, res: Response) => {
    const riskScores = db.getRiskScores();
    return res.json({ riskScores });
  }
);

// POST /api/risk/recalculate
app.post(
  '/api/risk/recalculate',
  authenticateJWT,
  requireRoles('ADMIN', 'SECURITY_ANALYST'),
  (req: Request, res: Response) => {
    const users = db.getUsers();
    users.forEach((u) => {
      siemServer.recalculateRisk(u.id);
      siemServer.recalculateMLAnomaly(u.id);
      siemServer.correlateAlertsForUser(u.id);
    });
    return res.json({ message: 'All user risk scores recalculated from database.' });
  }
);

// GET /api/ml/anomalies
app.get(
  '/api/ml/anomalies',
  authenticateJWT,
  requireRoles('ADMIN', 'SECURITY_ANALYST'),
  (req: Request, res: Response) => {
    const anomalies = db.getMLAnomalies();
    return res.json({ anomalies });
  }
);

// POST /api/ml/train
app.post(
  '/api/ml/train',
  authenticateJWT,
  requireRoles('ADMIN', 'SECURITY_ANALYST'),
  (req: Request, res: Response) => {
    const user = (req as any).user as DBUser;
    siemServer.mlVersion = `iforest-v1.${Math.floor(Math.random() * 5 + 5)}`;
    db.getUsers().forEach((u) => siemServer.recalculateMLAnomaly(u.id));

    db.addAuditLog({
      id: db.getAuditLogs().length + 1,
      actor: user.username,
      userId: user.id,
      action: 'ML_MODEL_TRAIN',
      resource: 'IsolationForest',
      details: `Retrained ML Anomaly engine (${siemServer.mlVersion})`,
      timestamp: new Date().toISOString(),
    });

    return res.json({ message: `ML Isolation Forest updated to ${siemServer.mlVersion}` });
  }
);

// GET /api/usb/devices
app.get(
  '/api/usb/devices',
  authenticateJWT,
  requireRoles('ADMIN', 'SECURITY_ANALYST'),
  (req: Request, res: Response) => {
    const usbDevices = db.getUSBDevices();
    return res.json({ usbDevices });
  }
);

// POST /api/usb/devices/:id/toggle-auth
app.post(
  '/api/usb/devices/:id/toggle-auth',
  authenticateJWT,
  requireRoles('ADMIN', 'SECURITY_ANALYST'),
  (req: Request, res: Response) => {
    const deviceId = req.params.id;
    const { authorized } = req.body;
    const user = (req as any).user as DBUser;

    const dev = db.getUSBDeviceById(deviceId);
    if (!dev) {
      return res.status(404).json({ error: `USB Device '${deviceId}' not found.` });
    }

    dev.authorized = Boolean(authorized);
    dev.status = dev.authorized ? 'CONNECTED' : 'BLOCKED';
    db.addOrUpdateUSBDevice(dev);

    db.addAuditLog({
      id: db.getAuditLogs().length + 1,
      actor: user.username,
      userId: user.id,
      action: 'USB_POLICY_UPDATE',
      resource: `device:${deviceId}`,
      details: `USB ${deviceId} set to ${dev.authorized ? 'AUTHORIZED' : 'UNAUTHORIZED'}`,
      timestamp: new Date().toISOString(),
    });

    return res.json({ message: 'USB authorization updated', device: dev });
  }
);

// GET /api/usb/transfers
app.get(
  '/api/usb/transfers',
  authenticateJWT,
  requireRoles('ADMIN', 'SECURITY_ANALYST'),
  (req: Request, res: Response) => {
    const transfers = db.getUSBTransfers();
    return res.json({ transfers });
  }
);

// POST /api/usb/transfers
app.post(
  '/api/usb/transfers',
  authenticateJWT,
  requireRoles('ADMIN', 'SECURITY_ANALYST'),
  (req: Request, res: Response) => {
    const { userId, deviceId, files } = req.body;
    const user = (req as any).user as DBUser;

    const targetUserId = userId || user.id;
    const transfer = siemServer.requestUSBTransfer(targetUserId, deviceId, files || []);

    return res.json({ transfer });
  }
);

// GET /api/audit (Admin or Security Analyst)
app.get('/api/audit', authenticateJWT, requireRoles('ADMIN', 'SECURITY_ANALYST'), (req: Request, res: Response) => {
  const auditLogs = db.getAuditLogs();
  return res.json({ auditLogs });
});

// POST /api/scenarios/inject (Admin or Security Analyst)
app.post(
  '/api/scenarios/inject',
  authenticateJWT,
  requireRoles('ADMIN', 'SECURITY_ANALYST'),
  (req: Request, res: Response) => {
    const { scenarioType } = req.body;
    const targetUser = db.getUsers()[0]; // Alex Mercer
    const now = new Date();

    if (scenarioType === 'DISGRUNTLED_EXFIL') {
      siemServer.ingestLog({
        timestamp: new Date(now.getTime() - 1000 * 60 * 5).toISOString(),
        userId: targetUser.id,
        username: targetUser.username,
        source: 'usb-monitor',
        eventType: 'USB_INSERT',
        action: 'DEVICE_ATTACHED',
        deviceId: 'USB-PERS-404',
        ipAddress: targetUser.ipAddress,
        severity: 'HIGH',
        details: { authorized: false, device_name: 'SanDisk Rogue Flash', vendor: 'SanDisk' },
      });

      ['/vault/finance/M&A_Confidential_Brief.pdf', '/vault/rnd/Quantum_Algorithm_Seed.bin'].forEach(
        (res, idx) => {
          siemServer.ingestLog({
            timestamp: new Date(now.getTime() - 1000 * 60 * (4 - idx)).toISOString(),
            userId: targetUser.id,
            username: targetUser.username,
            source: 'endpoint-agent',
            eventType: 'SENSITIVE_FILE_ACCESS',
            action: 'FILE_READ_RESTRICTED',
            resource: res,
            ipAddress: targetUser.ipAddress,
            severity: 'HIGH',
            details: { classification: 'RESTRICTED_TOP_SECRET', file_size_mb: 34.5 },
          });
        }
      );

      siemServer.requestUSBTransfer(targetUser.id, 'USB-PERS-404', [
        { name: 'M&A_Confidential_Brief.pdf', sizeMb: 34.5, sensitive: true, type: 'application/pdf' },
        { name: 'Quantum_Algorithm_Seed.bin', sizeMb: 520.0, sensitive: true, type: 'application/octet-stream' },
        { name: 'Customer_Master_Database_2026.csv', sizeMb: 110.0, sensitive: true, type: 'text/csv' },
      ]);
    } else if (scenarioType === 'BRUTE_FORCE') {
      for (let i = 0; i < 6; i++) {
        siemServer.ingestLog({
          timestamp: new Date(now.getTime() - (6 - i) * 15000).toISOString(),
          userId: targetUser.id,
          username: targetUser.username,
          source: 'auth-service',
          eventType: 'FAILED_LOGIN',
          action: 'AUTH_FAILED',
          resource: 'Internal-AD-Kerberos',
          ipAddress: '192.168.100.250',
          severity: 'MEDIUM',
          details: { attempt: i + 1, failure_code: 'ERR_BAD_PASSWORD' },
        });
      }
    } else if (scenarioType === 'MASS_DOWNLOAD') {
      siemServer.ingestLog({
        timestamp: now.toISOString(),
        userId: targetUser.id,
        username: targetUser.username,
        source: 'endpoint-agent',
        eventType: 'FILE_DOWNLOAD',
        action: 'EGRESS_DOWNLOAD',
        resource: '/share/corporate_archive_2026_full.tar.gz',
        ipAddress: targetUser.ipAddress,
        severity: 'HIGH',
        details: { file_size_mb: 840.0, protocol: 'SFTP' },
      });
    } else if (scenarioType === 'PRIVILEGE_ESCALATION') {
      siemServer.ingestLog({
        timestamp: now.toISOString(),
        userId: targetUser.id,
        username: targetUser.username,
        source: 'server',
        eventType: 'PRIVILEGE_CHANGE',
        action: 'SUDOERS_MODIFICATION',
        resource: '/etc/sudoers.d/backdoor',
        ipAddress: targetUser.ipAddress,
        severity: 'CRITICAL',
        details: { executed_by: 'amercer', granted_role: 'ROOT_SUPERADMIN' },
      });
    } else if (scenarioType === 'UNAUTHORIZED_ACCESS') {
      const empId = targetUser.employeeId || `EMP-${targetUser.id}`;
      const resource = '/api/admin/system/security-keys';
      const reason = `User ${empId} (Role: ${targetUser.role}) attempted unauthorized access to resource: ${resource}`;

      // 1. Generate Security Event
      db.addSecurityEvent({
        id: db.getSecurityEvents().length + 1,
        eventType: 'UNAUTHORIZED_ACCESS',
        userId: targetUser.id,
        username: targetUser.username,
        identifier: empId,
        ipAddress: targetUser.ipAddress || '10.14.88.102',
        timestamp: now.toISOString(),
        attemptCount: 1,
        threshold: 1,
        severity: 'HIGH',
        description: `Access Denied (403 Forbidden): Role '${targetUser.role}' attempted unauthorized access to protected resource '${resource}'.`,
        status: 'OPEN',
        metadata: {
          employeeId: empId,
          userRole: targetUser.role,
          resource,
          requiredRoles: ['ADMIN'],
          reason,
        },
      });

      // 2. Ingest into SIEM server engine (triggers RULE-002)
      siemServer.ingestLog({
        timestamp: now.toISOString(),
        userId: targetUser.id,
        username: targetUser.username,
        source: 'rbac-enforcer',
        eventType: 'UNAUTHORIZED_ACCESS',
        action: 'ACCESS_DENIED',
        resource,
        ipAddress: targetUser.ipAddress || '10.14.88.102',
        severity: 'HIGH',
        details: {
          resource,
          userRole: targetUser.role,
          employeeId: empId,
          requiredRoles: ['ADMIN'],
          reason,
          statusCode: 403,
        },
      });

      // 3. Audit Log
      db.addAuditLog({
        id: db.getAuditLogs().length + 1,
        actor: targetUser.username,
        userId: targetUser.id,
        action: 'UNAUTHORIZED_ACCESS_ATTEMPT',
        resource,
        details: `Blocked 403 Forbidden: ${empId} (${targetUser.role}) attempted unauthorized access to ${resource}. Required: ADMIN`,
        ipAddress: targetUser.ipAddress || '10.14.88.102',
        timestamp: now.toISOString(),
      });
    }

    return res.json({ message: `Scenario '${scenarioType}' injected successfully into database.` });
  }
);

// GET /api/admin/settings (Admin Only) - Protected endpoint for RBAC boundary testing
app.get('/api/admin/settings', authenticateJWT, requireRoles('ADMIN'), (req: Request, res: Response) => {
  return res.json({
    status: 'ok',
    message: 'Authorized access to administrative settings.',
    config: { mfaEnforced: true, zeroTrustLevel: 'MAXIMUM' },
  });
});

// POST /api/demo/seed (Admin or Security Analyst) - Load 1,000 Demo Employees, ~15k Security Events, 7 Detection Rules, Risk Scoring, Alerts
app.post('/api/demo/seed', authenticateJWT, requireRoles('ADMIN', 'SECURITY_ANALYST'), (req: Request, res: Response) => {
  siemServer.seedDemoData();
  const summary = siemServer.getSOCSummary();
  return res.json({
    message: 'Demo dataset loaded successfully (1,000 Demo Employees, ~15k Events, 7 Detection Rules, Risk Scoring, Alerts).',
    summary,
  });
});

// POST /api/admin/seed (Admin Only)
app.post('/api/admin/seed', authenticateJWT, requireRoles('ADMIN'), (req: Request, res: Response) => {
  siemServer.seedDemoData();
  const summary = siemServer.getSOCSummary();
  return res.json({
    message: 'Baseline demonstration data loaded into database.',
    summary,
  });
});

// POST /api/admin/clear (Admin Only)
app.post('/api/admin/clear', authenticateJWT, requireRoles('ADMIN'), (req: Request, res: Response) => {
  db.resetToCleanSlate();
  return res.json({ message: 'All telemetry and incidents cleared from database.' });
});

// Health check endpoint
app.get('/api/health', (req: Request, res: Response) => {
  const usersCount = db.getUsers().length;
  const filesCount = db.getFiles().length;
  res.json({
    status: 'ok',
    database: 'connected',
    users: usersCount,
    files: filesCount,
    timestamp: new Date().toISOString(),
  });
});

// Start Express Server with Vite integration & WebSocket support
async function startServer() {
  const httpServer = http.createServer(app);

  // Initialize WebSocket Real-Time Alert Server
  wsManager.initialize(httpServer);

  // Ensure baseline demonstration telemetry is present
  try {
    if (db.getNormalizedEvents().length === 0) {
      console.log('[SIEM Init] Populating initial demonstration security telemetry...');
      siemServer.seedDemoData();
    }
  } catch (seedErr) {
    console.warn('[SIEM Init] Note on telemetry population:', seedErr);
  }

  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req: Request, res: Response) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  httpServer.listen(PORT, '0.0.0.0', () => {
    console.log(`SIEM Platform backend & WebSocket engine listening on http://0.0.0.0:${PORT}`);
  });
}

// Only start the server if executed directly (not when imported in tests)
if (process.env.NODE_ENV !== 'test' && !process.env.JEST_WORKER_ID) {
  startServer();
}

export { app, startServer };
