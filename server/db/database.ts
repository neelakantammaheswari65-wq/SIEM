import fs from 'fs';
import path from 'path';
import bcrypt from 'bcryptjs';
import {
  Alert,
  AuditLog,
  DemoFile,
  FileActivityRecord,
  Finding,
  MLAnomaly,
  NormalizedEvent,
  RiskScore,
  Rule,
  SecurityLog,
  USBDevice,
  USBTransferRequest,
  User,
} from '../../src/types/siem';

export interface SecurityEventRecord {
  id: number;
  eventType: 'MULTIPLE_SIGNUP_ATTEMPTS' | 'MULTIPLE_FAILED_DOWNLOADS' | 'BRUTE_FORCE_AUTH' | 'UNAUTHORIZED_ACCESS' | 'SUSPICIOUS_ACTIVITY';
  userId?: number;
  username?: string;
  identifier?: string;
  ipAddress?: string;
  timestamp: string;
  attemptCount: number;
  threshold: number;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  description: string;
  status: 'OPEN' | 'INVESTIGATING' | 'RESOLVED';
  metadata: Record<string, any>;
}

export interface DBUser extends User {
  passwordHash: string;
}

export interface SIEMDatabaseSchema {
  version: number;
  lastUpdated: string;
  users: DBUser[];
  files: DemoFile[];
  fileActivities: FileActivityRecord[];
  securityLogs: SecurityLog[];
  normalizedEvents: NormalizedEvent[];
  rules: Rule[];
  findings: Finding[];
  riskScores: RiskScore[];
  mlAnomalies: MLAnomaly[];
  alerts: Alert[];
  usbDevices: USBDevice[];
  usbTransfers: USBTransferRequest[];
  auditLogs: AuditLog[];
  securityEvents: SecurityEventRecord[];
}

// Initial baseline users
const defaultSalt = bcrypt.genSaltSync(10);
const defaultHashedPassword = bcrypt.hashSync('password123', defaultSalt);

export const INITIAL_USERS: DBUser[] = [
  {
    id: 101,
    username: 'amercer',
    email: 'alex.mercer@corp-apex.internal',
    passwordHash: defaultHashedPassword,
    fullName: 'Alex Mercer',
    department: 'R&D Engineering',
    role: 'EMPLOYEE',
    status: 'ACTIVE',
    employeeId: 'EMP-101',
    designation: 'Senior Software Engineer',
    clearanceLevel: 'INTERNAL',
    createdAt: '2025-01-15T08:00:00Z',
    lastLogin: new Date().toISOString(),
    ipAddress: '10.14.88.102',
  },
  {
    id: 102,
    username: 'schen',
    email: 'sarah.chen@corp-apex.internal',
    passwordHash: defaultHashedPassword,
    fullName: 'Sarah Chen',
    department: 'Infrastructure & DevOps',
    role: 'ADMIN',
    status: 'ACTIVE',
    employeeId: 'EMP-102',
    designation: 'Director of Cloud Infrastructure',
    clearanceLevel: 'RESTRICTED',
    createdAt: '2024-06-10T08:00:00Z',
    lastLogin: new Date().toISOString(),
    ipAddress: '10.14.88.15',
  },
  {
    id: 103,
    username: 'dkim',
    email: 'david.kim@corp-apex.internal',
    passwordHash: defaultHashedPassword,
    fullName: 'David Kim',
    department: 'Security Operations',
    role: 'SECURITY_ANALYST',
    status: 'ACTIVE',
    employeeId: 'EMP-103',
    designation: 'Lead SOC Analyst',
    clearanceLevel: 'RESTRICTED',
    createdAt: '2024-09-01T08:00:00Z',
    lastLogin: new Date().toISOString(),
    ipAddress: '10.14.88.22',
  },
  {
    id: 104,
    username: 'admin',
    email: 'admin@corp-apex.internal',
    passwordHash: defaultHashedPassword,
    fullName: 'SOC Lead Administrator',
    department: 'Cyber Command',
    role: 'ADMIN',
    status: 'ACTIVE',
    employeeId: 'EMP-001',
    designation: 'Enterprise Security Administrator',
    clearanceLevel: 'RESTRICTED',
    createdAt: '2024-01-01T08:00:00Z',
    lastLogin: new Date().toISOString(),
    ipAddress: '10.14.88.1',
  },
  {
    id: 105,
    username: 'rvance',
    email: 'robert.vance@corp-apex.internal',
    passwordHash: defaultHashedPassword,
    fullName: 'Robert Vance',
    department: 'Finance & Strategy',
    role: 'EMPLOYEE',
    status: 'ACTIVE',
    employeeId: 'EMP-105',
    designation: 'Strategic Financial Analyst',
    clearanceLevel: 'CONFIDENTIAL',
    createdAt: '2025-02-01T08:00:00Z',
    lastLogin: new Date().toISOString(),
    ipAddress: '10.14.88.105',
  },
];

export const INITIAL_FILES: DemoFile[] = [
  {
    id: 'f-handbook-001',
    name: 'Employee_Handbook.pdf',
    sizeMb: 2,
    classification: 'PUBLIC',
    type: 'PDF Document',
    department: 'Human Resources',
    accessPermission: 'PUBLIC',
    description: 'Corporate employee onboarding policies, conduct guidelines, and workplace ethics.',
    lastModified: '2026-01-10T09:00:00Z',
  },
  {
    id: 'f-report-002',
    name: 'Team_Project_Report.docx',
    sizeMb: 20,
    classification: 'INTERNAL',
    type: 'Word Document',
    department: 'Engineering',
    accessPermission: 'INTERNAL',
    description: 'Quarterly cross-functional milestone progress, sprint reviews, and engineering deliverables.',
    lastModified: '2026-02-15T14:30:00Z',
  },
  {
    id: 'f-finance-003',
    name: 'Financial_Report_2026.xlsx',
    sizeMb: 150,
    classification: 'CONFIDENTIAL',
    type: 'Excel Spreadsheet',
    department: 'Finance',
    accessPermission: 'CONFIDENTIAL',
    description: 'Annual corporate financial audit, departmental budgets, cash flow statements, and EBITDA forecasts.',
    lastModified: '2026-02-28T18:00:00Z',
  },
  {
    id: 'f-customer-004',
    name: 'Customer_Database_Backup.zip',
    sizeMb: 450,
    classification: 'CONFIDENTIAL',
    type: 'Zip Archive',
    department: 'Customer Operations',
    accessPermission: 'CONFIDENTIAL',
    description: 'Production customer accounts dump, transaction ledgers, CRM metadata, and partner profiles.',
    lastModified: '2026-02-20T11:45:00Z',
  },
  {
    id: 'f-strategy-005',
    name: 'Strategic_Business_Plan.pdf',
    sizeMb: 750,
    classification: 'HIGHLY_CONFIDENTIAL',
    type: 'PDF Document',
    department: 'Executive Leadership',
    accessPermission: 'HIGHLY_CONFIDENTIAL',
    description: 'Long-term 5-year growth strategy, proprietary patent roadmaps, and competitive intelligence.',
    lastModified: '2026-03-01T02:00:00Z',
  },
  {
    id: 'f-payroll-006',
    name: 'Payroll_Records.xlsx',
    sizeMb: 300,
    classification: 'CONFIDENTIAL',
    type: 'Excel Spreadsheet',
    department: 'Human Resources & Finance',
    accessPermission: 'CONFIDENTIAL',
    description: 'Enterprise executive compensation, employee salary grades, bonuses, and direct deposit details.',
    lastModified: '2026-03-01T08:00:00Z',
  },
  {
    id: 'f-source-007',
    name: 'Source_Code_Archive.zip',
    sizeMb: 600,
    classification: 'INTERNAL',
    type: 'Zip Archive',
    department: 'Engineering',
    accessPermission: 'INTERNAL',
    description: 'Monorepo backend source code archives, core microservices, and internal libraries.',
    lastModified: '2026-02-25T16:15:00Z',
  },
  {
    id: 'f-ma-008',
    name: 'M&A_Strategy_Document.pdf',
    sizeMb: 800,
    classification: 'HIGHLY_CONFIDENTIAL',
    type: 'PDF Document',
    department: 'Executive Leadership',
    accessPermission: 'HIGHLY_CONFIDENTIAL',
    description: 'Confidential target acquisition valuations, deal structures, and non-disclosure contracts.',
    lastModified: '2026-03-01T12:00:00Z',
  },
];

export const INITIAL_RULES: Rule[] = [
  {
    id: 1,
    ruleCode: 'RULE-001',
    name: 'Multiple Failed Logins',
    description: 'Detects 5 or more failed login attempts within a 10-minute rolling detection window',
    eventType: 'FAILED_LOGIN',
    severity: 'HIGH',
    enabled: true,
    conditions: [],
    isTemporal: true,
    temporalConfig: { countThreshold: 5, windowMinutes: 10 },
    riskWeight: 35,
    createdAt: new Date(Date.now() - 86400000 * 30).toISOString(),
  },
  {
    id: 2,
    ruleCode: 'RULE-002',
    name: 'Unauthorized Access',
    description: 'Detects unauthorized access attempts to protected endpoints and administrative resources (403 Forbidden / RBAC boundary violations)',
    eventType: 'UNAUTHORIZED_ACCESS',
    severity: 'HIGH',
    enabled: true,
    conditions: [
      {
        field: 'action',
        operator: 'in',
        value: ['ACCESS_DENIED', 'RBAC_VIOLATION', 'UNAUTHORIZED_ACCESS', 'FORBIDDEN_403', 'FORBIDDEN'],
      },
    ],
    riskWeight: 40,
    createdAt: new Date(Date.now() - 86400000 * 30).toISOString(),
  },
  {
    id: 3,
    ruleCode: 'RULE-003',
    name: 'Sensitive File Access',
    description: 'Detects access to CONFIDENTIAL, RESTRICTED, or HIGHLY_CONFIDENTIAL corporate repositories',
    eventType: 'FILE_ACCESS',
    severity: 'MEDIUM',
    enabled: true,
    conditions: [
      {
        field: 'classification',
        operator: 'in',
        value: ['CONFIDENTIAL', 'RESTRICTED', 'SENSITIVE', 'HIGHLY_CONFIDENTIAL'],
      },
    ],
    riskWeight: 25,
    createdAt: new Date(Date.now() - 86400000 * 30).toISOString(),
  },
  {
    id: 4,
    ruleCode: 'RULE-004',
    name: 'Large File Download (>500MB)',
    description: 'Detects bulk file egress and downloads exceeding the 500 MB enterprise security threshold',
    eventType: 'FILE_ACCESS',
    severity: 'HIGH',
    enabled: true,
    conditions: [
      { field: 'action', operator: '==', value: 'DOWNLOAD' },
      { field: 'sizeMb', operator: '>', value: 500 },
    ],
    riskWeight: 40,
    createdAt: new Date(Date.now() - 86400000 * 30).toISOString(),
  },
  {
    id: 5,
    ruleCode: 'RULE-005',
    name: 'Unauthorized USB Device Inserted',
    description: 'Detects connection of an unapproved, unwhitelisted external USB mass storage peripheral',
    eventType: 'USB_INSERT',
    severity: 'HIGH',
    enabled: true,
    conditions: [{ field: 'authorized', operator: '==', value: false }],
    riskWeight: 35,
    createdAt: new Date(Date.now() - 86400000 * 30).toISOString(),
  },
  {
    id: 6,
    ruleCode: 'RULE-006',
    name: 'High-Volume USB Transfer (>500MB)',
    description: 'Detects attempted external drive data egress exceeding enterprise DLP 500MB threshold',
    eventType: 'USB_TRANSFER_REQUEST',
    severity: 'HIGH',
    enabled: true,
    conditions: [{ field: 'totalSizeMb', operator: '>', value: 500 }],
    riskWeight: 45,
    createdAt: new Date(Date.now() - 86400000 * 30).toISOString(),
  },
  {
    id: 7,
    ruleCode: 'RULE-007',
    name: 'Privilege Escalation Detected',
    description: 'Detects modifications to root permissions, sudoers files, or unauthorized privilege elevation',
    eventType: 'PRIVILEGE_CHANGE',
    severity: 'CRITICAL',
    enabled: true,
    conditions: [{ field: 'action', operator: 'contains', value: 'SUDO' }],
    riskWeight: 50,
    createdAt: new Date(Date.now() - 86400000 * 30).toISOString(),
  },
];

export const INITIAL_USB_DEVICES: USBDevice[] = [
  {
    id: 1,
    deviceId: 'USB-CORP-001',
    deviceName: 'Kingston IronKey D300 (Hardware Encrypted)',
    vendor: 'Kingston',
    serialNumber: 'IKD300-9948271',
    capacityGb: 32,
    userId: 102,
    username: 'schen',
    authorized: true,
    status: 'CONNECTED',
    insertedAt: new Date(Date.now() - 3600000 * 4).toISOString(),
    createdAt: '2026-01-10T08:00:00Z',
  },
  {
    id: 2,
    deviceId: 'USB-CORP-002',
    deviceName: 'SanDisk Ultra Dual Drive Luxe',
    vendor: 'SanDisk',
    serialNumber: 'SDLUX-4482019',
    capacityGb: 64,
    userId: 103,
    username: 'dkim',
    authorized: true,
    status: 'DISCONNECTED',
    insertedAt: new Date(Date.now() - 86400000).toISOString(),
    removedAt: new Date(Date.now() - 86400000 + 1800000).toISOString(),
    createdAt: '2026-01-15T08:00:00Z',
  },
  {
    id: 3,
    deviceId: 'USB-PERS-404',
    deviceName: 'Generic Mass Storage Device (Unidentified)',
    vendor: 'Generic USB',
    serialNumber: 'GEN-8839210',
    capacityGb: 128,
    userId: 101,
    username: 'amercer',
    authorized: false,
    status: 'BLOCKED',
    insertedAt: new Date(Date.now() - 1800000).toISOString(),
    createdAt: '2026-02-01T08:00:00Z',
  },
];

export class DatabaseService {
  private static instance: DatabaseService;
  private dbFilePath: string;
  private data: SIEMDatabaseSchema;
  private saveTimeout: NodeJS.Timeout | null = null;

  private constructor() {
    const dataDir = path.join(process.cwd(), 'data');
    if (!fs.existsSync(dataDir)) {
      try {
        fs.mkdirSync(dataDir, { recursive: true });
      } catch (e) {
        // ignore if already created
      }
    }
    this.dbFilePath = process.env.DATABASE_FILE_PATH || path.join(dataDir, 'siem_database.json');
    this.data = this.loadOrCreateDatabase();
  }

  public static getInstance(): DatabaseService {
    if (!DatabaseService.instance) {
      DatabaseService.instance = new DatabaseService();
    }
    return DatabaseService.instance;
  }

  private createFreshSchema(): SIEMDatabaseSchema {
    return {
      version: 1,
      lastUpdated: new Date().toISOString(),
      users: JSON.parse(JSON.stringify(INITIAL_USERS)),
      files: JSON.parse(JSON.stringify(INITIAL_FILES)),
      fileActivities: [],
      securityLogs: [],
      normalizedEvents: [],
      rules: JSON.parse(JSON.stringify(INITIAL_RULES)),
      findings: [],
      riskScores: [],
      mlAnomalies: [],
      alerts: [],
      usbDevices: JSON.parse(JSON.stringify(INITIAL_USB_DEVICES)),
      usbTransfers: [],
      auditLogs: [],
      securityEvents: [],
    };
  }

  private loadOrCreateDatabase(): SIEMDatabaseSchema {
    try {
      if (fs.existsSync(this.dbFilePath)) {
        const raw = fs.readFileSync(this.dbFilePath, 'utf-8');
        const parsed = JSON.parse(raw) as SIEMDatabaseSchema;
        if (parsed && Array.isArray(parsed.users) && Array.isArray(parsed.files)) {
          // Ensure all tables exist
          // Sync initial catalog files if missing
          INITIAL_FILES.forEach((initFile) => {
            const idx = parsed.files.findIndex((f) => f.id === initFile.id || f.name === initFile.name);
            if (idx >= 0) {
              parsed.files[idx] = { ...initFile, ...parsed.files[idx], sizeMb: initFile.sizeMb, classification: initFile.classification };
            } else {
              parsed.files.push(initFile);
            }
          });
          INITIAL_USERS.forEach((initUser) => {
            const idx = parsed.users.findIndex((u) => u.username === initUser.username);
            if (idx >= 0) {
              parsed.users[idx] = {
                ...parsed.users[idx],
                employeeId: initUser.employeeId || parsed.users[idx].employeeId,
                designation: initUser.designation || parsed.users[idx].designation,
                clearanceLevel: initUser.clearanceLevel || parsed.users[idx].clearanceLevel,
                role: parsed.users[idx].role === 'VIEWER' ? 'EMPLOYEE' : parsed.users[idx].role,
              };
            } else {
              parsed.users.push(initUser);
            }
          });

          // Sanitize user list: deduplicate by username, resolve ID collisions, ensure employeeId
          const deduplicatedUsers: DBUser[] = [];
          const seenUsernames = new Set<string>();
          for (const u of parsed.users) {
            const lowerUsername = u.username.toLowerCase();
            if (seenUsernames.has(lowerUsername)) continue;
            seenUsernames.add(lowerUsername);
            deduplicatedUsers.push(u);
          }

          // Ensure Jane Doe (emp_test_mtk7107v) has employeeId EMP-106 and id 106
          const janeDoe = deduplicatedUsers.find((u) => u.username === 'emp_test_mtk7107v');
          if (janeDoe) {
            janeDoe.employeeId = 'EMP-106';
            janeDoe.id = 106;
          }

          // If another user (like xyz) shares id 106, reassign to avoid collision with EMP-106 / Jane Doe
          const xyzAdmin = deduplicatedUsers.find((u) => u.username === 'xyz');
          if (xyzAdmin && xyzAdmin.id === 106) {
            xyzAdmin.id = 150;
          }

          // Ensure strictly unique numeric IDs across all users
          const assignedIds = new Set<number>();
          for (const u of deduplicatedUsers) {
            if (assignedIds.has(u.id)) {
              u.id = Math.max(...Array.from(assignedIds), 100) + 1;
            }
            assignedIds.add(u.id);

            // Backfill employeeId if missing
            if (!u.employeeId && u.role === 'EMPLOYEE') {
              u.employeeId = `EMP-${u.id}`;
            }
          }

          parsed.users = deduplicatedUsers;
          parsed.rules = JSON.parse(JSON.stringify(INITIAL_RULES));
          if (!parsed.fileActivities) parsed.fileActivities = [];
          if (!parsed.securityLogs) parsed.securityLogs = [];
          if (!parsed.normalizedEvents) parsed.normalizedEvents = [];
          if (!parsed.rules) parsed.rules = JSON.parse(JSON.stringify(INITIAL_RULES));
          if (!parsed.findings) parsed.findings = [];
          if (!parsed.riskScores) parsed.riskScores = [];
          if (!parsed.mlAnomalies) parsed.mlAnomalies = [];
          if (!parsed.alerts) parsed.alerts = [];
          if (!parsed.usbDevices) parsed.usbDevices = JSON.parse(JSON.stringify(INITIAL_USB_DEVICES));
          if (!parsed.usbTransfers) parsed.usbTransfers = [];
          if (!parsed.auditLogs) parsed.auditLogs = [];
          if (!parsed.securityEvents) parsed.securityEvents = [];
          return parsed;
        }
      }
    } catch (err) {
      console.warn('Could not read existing database file, initializing fresh database:', err);
    }

    const fresh = this.createFreshSchema();
    this.saveImmediate(fresh);
    return fresh;
  }

  private saveImmediate(dataToSave?: SIEMDatabaseSchema): void {
    const data = dataToSave || this.data;
    data.lastUpdated = new Date().toISOString();
    try {
      const tempPath = `${this.dbFilePath}.tmp`;
      fs.writeFileSync(tempPath, JSON.stringify(data, null, 2), 'utf-8');
      fs.renameSync(tempPath, this.dbFilePath);
    } catch (err) {
      console.error('Failed to persist database to disk:', err);
    }
  }

  public save(): void {
    if (this.saveTimeout) {
      clearTimeout(this.saveTimeout);
    }
    this.saveTimeout = setTimeout(() => {
      this.saveImmediate();
      this.saveTimeout = null;
    }, 50);
  }

  public resetToCleanSlate(): void {
    this.data.fileActivities = [];
    this.data.securityLogs = [];
    this.data.normalizedEvents = [];
    this.data.findings = [];
    this.data.riskScores = [];
    this.data.mlAnomalies = [];
    this.data.alerts = [];
    this.data.usbTransfers = [];
    this.data.auditLogs = [];
    this.data.securityEvents = [];
    this.saveImmediate();
  }

  // Generic and Table Accessors
  public getSchema(): SIEMDatabaseSchema {
    return this.data;
  }

  // Users
  public getUsers(): DBUser[] {
    return this.data.users;
  }

  public getEmployees(): DBUser[] {
    return this.data.users.filter((u) => !!u.isManual);
  }

  public getUserById(id: number): DBUser | undefined {
    return this.data.users.find((u) => u.id === id);
  }

  public getUserByUsername(username: string): DBUser | undefined {
    return this.data.users.find((u) => u.username.toLowerCase() === username.toLowerCase());
  }

  public getUserByEmail(email: string): DBUser | undefined {
    return this.data.users.find((u) => u.email.toLowerCase() === email.toLowerCase());
  }

  public getUserByEmployeeId(employeeId: string): DBUser | undefined {
    if (!employeeId) return undefined;
    const clean = employeeId.trim().toLowerCase();
    return this.data.users.find((u) => {
      if (u.employeeId && u.employeeId.trim().toLowerCase() === clean) return true;
      if (u.employeeId) {
        const uClean = u.employeeId.trim().toLowerCase();
        if (clean.replace(/^emp-/, '') === uClean.replace(/^emp-/, '')) return true;
      }
      if (`emp-${u.id}`.toLowerCase() === clean) return true;
      return false;
    });
  }

  public addUser(user: DBUser): DBUser {
    if (!user.id || this.data.users.some((u) => u.id === user.id)) {
      user.id = Math.max(...this.data.users.map((u) => u.id || 100), 100) + 1;
    }
    this.data.users.push(user);
    this.saveImmediate();
    return user;
  }

  public updateUser(id: number, updates: Partial<DBUser>): DBUser | undefined {
    const user = this.getUserById(id);
    if (!user) return undefined;
    Object.assign(user, updates);
    this.saveImmediate();
    return user;
  }

  public deleteUser(idOrEmployeeId: number | string): DBUser | undefined {
    const idx = this.data.users.findIndex((u) => {
      if (typeof idOrEmployeeId === 'number' || !isNaN(Number(idOrEmployeeId))) {
        if (u.id === Number(idOrEmployeeId)) return true;
      }
      return (
        (u.employeeId && u.employeeId.trim().toLowerCase() === String(idOrEmployeeId).trim().toLowerCase()) ||
        (u.username && u.username.trim().toLowerCase() === String(idOrEmployeeId).trim().toLowerCase())
      );
    });

    if (idx < 0) return undefined;
    const removed = this.data.users.splice(idx, 1)[0];
    this.saveImmediate();
    return removed;
  }

  // Files
  public getFiles(): DemoFile[] {
    return this.data.files;
  }

  public getFileById(id: string): DemoFile | undefined {
    return this.data.files.find((f) => f.id === id);
  }

  // File Activities
  public getFileActivities(userId?: number): FileActivityRecord[] {
    if (userId !== undefined) {
      return this.data.fileActivities.filter((a) => a.userId === userId);
    }
    return this.data.fileActivities;
  }

  public addFileActivity(activity: FileActivityRecord): void {
    this.data.fileActivities.unshift(activity);
    if (this.data.fileActivities.length > 2000) {
      this.data.fileActivities.pop();
    }
    this.save();
  }

  // Security Logs & Events
  public getSecurityLogs(): SecurityLog[] {
    return this.data.securityLogs;
  }

  public addSecurityLog(log: SecurityLog): void {
    this.data.securityLogs.unshift(log);
    if (this.data.securityLogs.length > 25000) {
      this.data.securityLogs.pop();
    }
    this.save();
  }

  public getNormalizedEvents(): NormalizedEvent[] {
    return this.data.normalizedEvents;
  }

  public addNormalizedEvent(event: NormalizedEvent): void {
    this.data.normalizedEvents.unshift(event);
    if (this.data.normalizedEvents.length > 25000) {
      this.data.normalizedEvents.pop();
    }
    this.save();
  }

  // Rules
  public getRules(): Rule[] {
    return this.data.rules;
  }

  public getRuleById(id: number): Rule | undefined {
    return this.data.rules.find((r) => r.id === id);
  }

  public addRule(rule: Rule): void {
    this.data.rules.push(rule);
    this.save();
  }

  public setRules(rules: Rule[]): void {
    this.data.rules = rules;
    this.save();
  }

  public updateRule(id: number, updates: Partial<Rule>): Rule | undefined {
    const rule = this.getRuleById(id);
    if (!rule) return undefined;
    Object.assign(rule, updates, { updatedAt: new Date().toISOString() });
    this.save();
    return rule;
  }

  // Findings
  public getFindings(): Finding[] {
    return this.data.findings;
  }

  public addFinding(finding: Finding): void {
    this.data.findings.unshift(finding);
    if (this.data.findings.length > 25000) {
      this.data.findings.pop();
    }
    this.save();
  }

  // Risk Scores
  public getRiskScores(): RiskScore[] {
    return this.data.riskScores;
  }

  public getRiskScoreByUserId(userId: number): RiskScore | undefined {
    return this.data.riskScores.find((r) => r.userId === userId);
  }

  public setRiskScore(score: RiskScore): void {
    const idx = this.data.riskScores.findIndex((r) => r.userId === score.userId);
    if (idx >= 0) {
      this.data.riskScores[idx] = score;
    } else {
      this.data.riskScores.push(score);
    }
    this.save();
  }

  // ML Anomalies
  public getMLAnomalies(): MLAnomaly[] {
    return this.data.mlAnomalies;
  }

  public getMLAnomalyByUserId(userId: number): MLAnomaly | undefined {
    return this.data.mlAnomalies.find((a) => a.userId === userId);
  }

  public setMLAnomaly(anomaly: MLAnomaly): void {
    const idx = this.data.mlAnomalies.findIndex((a) => a.userId === anomaly.userId);
    if (idx >= 0) {
      this.data.mlAnomalies[idx] = anomaly;
    } else {
      this.data.mlAnomalies.push(anomaly);
    }
    this.save();
  }

  // Alerts
  public getAlerts(): Alert[] {
    return this.data.alerts;
  }

  public getAlertById(alertId: string): Alert | undefined {
    return this.data.alerts.find((a) => a.alertId === alertId);
  }

  public addAlert(alert: Alert): void {
    this.data.alerts.unshift(alert);
    console.log(
      `[ALERT_CREATED] Alert: ${alert.alertId} | Severity: ${alert.severity} | Title: "${alert.title}" | Target: ${alert.username} (Risk Score: ${alert.riskScore})`
    );
    this.save();
  }

  public updateAlert(alertId: string, updates: Partial<Alert>): Alert | undefined {
    const alert = this.getAlertById(alertId);
    if (!alert) return undefined;
    Object.assign(alert, updates, { updatedAt: new Date().toISOString() });
    this.save();
    return alert;
  }

  // USB
  public getUSBDevices(): USBDevice[] {
    return this.data.usbDevices;
  }

  public getUSBDeviceById(deviceId: string): USBDevice | undefined {
    return this.data.usbDevices.find((d) => d.deviceId === deviceId);
  }

  public addOrUpdateUSBDevice(device: USBDevice): void {
    const idx = this.data.usbDevices.findIndex((d) => d.deviceId === device.deviceId);
    if (idx >= 0) {
      this.data.usbDevices[idx] = device;
    } else {
      this.data.usbDevices.unshift(device);
    }
    this.save();
  }

  public getUSBTransfers(): USBTransferRequest[] {
    return this.data.usbTransfers;
  }

  public addUSBTransfer(transfer: USBTransferRequest): void {
    this.data.usbTransfers.unshift(transfer);
    this.save();
  }

  // Audit Logs
  public getAuditLogs(): AuditLog[] {
    return this.data.auditLogs;
  }

  public addAuditLog(log: AuditLog): void {
    this.data.auditLogs.unshift(log);
    if (this.data.auditLogs.length > 2000) {
      this.data.auditLogs.pop();
    }
    this.save();
  }

  // Security Events (Abuse tracking)
  public getSecurityEvents(): SecurityEventRecord[] {
    return this.data.securityEvents;
  }

  public addSecurityEvent(event: SecurityEventRecord): void {
    this.data.securityEvents.unshift(event);
    if (this.data.securityEvents.length > 2000) {
      this.data.securityEvents.pop();
    }
    this.save();
  }
}

export const db = DatabaseService.getInstance();
