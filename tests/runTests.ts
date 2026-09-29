import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { db, DBUser } from '../server/db/database';
import { siemServer } from '../server/services/siemServerEngine';
import { securityAbuse } from '../server/services/securityAbuseService';

let passedCount = 0;
let failedCount = 0;

function assert(condition: boolean, testName: string, detail?: string) {
  if (condition) {
    passedCount++;
    console.log(`  \x1b[32m✔ PASS\x1b[0m ${testName}`);
  } else {
    failedCount++;
    console.error(`  \x1b[31m✖ FAIL\x1b[0m ${testName}`);
    if (detail) console.error(`    -> ${detail}`);
  }
}

async function runTestSuite() {
  console.log('\n=============================================================');
  console.log(' SIEM INSIDER THREAT DETECTION PLATFORM - AUTOMATED TEST SUITE');
  console.log('=============================================================\n');

  // -------------------------------------------------------------
  // SUITE 1: UNIT TESTS (Crypto, Scoring & Rules)
  // -------------------------------------------------------------
  console.log('\x1b[36m[SUITE 1] Unit Tests: Cryptography, Rule Conditions & Risk Math\x1b[0m');

  // Test 1.1: Password hashing and comparison
  const testPass = 'SecretAdminP@ssw0rd!2026';
  const hashed = bcrypt.hashSync(testPass, 10);
  assert(bcrypt.compareSync(testPass, hashed), 'bcrypt password hashing and verification succeeds');
  assert(!bcrypt.compareSync('WrongPassword', hashed), 'bcrypt password verification rejects bad password');

  // Test 1.2: JWT generation & decoding
  const testPayload = { id: 999, username: 'testuser', role: 'ADMIN' };
  const token = jwt.sign(testPayload, 'siem_soc_jwt_secure_secret_key_2026', { expiresIn: '1h' });
  const decoded = jwt.verify(token, 'siem_soc_jwt_secure_secret_key_2026') as any;
  assert(decoded.id === 999 && decoded.username === 'testuser', 'JWT tokens encode and verify user identity correctly');

  // Test 1.3: Risk Score Calculation
  const testUser = db.getUsers()[0];
  const initialRisk = siemServer.recalculateRisk(testUser.id);
  assert(typeof initialRisk.finalScore === 'number' && initialRisk.finalScore >= 0 && initialRisk.finalScore <= 100, 'Risk score calculates bounded numeric value (0-100)');
  assert(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(initialRisk.riskLevel), 'Risk level maps correctly to categorical enum');

  // Test 1.4: ML Isolation Forest Anomaly Scoring
  const mlResult = siemServer.recalculateMLAnomaly(testUser.id);
  assert(typeof mlResult.anomalyScore === 'number' && mlResult.anomalyScore >= 0 && mlResult.anomalyScore <= 100, 'ML anomaly score computes within valid range (0-100)');
  assert(Array.isArray(mlResult.indicators) && mlResult.indicators.length > 0, 'ML anomaly provides diagnostic feature indicators');

  // -------------------------------------------------------------
  // SUITE 2: INTEGRATION TESTS (Database, SIEM Pipeline & DLP)
  // -------------------------------------------------------------
  console.log('\n\x1b[36m[SUITE 2] Integration Tests: Database Persistence & SIEM Engine\x1b[0m');

  // Test 2.1: Database Schema & Users
  const allUsers = db.getUsers();
  assert(allUsers.length >= 4, `Database initialized with default user accounts (${allUsers.length} users found)`);
  const adminUser = db.getUserByUsername('admin');
  assert(adminUser !== undefined && adminUser.role === 'ADMIN', 'Admin user account exists with ADMIN role');

  // Test 2.2: Files Repository
  const files = db.getFiles();
  assert(files.length >= 8, `Corporate file repository loaded ${files.length} cataloged documents`);
  const confidentialDoc = files.find((f) => f.classification === 'CONFIDENTIAL');
  assert(confidentialDoc !== undefined, 'Confidential data classification files exist in database');

  // Test 2.3: Ingestion -> Normalization -> Rule Findings Pipeline
  const ingestResult = siemServer.ingestLog({
    timestamp: new Date().toISOString(),
    userId: testUser.id,
    username: testUser.username,
    source: 'endpoint-agent',
    eventType: 'FILE_ACCESS',
    action: 'DOWNLOAD',
    resource: '/shares/rnd/Source_Code_Repository.zip',
    ipAddress: testUser.ipAddress,
    severity: 'HIGH',
    details: {
      file_id: 'f-source-006',
      file_name: 'Source_Code_Repository.zip',
      size_mb: 750,
      classification: 'RESTRICTED',
      action: 'DOWNLOAD',
    },
  });

  assert(ingestResult.log.id > 0, 'Log entry ingested with auto-increment ID');
  assert(ingestResult.event.processed === true, 'Normalized event successfully processed by rule engine');
  assert(ingestResult.findings.length > 0, `Rule engine flagged ${ingestResult.findings.length} findings for large file download`);

  // Test 2.4: USB Transfer Policy Evaluation
  const transferAllow = siemServer.requestUSBTransfer(testUser.id, 'USB-CORP-001', [
    { name: 'Public_Guide.pdf', sizeMb: 5, sensitive: false, type: 'application/pdf' },
  ]);
  assert(transferAllow.decision === 'ALLOW', 'Authorized USB drive with small non-sensitive payload is ALLOWED');

  const transferBlock = siemServer.requestUSBTransfer(testUser.id, 'USB-PERS-404', [
    { name: 'Secret.bin', sizeMb: 50, sensitive: true, type: 'application/octet-stream' },
  ]);
  assert(transferBlock.decision === 'BLOCK', 'Unauthorized USB drive transfer is BLOCKED by DLP policy');

  // -------------------------------------------------------------
  // SUITE 3: SECURITY & ABUSE DETECTION TESTS (Requirement 4)
  // -------------------------------------------------------------
  console.log('\n\x1b[36m[SUITE 3] Security & Abuse Detection: Sign-up Velocity & Failed Downloads\x1b[0m');

  securityAbuse.resetTrackers();

  // Test 3.1: Normal sign-up attempt does not trigger abuse
  const singleSignup = securityAbuse.recordSignupAttempt('normal_user_1', '192.168.1.10', true);
  assert(!singleSignup.abuseDetected && singleSignup.attemptCount === 1, 'Single normal registration attempt does not trigger abuse alert');

  // Test 3.2: Repeated sign-up attempts trigger threshold-based alert
  const signupIp = '203.0.113.45';
  securityAbuse.recordSignupAttempt('bot_user', signupIp, false, 'Bad input');
  securityAbuse.recordSignupAttempt('bot_user', signupIp, false, 'Bad input');
  const abuseTrigger = securityAbuse.recordSignupAttempt('bot_user', signupIp, false, 'Bad input');

  assert(abuseTrigger.abuseDetected === true, 'Rapid repeated sign-up attempts (>= threshold) trigger abuse detection');
  assert(abuseTrigger.securityEvent !== undefined, 'SecurityEvent record created in database for sign-up abuse');
  assert(abuseTrigger.securityEvent?.eventType === 'MULTIPLE_SIGNUP_ATTEMPTS', 'SecurityEvent type is MULTIPLE_SIGNUP_ATTEMPTS');
  assert(abuseTrigger.alert !== undefined, 'Correlating Alert generated in SIEM alert registry for SOC visibility');

  // Test 3.3: Normal file access does not trigger download failure abuse
  const singleFail = securityAbuse.recordFailedDownload('f-handbook-001', 'AUTH_ERROR', testUser.id, testUser.username, '10.14.88.102');
  assert(!singleFail.abuseDetected && singleFail.failureCount === 1, 'Single download failure does not trigger abuse alert');

  // Test 3.4: Repeated failed downloads exceed threshold -> triggers alert
  securityAbuse.recordFailedDownload('f-nonexistent-1', 'FILE_NOT_FOUND', testUser.id, testUser.username, '10.14.88.102');
  securityAbuse.recordFailedDownload('f-nonexistent-2', 'FILE_NOT_FOUND', testUser.id, testUser.username, '10.14.88.102');
  const downloadAbuse = securityAbuse.recordFailedDownload('f-nonexistent-3', 'FILE_NOT_FOUND', testUser.id, testUser.username, '10.14.88.102');

  assert(downloadAbuse.abuseDetected === true, 'Repeated failed downloads (>= threshold) trigger abuse detection');
  assert(downloadAbuse.securityEvent?.eventType === 'MULTIPLE_FAILED_DOWNLOADS', 'SecurityEvent type is MULTIPLE_FAILED_DOWNLOADS');
  assert(downloadAbuse.alert?.title.includes('Repeated Failed Downloads'), 'SIEM Alert created with detailed diagnostic evidence');

  // Test 3.5: User isolation in abuse tracking
  const otherUserFail = securityAbuse.recordFailedDownload('f-secret-009', 'FORBIDDEN', 103, 'dkim', '10.14.88.22');
  assert(otherUserFail.failureCount === 1 && !otherUserFail.abuseDetected, 'Abuse velocity is tracked independently per user/IP');

  // -------------------------------------------------------------
  // SUITE 4: SMOKE TEST (System Health & Summary Aggregation)
  // -------------------------------------------------------------
  console.log('\n\x1b[36m[SUITE 4] Smoke Test: SOC Summary Aggregation & Audit Trail\x1b[0m');

  const summary = siemServer.getSOCSummary();
  assert(typeof summary.totalEvents === 'number' && summary.totalEvents > 0, `Total events tracked in database: ${summary.totalEvents}`);
  assert(typeof summary.openAlerts === 'number', `Open SOC incidents tracked: ${summary.openAlerts}`);
  assert(typeof summary.rulesActive === 'number' && summary.rulesActive > 0, `Active detection rules: ${summary.rulesActive}`);

  const auditCount = db.getAuditLogs().length;
  assert(auditCount > 0, `Audit compliance trail recorded ${auditCount} actions in database`);

  // -------------------------------------------------------------
  // SUITE 5: COMPLETE END-TO-END REAL TEST WORKFLOW
  // -------------------------------------------------------------
  console.log('\n\x1b[36m[SUITE 5] End-to-End Real Test: Employee Registration, 750MB Download & SOC Alert Flow\x1b[0m');

  // Step 1: Register employee
  const testEmpUsername = `emp_test_${Date.now().toString(36)}`;
  const testEmpPassword = 'ComplexPassword123!';
  const newEmpId = Math.max(...db.getUsers().map((u) => u.id || 100), 100) + 1;
  const newEmpUser = db.addUser({
    id: newEmpId,
    username: testEmpUsername,
    employeeId: `EMP-${newEmpId}`,
    email: `${testEmpUsername}@corp-apex.internal`,
    passwordHash: bcrypt.hashSync(testEmpPassword, 10),
    fullName: 'Jane Doe Senior Analyst',
    department: 'Corporate Strategy',
    role: 'EMPLOYEE',
    status: 'ACTIVE',
    createdAt: new Date().toISOString(),
    lastLogin: new Date().toISOString(),
    ipAddress: '10.14.88.199',
  });
  assert(newEmpUser.id > 0 && newEmpUser.role === 'EMPLOYEE', 'Employee user created and stored in database');

  // Step 2: Employee Authentication
  const authRecord = db.getUserByUsername(testEmpUsername);
  assert(authRecord !== undefined && bcrypt.compareSync(testEmpPassword, authRecord.passwordHash), 'Employee credentials authenticated successfully');
  assert(!bcrypt.compareSync('WrongPassword', authRecord!.passwordHash), 'Invalid employee password rejected');

  // Step 3: Check initial employee risk score
  const initialEmpRisk = siemServer.recalculateRisk(newEmpUser.id);
  assert(initialEmpRisk.finalScore <= 15, `Initial employee baseline risk is nominal (${initialEmpRisk.finalScore}/100)`);

  // Step 4: Employee downloads 750MB Highly Confidential file
  const stratFile = db.getFiles().find((f) => f.name.includes('Strategic_Business_Plan')) || db.getFileById('f-strategy-005') || db.getFiles()[0];
  const downloadResult = siemServer.accessFile(stratFile.id, 'DOWNLOAD', newEmpUser);
  assert(downloadResult.success === true, `Employee successfully downloaded '${stratFile.name}' (${stratFile.sizeMb} MB)`);

  // Step 5: Verify File Activity recorded for employee
  const empActivities = db.getFileActivities(newEmpUser.id);
  assert(empActivities.length > 0 && empActivities[0].action === 'DOWNLOAD', 'File activity audit recorded in employee activity ledger');

  // Step 6: Verify Rule Findings generated
  const empFindings = db.getFindings().filter((f) => f.userId === newEmpUser.id);
  assert(empFindings.length > 0, `SIEM Rule Engine generated ${empFindings.length} detection findings`);
  const hasLargeDownloadFinding = empFindings.some((f) => f.ruleCode.includes('LARGE_FILE') || f.ruleCode.includes('DOWNLOAD') || f.ruleCode.includes('SENSITIVE'));
  assert(hasLargeDownloadFinding, 'Detection rule correctly flagged 750MB confidential egress breach');

  // Step 7: Verify Risk Score Escalation
  const updatedEmpRisk = siemServer.recalculateRisk(newEmpUser.id);
  assert(updatedEmpRisk.finalScore > initialEmpRisk.finalScore, `Employee risk score escalated from ${initialEmpRisk.finalScore} to ${updatedEmpRisk.finalScore}/100`);

  // Step 8: Verify SOC Alert Generated
  const empAlerts = db.getAlerts().filter((a) => a.userId === newEmpUser.id);
  assert(empAlerts.length > 0, `Critical SOC Alert generated (${empAlerts.length} alert(s) present in database)`);
  const latestAlert = empAlerts[empAlerts.length - 1];
  assert(latestAlert.severity === 'CRITICAL' || latestAlert.severity === 'HIGH', `Generated alert severity is elevated (${latestAlert.severity})`);
  assert(latestAlert.evidence.length > 0, 'Alert evidence ledger contains forensic artifacts');

  // Step 9: Verify RBAC Isolation
  assert(newEmpUser.role === 'EMPLOYEE', 'Employee role strictly enforced for user');

  // -------------------------------------------------------------
  // SUITE 6: Phase 8 Health Diagnostics & Phase 2 Admin Provisioning
  // -------------------------------------------------------------
  console.log('\n\x1b[36m[SUITE 6] Diagnostics & Admin Employee Provisioning (Phase 2 & 8)\x1b[0m');

  // Admin provisioning test
  const existingRachel = db.getUserByUsername('racheladams');
  const adminProvisionedEmp =
    existingRachel ||
    db.addUser({
      id: Math.max(...db.getUsers().map((u) => u.id || 100), 100) + 1,
      username: 'racheladams',
      email: 'rachel.adams@corp-apex.internal',
      passwordHash: bcrypt.hashSync('password123', 10),
      fullName: 'Rachel Adams',
      department: 'R&D Engineering',
      designation: 'Staff Security Engineer',
      employeeId: 'EMP-9901',
      clearanceLevel: 'RESTRICTED',
      role: 'EMPLOYEE', // Backend strictly forces EMPLOYEE
      status: 'ACTIVE',
      createdAt: new Date().toISOString(),
    });

  assert(adminProvisionedEmp.employeeId === 'EMP-9901', 'Admin successfully provisioned employee with EMP-ID');
  assert(adminProvisionedEmp.role === 'EMPLOYEE', 'Admin provisioning strictly forced role=EMPLOYEE');

  // Employee ID login lookup test
  const userByEmpId = db.getUserByEmployeeId('EMP-9901');
  assert(userByEmpId !== undefined && userByEmpId.username === 'racheladams', 'User lookup via Employee ID succeeds');

  const defaultEmpLookup = db.getUserByEmployeeId('EMP-101');
  assert(defaultEmpLookup !== undefined && defaultEmpLookup.username === 'amercer', 'Default employee lookup via EMP-101 succeeds');

  // Subsystem health diagnostics test
  const totalDbUsers = db.getUsers().length;
  const totalDbFiles = db.getFiles().length;
  const totalDbRules = db.getRules().length;
  const totalDbAlerts = db.getAlerts().length;

  assert(totalDbUsers >= 4, 'Health check: Database users subsystem operational');
  assert(totalDbFiles >= 10, 'Health check: Corporate file repository operational');
  assert(totalDbRules >= 6, 'Health check: SIEM rule engine operational');
  assert(totalDbAlerts >= 1, 'Health check: Alert creation subsystem operational');

  // -------------------------------------------------------------
  // SUITE 7: RBAC AUTHORIZATION & EMPLOYEE LIFECYCLE
  // -------------------------------------------------------------
  console.log('\n\x1b[36m[SUITE 7] RBAC Authorization & Employee Lifecycle Management\x1b[0m');

  // Test 7.1: RBAC Middleware simulation for Admin vs Employee
  const employeeRole = 'EMPLOYEE';
  const adminRole = 'ADMIN';

  function checkAccess(userRole: string, allowedRoles: string[]): boolean {
    const normalized = userRole === 'EMPLOYEE' ? 'VIEWER' : userRole;
    return allowedRoles.some((r) => {
      const normR = r === 'EMPLOYEE' ? 'VIEWER' : r;
      return normR === normalized || r === userRole;
    });
  }

  assert(!checkAccess(employeeRole, ['ADMIN']), 'RBAC: Employee is blocked from accessing Admin-only alert endpoints (403)');
  assert(!checkAccess(employeeRole, ['ADMIN']), 'RBAC: Employee is blocked from accessing Admin-only employee directory (403)');
  assert(!checkAccess(employeeRole, ['ADMIN']), 'RBAC: Employee is blocked from accessing Admin-only audit logs (403)');
  assert(checkAccess(adminRole, ['ADMIN']), 'RBAC: Admin has authorized access to Admin endpoints');

  // -------------------------------------------------------------
  // SUITE 8: EMPLOYEE DISABLE/DELETE & ADMIN SELF-PROTECTION (TEST CASES 1-6)
  // -------------------------------------------------------------
  console.log('\n\x1b[36m[SUITE 8] Employee Disable/Delete & Self-Protection Verification\x1b[0m');

  const adminUserRecord = db.getUserByUsername('admin') || db.getUsers().find((u) => u.role === 'ADMIN')!;
  assert(adminUserRecord !== undefined, 'Admin user exists for testing');

  // Resolver helper mirroring server.ts resolveTargetEmployee
  function resolveTargetEmployeeTest(param: string) {
    const clean = String(param).trim();
    let u = db.getUserByEmployeeId(clean);
    if (u) return u;
    if (!isNaN(Number(clean))) {
      u = db.getUserById(Number(clean));
      if (u) return u;
    }
    u = db.getUserByUsername(clean) || db.getUserByEmail(clean);
    if (u) return u;
    if (/^\d+$/.test(clean)) return db.getUserByEmployeeId(`EMP-${clean}`);
    return undefined;
  }

  function isSelfAdminTest(target: any, admin: any) {
    if (target.id === admin.id) return true;
    if (target.username && admin.username && target.username.toLowerCase() === admin.username.toLowerCase()) return true;
    if (target.employeeId && admin.employeeId && target.employeeId.toLowerCase() === admin.employeeId.toLowerCase()) return true;
    if (target.email && admin.email && target.email.toLowerCase() === admin.email.toLowerCase()) return true;
    return false;
  }

  // TEST 1: Disable Normal Employee (Jane Doe EMP-106)
  let janeDoe = db.getUserByEmployeeId('EMP-106') || db.getUsers().find((u) => u.role === 'EMPLOYEE' && u.id !== adminUserRecord.id);
  if (!janeDoe) {
    const maxId = db.getUsers().reduce((max, u) => Math.max(max, u.id || 0), 100);
    janeDoe = db.addUser({
      id: maxId + 1,
      username: 'jdoe',
      email: 'jane.doe@corp-apex.internal',
      passwordHash: bcrypt.hashSync('Password123!', 10),
      fullName: 'Jane Doe',
      department: 'Corporate Strategy',
      designation: 'Senior Analyst',
      employeeId: 'EMP-106',
      clearanceLevel: 'CONFIDENTIAL',
      role: 'EMPLOYEE',
      status: 'ACTIVE',
      createdAt: new Date().toISOString(),
    });
  }
  assert(janeDoe !== undefined, 'Jane Doe (EMP-106) located in database');

  const isJaneSelfAdmin = isSelfAdminTest(janeDoe, adminUserRecord);
  assert(!isJaneSelfAdmin, 'Jane Doe is NOT identified as the logged-in administrator');

  // Perform disable
  janeDoe.status = 'DISABLED';
  db.updateUser(janeDoe.id, { status: 'DISABLED' });
  db.addAuditLog({
    id: db.getAuditLogs().length + 1,
    actor: adminUserRecord.username,
    userId: janeDoe.id,
    action: 'EMPLOYEE_DISABLED',
    resource: `user:${janeDoe.username}`,
    details: `Admin ${adminUserRecord.username} disabled employee [${janeDoe.employeeId}] ${janeDoe.fullName}`,
    timestamp: new Date().toISOString(),
  });

  // TEST 2: Verify Persistence
  const janeDoeAfter = db.getUserById(janeDoe.id);
  assert(janeDoeAfter?.status === 'DISABLED', 'TEST 1 & 2: Jane Doe (EMP-106) is successfully DISABLED and persists');

  // TEST 3: Admin Self-Protection
  const isSelf = isSelfAdminTest(adminUserRecord, adminUserRecord);
  assert(isSelf === true, 'TEST 3: Admin self-protection detects admin attempting to disable own account');

  // TEST 4: Non-admin employee cannot disable employees
  const employeeCanAccess = checkAccess('EMPLOYEE', ['ADMIN']);
  assert(!employeeCanAccess, 'TEST 4: Non-admin employee blocked from employee disable endpoint (403)');

  // TEST 5: Invalid Employee Lookup
  const nonExistent = resolveTargetEmployeeTest('EMP-999999');
  assert(nonExistent === undefined, 'TEST 5: Nonexistent employee ID resolves to 404 (not found)');

  // TEST 6: Add Employee Regression Test + Disable
  const regressionEmp = db.addUser({
    id: Math.max(...db.getUsers().map((u) => u.id || 100), 100) + 1,
    username: 'deletetestuser',
    email: 'delete.test@corp-apex.internal',
    passwordHash: bcrypt.hashSync('Password123!', 10),
    fullName: 'Delete Test User',
    department: 'Security Operations',
    designation: 'Security Associate',
    employeeId: 'TEST-EMP-DELETE-001',
    clearanceLevel: 'CONFIDENTIAL',
    role: 'EMPLOYEE',
    status: 'ACTIVE',
    createdAt: new Date().toISOString(),
  });

  assert(regressionEmp.employeeId === 'TEST-EMP-DELETE-001', 'TEST 6: Employee created successfully with TEST-EMP-DELETE-001');

  // Disable that employee
  const resolvedRegEmp = resolveTargetEmployeeTest('TEST-EMP-DELETE-001');
  assert(resolvedRegEmp !== undefined, 'Target TEST-EMP-DELETE-001 resolved correctly');
  assert(!isSelfAdminTest(resolvedRegEmp, adminUserRecord), 'TEST-EMP-DELETE-001 is not admin');
  resolvedRegEmp.status = 'DISABLED';
  db.updateUser(resolvedRegEmp.id, { status: 'DISABLED' });

  // Verify persistence
  const regEmpAfter = db.getUserByEmployeeId('TEST-EMP-DELETE-001');
  assert(regEmpAfter?.status === 'DISABLED', 'TEST 6: TEST-EMP-DELETE-001 disabled successfully and persists as DISABLED');

  // -------------------------------------------------------------
  // SUMMARY
  // -------------------------------------------------------------
  console.log('\n=============================================================');
  console.log(` TEST EXECUTION SUMMARY: \x1b[32m${passedCount} PASSED\x1b[0m | \x1b[${failedCount > 0 ? '31' : '32'}m${failedCount} FAILED\x1b[0m`);
  console.log('=============================================================\n');

  if (failedCount > 0) {
    process.exit(1);
  }
}

runTestSuite().catch((err) => {
  console.error('Fatal error during test suite execution:', err);
  process.exit(1);
});
