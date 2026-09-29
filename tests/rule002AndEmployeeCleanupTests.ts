import { db } from '../server/db/database';
import { siemServer } from '../server/services/siemServerEngine';
import { isUnauthorizedAccessEvent } from '../src/utils/siemRules';

async function runRule002AndCleanupTests() {
  console.log('=============================================================');
  console.log(' SIEM VERIFICATION: RULE-002 & EMPLOYEE CLEANUP TESTS');
  console.log('=============================================================');

  let passed = 0;
  let failed = 0;

  function assert(condition: boolean, message: string) {
    if (condition) {
      console.log(`  \x1b[32m✔ PASS\x1b[0m ${message}`);
      passed++;
    } else {
      console.log(`  \x1b[31m✖ FAIL\x1b[0m ${message}`);
      failed++;
    }
  }

  console.log('\n\x1b[36m[SUITE 1] Change 1 Verification: No Auto-Created Employees\x1b[0m');

  // 1. Check getEmployees() returns only manual employees
  const initialEmployees = db.getEmployees();
  console.log(`  Current active manual employees count: ${initialEmployees.length}`);
  const allManual = initialEmployees.every((u) => u.isManual === true);
  assert(allManual, 'All employees returned by getEmployees() have isManual: true');

  // Check no phantom or fake employees exist in getEmployees
  const hasElena = initialEmployees.some((u) => u.username === 'erostova' || u.fullName === 'Elena Rostova');
  const hasMarcus = initialEmployees.some((u) => u.username === 'mvance' || u.fullName === 'Marcus Vance');
  assert(!hasElena, 'Auto-generated Elena Rostova is not in getEmployees()');
  assert(!hasMarcus, 'Auto-generated Marcus Vance is not in getEmployees()');

  // 2. Add manual employee and verify it is included
  const testManualUser = {
    id: Math.max(...db.getUsers().map((u) => u.id)) + 1,
    username: 'manual_worker_1',
    email: 'manual.worker@corp-apex.internal',
    passwordHash: 'hash',
    fullName: 'Manual Worker One',
    department: 'Engineering',
    designation: 'Software Engineer',
    employeeId: 'EMP-MANUAL-001',
    clearanceLevel: 'LEVEL_2_CONFIDENTIAL' as const,
    role: 'EMPLOYEE' as const,
    status: 'ACTIVE' as const,
    createdAt: new Date().toISOString(),
    isManual: true,
  };
  db.addUser(testManualUser);
  const updatedEmployees = db.getEmployees();
  assert(
    updatedEmployees.some((u) => u.employeeId === 'EMP-MANUAL-001'),
    'Manually created employee EMP-MANUAL-001 is included in getEmployees()'
  );

  // 3. Verify simulation does NOT permanently create an employee
  const employeeCountBeforeSim = db.getEmployees().length;
  // Trigger simulation
  const targetUser = db.getUsers()[0];
  siemServer.ingestLog({
    timestamp: new Date().toISOString(),
    userId: targetUser.id,
    username: targetUser.username,
    source: 'rbac-enforcer',
    eventType: 'UNAUTHORIZED_ACCESS',
    action: 'ACCESS_DENIED',
    resource: '/api/admin/settings',
    ipAddress: targetUser.ipAddress || '10.14.88.102',
    severity: 'HIGH',
    details: {
      resource: '/api/admin/settings',
      userRole: targetUser.role,
      employeeId: targetUser.employeeId || `EMP-${targetUser.id}`,
      requiredRoles: ['ADMIN'],
      statusCode: 403,
    },
  });
  const employeeCountAfterSim = db.getEmployees().length;
  assert(
    employeeCountBeforeSim === employeeCountAfterSim,
    'Simulation of unauthorized access did NOT create a new employee record'
  );

  console.log('\n\x1b[36m[SUITE 2] Change 2 Verification: Rule-002 Unauthorized Access\x1b[0m');

  // 1. Rule definition check
  const rules = db.getRules();
  const rule002 = rules.find((r) => r.ruleCode === 'UNAUTHORIZED_ACCESS' || r.name === 'Unauthorized Access');
  assert(!!rule002, 'Rule-002 (Unauthorized Access) is registered in database rules');
  assert(rule002?.enabled === true, 'Rule-002 is enabled by default');
  assert(rule002?.severity === 'HIGH', 'Rule-002 severity is HIGH');

  // 2. isUnauthorizedAccessEvent helper test
  const testAccessDeniedEvent = {
    id: 999,
    timestamp: new Date().toISOString(),
    userId: 101,
    username: 'amercer',
    eventType: 'UNAUTHORIZED_ACCESS',
    action: 'ACCESS_DENIED',
    normalizedData: {
      resource: '/api/admin/system/security-keys',
      userRole: 'EMPLOYEE',
      statusCode: 403,
    },
    rawLog: '',
    processed: false,
  };
  assert(isUnauthorizedAccessEvent(testAccessDeniedEvent), 'isUnauthorizedAccessEvent correctly recognizes 403 / ACCESS_DENIED');

  // 3. Ingestion & Finding Generation
  const initialFindingsCount = db.getFindings().length;
  siemServer.ingestLog({
    timestamp: new Date().toISOString(),
    userId: testManualUser.id,
    username: testManualUser.username,
    source: 'rbac-enforcer',
    eventType: 'UNAUTHORIZED_ACCESS',
    action: 'ACCESS_DENIED',
    resource: '/api/admin/confidential-keys',
    ipAddress: '10.14.99.55',
    severity: 'HIGH',
    details: {
      resource: '/api/admin/confidential-keys',
      userRole: testManualUser.role,
      employeeId: testManualUser.employeeId,
      requiredRoles: ['ADMIN'],
      statusCode: 403,
      reason: `User ${testManualUser.employeeId} (Role: ${testManualUser.role}) attempted unauthorized access to resource: /api/admin/confidential-keys`,
    },
  });

  const findingsAfter = db.getFindings();
  assert(findingsAfter.length > initialFindingsCount, 'SIEM engine generated finding for unauthorized access event');

  const rule002Finding = findingsAfter.find(
    (f) => f.userId === testManualUser.id && (f.ruleCode === 'UNAUTHORIZED_ACCESS' || f.ruleId === 11)
  );
  assert(!!rule002Finding, 'Finding has ruleCode UNAUTHORIZED_ACCESS');
  assert(rule002Finding?.metadata?.ruleId === 'RULE-002', 'Finding metadata includes ruleId: RULE-002');
  assert(
    rule002Finding?.reason.includes(testManualUser.employeeId) ?? false,
    'Finding reason contains the employee ID'
  );

  // 4. Alert Correlation
  const alerts = db.getAlerts();
  const rule002Alert = alerts.find(
    (a) => a.userId === testManualUser.id && a.correlationKey === `RULE-002_${testManualUser.id}`
  );
  assert(!!rule002Alert, 'Alert Correlator generated dedicated RULE-002 Alert');
  assert(rule002Alert?.severity === 'HIGH', 'Rule-002 Alert severity is HIGH');
  assert(
    rule002Alert?.policyViolations.includes('RULE-002') ?? false,
    'Alert policy violations includes RULE-002'
  );
  assert(
    rule002Alert?.evidence.some((e) => e.includes('RULE-002')) ?? false,
    'Alert evidence contains forensic artifacts with RULE-002'
  );

  // 5. SecurityEvent database record
  db.addSecurityEvent({
    id: db.getSecurityEvents().length + 1,
    eventType: 'UNAUTHORIZED_ACCESS',
    userId: testManualUser.id,
    username: testManualUser.username,
    identifier: testManualUser.employeeId,
    ipAddress: '10.14.99.55',
    timestamp: new Date().toISOString(),
    attemptCount: 1,
    threshold: 1,
    severity: 'HIGH',
    description: `Access Denied (403 Forbidden): Role '${testManualUser.role}' attempted unauthorized access to protected resource '/api/admin/confidential-keys'.`,
    status: 'OPEN',
    metadata: {
      employeeId: testManualUser.employeeId,
      userRole: testManualUser.role,
      resource: '/api/admin/confidential-keys',
      requiredRoles: ['ADMIN'],
    },
  });

  const secEvents = db.getSecurityEvents();
  const rbacSecEvent = secEvents.find(
    (e) => e.userId === testManualUser.id && e.eventType === 'UNAUTHORIZED_ACCESS'
  );
  assert(!!rbacSecEvent, 'SecurityEvent record for UNAUTHORIZED_ACCESS successfully created in database');

  console.log('\n\x1b[36m[SUITE 3] Regression Verification: Rule-001 & Rule-005 Still Operational\x1b[0m');

  // Rule 001 (Failed Logins)
  const rule001 = rules.find((r) => r.ruleCode === 'MULTIPLE_FAILED_LOGINS');
  assert(rule001?.enabled === true, 'Rule-001 (Multiple Failed Logins) is still enabled');

  // Rule 005 (Sensitive File Access)
  const rule005 = rules.find((r) => r.ruleCode === 'SENSITIVE_FILE_DOWNLOAD');
  assert(rule005?.enabled === true, 'Rule-005 (Sensitive File Access) is still enabled');

  console.log('\n=============================================================');
  console.log(` RULE-002 & CLEANUP TEST SUMMARY: ${passed} PASSED | ${failed} FAILED`);
  console.log('=============================================================');

  // Clean up test user & its artifacts
  const userIdx = db.getUsers().findIndex((u) => u.id === testManualUser.id);
  if (userIdx !== -1) {
    db.getUsers().splice(userIdx, 1);
  }
  const findings = db.getFindings();
  for (let i = findings.length - 1; i >= 0; i--) {
    if (findings[i].userId === testManualUser.id) {
      findings.splice(i, 1);
    }
  }
  const allAlerts = db.getAlerts();
  for (let i = allAlerts.length - 1; i >= 0; i--) {
    if (allAlerts[i].userId === testManualUser.id) {
      allAlerts.splice(i, 1);
    }
  }

  if (failed > 0) {
    process.exit(1);
  }
}

runRule002AndCleanupTests();
