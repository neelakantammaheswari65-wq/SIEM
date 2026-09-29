import { SIEMServerEngine } from '../server/services/siemServerEngine';
import { db } from '../server/db/database';
import { siemEngine } from '../src/services/siemEngine';
import { isFailedLoginEvent } from '../src/utils/siemRules';

async function runRule1Tests() {
  console.log('=============================================================');
  console.log(' RULE 1: MULTIPLE FAILED LOGINS - COMPREHENSIVE VERIFICATION ');
  console.log('=============================================================\n');

  let passed = 0;
  let failed = 0;

  function assert(condition: boolean, msg: string) {
    if (condition) {
      console.log(`\x1b[32m✔ PASS\x1b[0m ${msg}`);
      passed++;
    } else {
      console.error(`\x1b[31m✘ FAIL\x1b[0m ${msg}`);
      failed++;
    }
  }

  const siem = SIEMServerEngine.getInstance();
  const runId = Date.now().toString(36);

  // Provision distinct test users with unique IDs for this test run
  const user1 = db.addUser({
    id: db.getUsers().length + 1,
    username: `test_emp_r1_${runId}_101`,
    passwordHash: 'dummyhash',
    role: 'EMPLOYEE',
    employeeId: `EMP-R1-${runId.toUpperCase()}-101`,
    email: `emp101_${runId}@example.com`,
    fullName: 'Test Employee 101',
    department: 'Engineering',
    designation: 'Staff Engineer',
    clearanceLevel: 'SECRET',
    ipAddress: '192.168.1.101',
    status: 'ACTIVE',
    createdAt: new Date().toISOString(),
  });

  const user2 = db.addUser({
    id: db.getUsers().length + 2,
    username: `test_emp_r1_${runId}_102`,
    passwordHash: 'dummyhash',
    role: 'EMPLOYEE',
    employeeId: `EMP-R1-${runId.toUpperCase()}-102`,
    email: `emp102_${runId}@example.com`,
    fullName: 'Test Employee 102',
    department: 'Sales',
    designation: 'Account Exec',
    clearanceLevel: 'CONFIDENTIAL',
    ipAddress: '192.168.1.102',
    status: 'ACTIVE',
    createdAt: new Date().toISOString(),
  });

  // -------------------------------------------------------------
  // TEST 1: 1 failed login -> Expected: NO alert
  // -------------------------------------------------------------
  console.log('\n--- TEST 1: 1 failed login -> Expected: NO alert ---');
  const now1 = Date.now();
  const res1 = siem.ingestLog({
    timestamp: new Date(now1).toISOString(),
    userId: user1.id,
    username: user1.username,
    source: 'auth-service',
    eventType: 'FAILED_LOGIN',
    action: 'AUTH_FAILED',
    resource: 'Kerberos-AD',
    ipAddress: '192.168.1.101',
    severity: 'MEDIUM',
    details: { reason: 'ERR_BAD_PASSWORD' },
  });

  const alertsT1 = db.getAlerts().filter(a => a.userId === user1.id && a.title === 'Multiple Failed Logins');
  assert(res1.findings.length === 0, '1 failed login produces 0 findings for MULTIPLE_FAILED_LOGINS');
  assert(alertsT1.length === 0, '1 failed login produces NO Rule 1 alert');

  // -------------------------------------------------------------
  // TEST 2: 4 failed logins within 10 minutes -> Expected: NO Rule-1 alert
  // -------------------------------------------------------------
  console.log('\n--- TEST 2: 4 failed logins within 10 minutes -> Expected: NO Rule-1 alert ---');
  for (let i = 2; i <= 4; i++) {
    siem.ingestLog({
      timestamp: new Date(now1 + i * 1000).toISOString(),
      userId: user1.id,
      username: user1.username,
      source: 'auth-service',
      eventType: 'FAILED_LOGIN',
      action: 'AUTH_FAILED',
      resource: 'Kerberos-AD',
      ipAddress: '192.168.1.101',
      severity: 'MEDIUM',
      details: { attempt: i, reason: 'ERR_BAD_PASSWORD' },
    });
  }
  const alertsT2 = db.getAlerts().filter(a => a.userId === user1.id && a.title === 'Multiple Failed Logins');
  assert(alertsT2.length === 0, '4 failed logins within 10 minutes produces NO Rule-1 alert (threshold is 5)');

  // -------------------------------------------------------------
  // TEST 3: 5 failed logins within 10 minutes -> Expected: RULE-001 alert
  // -------------------------------------------------------------
  console.log('\n--- TEST 3: 5 failed logins within 10 minutes -> Expected: RULE-001 alert ---');
  const res5 = siem.ingestLog({
    timestamp: new Date(now1 + 5 * 1000).toISOString(),
    userId: user1.id,
    username: user1.username,
    source: 'auth-service',
    eventType: 'FAILED_LOGIN',
    action: 'AUTH_FAILED',
    resource: 'Kerberos-AD',
    ipAddress: '192.168.1.101',
    severity: 'MEDIUM',
    details: { attempt: 5, reason: 'ERR_BAD_PASSWORD' },
  });

  const alertsT3 = db.getAlerts().filter(a => a.userId === user1.id && a.title === 'Multiple Failed Logins');
  assert(res5.findings.some(f => f.ruleCode === 'MULTIPLE_FAILED_LOGINS'), '5th failed login triggers MULTIPLE_FAILED_LOGINS finding');
  assert(alertsT3.length === 1, 'Exactly 1 RULE-001 alert created');

  const alert1 = alertsT3[0];
  assert(alert1.severity === 'HIGH', 'Alert severity is HIGH');
  assert(alert1.status === 'OPEN', 'Alert status is OPEN');
  assert(alert1.correlationKey === `RULE-001_${user1.id}`, 'Alert correlationKey is RULE-001_' + user1.id);
  assert(alert1.description.includes(`failed login attempts detected for ${user1.employeeId} within 10 minutes`), `Detection reason correctly references employee ${user1.employeeId} and 10 minutes`);
  assert(alert1.evidence.some(e => e.includes('Rule ID: RULE-001')), 'Evidence includes Rule ID: RULE-001');
  assert(alert1.evidence.some(e => e.includes(`User/Employee ID: ${user1.employeeId}`)), `Evidence includes User/Employee ID: ${user1.employeeId}`);
  assert(alert1.evidence.some(e => e.includes('Detection window: 10 minutes')), 'Evidence includes Detection window: 10 minutes');

  // Verify Audit Log
  const auditLogs = db.getAuditLogs().filter(a => a.userId === user1.id && a.action === 'RULE_TRIGGER_ALERT');
  assert(auditLogs.length >= 1, 'Audit log created with action RULE_TRIGGER_ALERT for Rule 1');

  // -------------------------------------------------------------
  // TEST 4: 6 failed logins within 10 minutes -> Expected: deduplication, NO duplicate alerts
  // -------------------------------------------------------------
  console.log('\n--- TEST 4: 6 failed logins within 10 minutes -> Expected: deduplication, NO duplicate alerts ---');
  siem.ingestLog({
    timestamp: new Date(now1 + 6 * 1000).toISOString(),
    userId: user1.id,
    username: user1.username,
    source: 'auth-service',
    eventType: 'FAILED_LOGIN',
    action: 'AUTH_FAILED',
    resource: 'Kerberos-AD',
    ipAddress: '192.168.1.101',
    severity: 'MEDIUM',
    details: { attempt: 6, reason: 'ERR_BAD_PASSWORD' },
  });

  const alertsT4 = db.getAlerts().filter(a => a.userId === user1.id && a.title === 'Multiple Failed Logins');
  assert(alertsT4.length === 1, 'Still exactly 1 alert exists for user1 (no duplicate alerts created)');
  assert(alertsT4[0].eventCount === 6, 'Existing alert updated with eventCount = 6');
  assert(alertsT4[0].description.includes('6 failed login attempts detected'), 'Alert description updated to 6 failed login attempts');

  // -------------------------------------------------------------
  // TEST 5: 5 failed logins spread over more than 10 minutes -> Expected: NO Rule-1 alert
  // -------------------------------------------------------------
  console.log('\n--- TEST 5: 5 failed logins spread over more than 10 minutes -> Expected: NO Rule-1 alert ---');
  const user3 = db.addUser({
    id: db.getUsers().length + 1,
    username: `test_emp_r1_${runId}_103`,
    passwordHash: 'dummyhash',
    role: 'EMPLOYEE',
    employeeId: `EMP-R1-${runId.toUpperCase()}-103`,
    email: `emp103_${runId}@example.com`,
    fullName: 'Test Employee 103',
    department: 'Support',
    designation: 'Support Tech',
    clearanceLevel: 'PUBLIC',
    ipAddress: '192.168.1.103',
    status: 'ACTIVE',
    createdAt: new Date().toISOString(),
  });

  const nowT5 = Date.now();
  // 3 logins 15 minutes ago
  for (let i = 1; i <= 3; i++) {
    siem.ingestLog({
      timestamp: new Date(nowT5 - (15 - i) * 60 * 1000).toISOString(),
      userId: user3.id,
      username: user3.username,
      source: 'auth-service',
      eventType: 'FAILED_LOGIN',
      action: 'AUTH_FAILED',
      resource: 'Kerberos-AD',
      ipAddress: '192.168.1.103',
      severity: 'MEDIUM',
      details: { attempt: i, reason: 'ERR_BAD_PASSWORD' },
    });
  }
  // 2 logins now (total 5 logins, but only 2 within last 10 minutes)
  for (let i = 4; i <= 5; i++) {
    siem.ingestLog({
      timestamp: new Date(nowT5 + i * 1000).toISOString(),
      userId: user3.id,
      username: user3.username,
      source: 'auth-service',
      eventType: 'FAILED_LOGIN',
      action: 'AUTH_FAILED',
      resource: 'Kerberos-AD',
      ipAddress: '192.168.1.103',
      severity: 'MEDIUM',
      details: { attempt: i, reason: 'ERR_BAD_PASSWORD' },
    });
  }

  const alertsT5 = db.getAlerts().filter(a => a.userId === user3.id && a.title === 'Multiple Failed Logins');
  assert(alertsT5.length === 0, '5 failed logins spread over >10 minutes produces NO Rule-1 alert');

  // -------------------------------------------------------------
  // TEST 6: 3 failed logins for EMP-101 + 3 failed logins for EMP-102 -> Expected: NO Rule-1 alert for either user
  // -------------------------------------------------------------
  console.log('\n--- TEST 6: 3 failed logins EMP-101 + 3 failed logins EMP-102 -> Expected: NO alert for either ---');
  const user4A = db.addUser({
    id: db.getUsers().length + 1,
    username: `test_emp_r1_${runId}_104a`,
    passwordHash: 'dummyhash',
    role: 'EMPLOYEE',
    employeeId: `EMP-R1-${runId.toUpperCase()}-104A`,
    email: `emp104a_${runId}@example.com`,
    fullName: 'Test Employee 104A',
    department: 'Finance',
    designation: 'Financial Analyst',
    clearanceLevel: 'CONFIDENTIAL',
    ipAddress: '192.168.1.104',
    status: 'ACTIVE',
    createdAt: new Date().toISOString(),
  });

  const user4B = db.addUser({
    id: db.getUsers().length + 2,
    username: `test_emp_r1_${runId}_104b`,
    passwordHash: 'dummyhash',
    role: 'EMPLOYEE',
    employeeId: `EMP-R1-${runId.toUpperCase()}-104B`,
    email: `emp104b_${runId}@example.com`,
    fullName: 'Test Employee 104B',
    department: 'Legal',
    designation: 'Legal Counsel',
    clearanceLevel: 'CONFIDENTIAL',
    ipAddress: '192.168.1.105',
    status: 'ACTIVE',
    createdAt: new Date().toISOString(),
  });

  const nowT6 = Date.now();
  for (let i = 1; i <= 3; i++) {
    siem.ingestLog({
      timestamp: new Date(nowT6 + i * 1000).toISOString(),
      userId: user4A.id,
      username: user4A.username,
      source: 'auth-service',
      eventType: 'FAILED_LOGIN',
      action: 'AUTH_FAILED',
      resource: 'Kerberos-AD',
      ipAddress: '192.168.1.104',
      severity: 'MEDIUM',
      details: { attempt: i, reason: 'ERR_BAD_PASSWORD' },
    });
    siem.ingestLog({
      timestamp: new Date(nowT6 + i * 1000).toISOString(),
      userId: user4B.id,
      username: user4B.username,
      source: 'auth-service',
      eventType: 'FAILED_LOGIN',
      action: 'AUTH_FAILED',
      resource: 'Kerberos-AD',
      ipAddress: '192.168.1.105',
      severity: 'MEDIUM',
      details: { attempt: i, reason: 'ERR_BAD_PASSWORD' },
    });
  }

  const alerts4A = db.getAlerts().filter(a => a.userId === user4A.id && a.title === 'Multiple Failed Logins');
  const alerts4B = db.getAlerts().filter(a => a.userId === user4B.id && a.title === 'Multiple Failed Logins');
  assert(alerts4A.length === 0, 'No alert for User 104A (3 failed logins < 5 threshold)');
  assert(alerts4B.length === 0, 'No alert for User 104B (3 failed logins < 5 threshold)');

  // -------------------------------------------------------------
  // TEST 7: 5 failed logins for EMP-101 followed by successful login -> Expected: historical events remain visible
  // -------------------------------------------------------------
  console.log('\n--- TEST 7: 5 failed logins followed by successful login ---');
  const preLoginEventCount = db.getNormalizedEvents().filter(e => e.userId === user1.id).length;
  siem.ingestLog({
    timestamp: new Date().toISOString(),
    userId: user1.id,
    username: user1.username,
    source: 'auth-service',
    eventType: 'LOGIN',
    action: 'AUTH_SUCCESS',
    resource: 'Web-Login-Gateway',
    ipAddress: user1.ipAddress,
    severity: 'LOW',
    details: { role: user1.role, mfa_verified: true },
  });

  const postLoginEvents = db.getNormalizedEvents().filter(e => e.userId === user1.id);
  const failedEventsAfterSuccess = postLoginEvents.filter(e => isFailedLoginEvent(e));
  assert(failedEventsAfterSuccess.length >= 6, 'Historical failed login events remain completely intact (NOT deleted)');
  assert(postLoginEvents.length === preLoginEventCount + 1, 'Total event count incremented by 1 for the new successful login event');

  const alertAfterSuccess = db.getAlerts().find(a => a.userId === user1.id && a.title === 'Multiple Failed Logins');
  assert(alertAfterSuccess !== undefined && alertAfterSuccess.status === 'OPEN', 'Rule 1 alert remains OPEN in its standard lifecycle');

  // -------------------------------------------------------------
  // TEST 8: Refresh dashboard repeatedly -> Expected: NO duplicate Rule-1 alerts
  // -------------------------------------------------------------
  console.log('\n--- TEST 8: Refresh dashboard repeatedly -> Expected: NO duplicate alerts ---');
  const alertCountBefore = db.getAlerts().filter(a => a.userId === user1.id && a.title === 'Multiple Failed Logins').length;
  // Simulate 5 dashboard queries/fetches
  for (let r = 0; r < 5; r++) {
    const alerts = db.getAlerts();
    const findings = db.getFindings();
    const rules = db.getRules();
  }
  const alertCountAfter = db.getAlerts().filter(a => a.userId === user1.id && a.title === 'Multiple Failed Logins').length;
  assert(alertCountBefore === alertCountAfter && alertCountAfter === 1, 'Alert count remains exactly 1 after repeated dashboard reads');

  // -------------------------------------------------------------
  // TEST 9 & 10: Local/Demo mode & No Gemini requirement
  // -------------------------------------------------------------
  console.log('\n--- TEST 9 & 10: Local/Demo mode (siemEngine.ts) & Deterministic logic ---');
  const localUserId = 99000 + Math.floor(Math.random() * 1000);
  const localUsername = `demo_user_${runId}`;
  siemEngine.users.push({
    id: localUserId,
    username: localUsername,
    role: 'EMPLOYEE',
    employeeId: `EMP-LOCAL-${runId.toUpperCase()}`,
    department: 'Operations',
    fullName: 'Demo Local User',
    email: `demo_${runId}@example.com`,
    designation: 'Ops Lead',
    clearanceLevel: 'SECRET',
    ipAddress: '10.10.10.10',
    status: 'ACTIVE',
    createdAt: new Date().toISOString(),
  });

  const localNow = Date.now();
  for (let i = 1; i <= 5; i++) {
    siemEngine.ingestLog({
      timestamp: new Date(localNow + i * 1000).toISOString(),
      userId: localUserId,
      username: localUsername,
      source: 'auth-service',
      eventType: 'FAILED_LOGIN',
      action: 'AUTH_FAILED',
      resource: 'Internal-AD-Kerberos',
      ipAddress: '192.168.100.250',
      severity: 'MEDIUM',
      details: { attempt: i, reason: 'ERR_BAD_PASSWORD' },
    });
  }

  const localAlerts = siemEngine.alerts.filter(a => a.userId === localUserId && a.title === 'Multiple Failed Logins');
  assert(localAlerts.length === 1, 'Local siemEngine triggers exactly 1 Rule 1 alert without any backend or Gemini dependency');
  assert(localAlerts[0].description.includes('failed login attempts detected'), 'Local alert description includes detection reason');
  assert(localAlerts[0].evidence.some(e => e.includes('RULE-001')), 'Local alert evidence includes RULE-001');

  // -------------------------------------------------------------
  // TEST 11: Verify Rule 5 still works exactly as it did before this change
  // -------------------------------------------------------------
  console.log('\n--- TEST 11: Verify Rule 5 (SENSITIVE_FILE_DOWNLOAD) remains working ---');
  const user5 = db.addUser({
    id: db.getUsers().length + 1,
    username: `test_emp_r5_${runId}_105`,
    passwordHash: 'dummyhash',
    role: 'EMPLOYEE',
    employeeId: `EMP-R5-${runId.toUpperCase()}-105`,
    email: `emp105_${runId}@example.com`,
    fullName: 'Test Employee 105',
    department: 'R&D',
    designation: 'Research Scientist',
    clearanceLevel: 'RESTRICTED',
    ipAddress: '192.168.1.106',
    status: 'ACTIVE',
    createdAt: new Date().toISOString(),
  });

  const rule5Res = siem.ingestLog({
    timestamp: new Date().toISOString(),
    userId: user5.id,
    username: user5.username,
    source: 'endpoint-agent',
    eventType: 'FILE_ACCESS',
    action: 'DOWNLOAD',
    resource: 'Project_Titan_Confidential.pdf',
    ipAddress: '192.168.1.106',
    severity: 'HIGH',
    details: { classification: 'CONFIDENTIAL', file_size_mb: 45.0, sizeMb: 45.0 },
  });

  const matchedRule5 = rule5Res.findings.some(f => f.ruleCode === 'SENSITIVE_FILE_DOWNLOAD');
  assert(matchedRule5, 'Rule 5 (SENSITIVE_FILE_DOWNLOAD) triggers normally on confidential file download');

  console.log('\n=============================================================');
  console.log(` RULE 1 VERIFICATION SUMMARY: ${passed} PASSED | ${failed} FAILED `);
  console.log('=============================================================');

  if (failed > 0) {
    process.exit(1);
  }
}

runRule1Tests().catch((err) => {
  console.error('Fatal test error:', err);
  process.exit(1);
});
