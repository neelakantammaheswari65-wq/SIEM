import { DBUser } from '../db/database';
import {
  Alert,
  EventType,
  Finding,
  NormalizedEvent,
  RiskScore,
  Rule,
  SecurityLog,
  Severity,
  SOCSummary,
  User,
} from '../../src/types/siem';

// The canonical 7 Enterprise Detection Rules
export const SEVEN_DETECTION_RULES: Rule[] = [
  {
    id: 1,
    ruleCode: 'RULE-001',
    name: 'Multiple Failed Logins',
    description: 'Detects 5 or more failed authentication attempts within a 10-minute rolling detection window',
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

const FIRST_NAMES = [
  'James', 'Mary', 'Robert', 'Patricia', 'John', 'Jennifer', 'Michael', 'Linda',
  'David', 'Elizabeth', 'William', 'Barbara', 'Richard', 'Susan', 'Joseph', 'Jessica',
  'Thomas', 'Sarah', 'Charles', 'Karen', 'Christopher', 'Nancy', 'Daniel', 'Lisa',
  'Matthew', 'Betty', 'Anthony', 'Margaret', 'Mark', 'Sandra', 'Donald', 'Ashley',
  'Steven', 'Kimberly', 'Paul', 'Emily', 'Andrew', 'Donna', 'Joshua', 'Michelle',
  'Kenneth', 'Dorothy', 'Kevin', 'Carol', 'Brian', 'Amanda', 'George', 'Melissa',
  'Edward', 'Deborah', 'Ronald', 'Stephanie', 'Timothy', 'Rebecca', 'Jason', 'Sharon',
  'Jeffrey', 'Laura', 'Ryan', 'Cynthia', 'Jacob', 'Kathleen', 'Gary', 'Amy',
  'Nicholas', 'Shirley', 'Eric', 'Angela', 'Jonathan', 'Helen', 'Stephen', 'Anna',
  'Larry', 'Brenda', 'Justin', 'Pamela', 'Scott', 'Nicole', 'Brandon', 'Emma',
  'Benjamin', 'Samantha', 'Samuel', 'Katherine', 'Gregory', 'Christine', 'Alexander', 'Debra',
  'Patrick', 'Rachel', 'Frank', 'Catherine', 'Raymond', 'Carolyn', 'Jack', 'Janet',
  'Dennis', 'Ruth', 'Jerry', 'Maria', 'Tyler', 'Heather', 'Aaron', 'Diane',
  'Jose', 'Virginia', 'Adam', 'Julie', 'Nathan', 'Joyce', 'Henry', 'Victoria',
  'Douglas', 'Olivia', 'Zachary', 'Kelly', 'Peter', 'Christina', 'Kyle', 'Lauren',
  'Walter', 'Joan', 'Ethan', 'Evelyn', 'Jeremy', 'Judith', 'Harold', 'Megan',
  'Keith', 'Cheryl', 'Christian', 'Andrea', 'Roger', 'Hannah', 'Noah', 'Martha',
  'Gerald', 'Jacqueline', 'Carl', 'Frances', 'Terry', 'Gloria', 'Sean', 'Ann',
  'Austin', 'Teresa', 'Arthur', 'Kathryn', 'Lawrence', 'Sara', 'Jesse', 'Janice',
  'Dylan', 'Jean', 'Bryan', 'Alice', 'Joe', 'Madison', 'Jordan', 'Doris',
];

const LAST_NAMES = [
  'Smith', 'Johnson', 'Williams', 'Brown', 'Jones', 'Garcia', 'Miller', 'Davis',
  'Rodriguez', 'Martinez', 'Hernandez', 'Lopez', 'Gonzalez', 'Wilson', 'Anderson', 'Thomas',
  'Taylor', 'Moore', 'Jackson', 'Martin', 'Lee', 'Perez', 'Thompson', 'White',
  'Harris', 'Sanchez', 'Clark', 'Ramirez', 'Lewis', 'Robinson', 'Walker', 'Young',
  'Allen', 'King', 'Wright', 'Scott', 'Torres', 'Nguyen', 'Hill', 'Flores',
  'Green', 'Adams', 'Nelson', 'Baker', 'Hall', 'Rivera', 'Campbell', 'Mitchell',
  'Carter', 'Roberts', 'Gomez', 'Phillips', 'Evans', 'Turner', 'Diaz', 'Parker',
  'Cruz', 'Edwards', 'Collins', 'Reyes', 'Stewart', 'Morris', 'Morales', 'Murphy',
  'Cook', 'Rogers', 'Gutierrez', 'Ortiz', 'Morgan', 'Cooper', 'Peterson', 'Bailey',
  'Reed', 'Kelly', 'Howard', 'Ramos', 'Kim', 'Cox', 'Ward', 'Richardson',
  'Watson', 'Brooks', 'Chavez', 'Wood', 'James', 'Bennett', 'Gray', 'Mendoza',
  'Ruiz', 'Hughes', 'Price', 'Alvarez', 'Castillo', 'Sanders', 'Patel', 'Myers',
  'Long', 'Ross', 'Foster', 'Jimenez', 'Powell', 'Jenkins', 'Perry', 'Russell',
  'Sullivan', 'Bell', 'Coleman', 'Butler', 'Henderson', 'Barnes', 'Gonzales', 'Fisher',
];

const DEPARTMENTS: { name: string; weight: number; roles: string[] }[] = [
  {
    name: 'Engineering',
    weight: 300,
    roles: [
      'Senior Software Engineer',
      'Fullstack Developer',
      'Backend Systems Engineer',
      'Frontend Architect',
      'QA Automation Engineer',
      'DevOps Platform Engineer',
      'Site Reliability Engineer',
      'Cloud Infrastructure Specialist',
    ],
  },
  {
    name: 'Sales & Marketing',
    weight: 180,
    roles: [
      'Account Executive',
      'Enterprise Sales Director',
      'Sales Operations Analyst',
      'Growth Marketing Manager',
      'Solutions Architect',
      'Brand Strategist',
    ],
  },
  {
    name: 'Customer Operations',
    weight: 120,
    roles: [
      'Customer Success Manager',
      'Technical Support Engineer',
      'Client Onboarding Lead',
      'Operations Associate',
    ],
  },
  {
    name: 'Finance & Accounting',
    weight: 100,
    roles: [
      'Financial Controller',
      'Senior Financial Analyst',
      'Payroll Administrator',
      'Tax & Compliance Specialist',
      'Internal Auditor',
    ],
  },
  {
    name: 'Product & Design',
    weight: 90,
    roles: [
      'Senior Product Manager',
      'Product Owner',
      'Lead UX Researcher',
      'UI/UX Designer',
      'Design Systems Engineer',
    ],
  },
  {
    name: 'Human Resources',
    weight: 60,
    roles: [
      'People Operations Director',
      'Talent Acquisition Lead',
      'HR Business Partner',
      'Compensation & Benefits Analyst',
    ],
  },
  {
    name: 'IT & Security',
    weight: 60,
    roles: [
      'Systems Administrator',
      'SOC Security Analyst',
      'IT Support Specialist',
      'Network Security Engineer',
      'IAM Administrator',
    ],
  },
  {
    name: 'Legal & Compliance',
    weight: 50,
    roles: [
      'Corporate Legal Counsel',
      'Compliance Officer',
      'Data Privacy Officer',
      'Regulatory Affairs Specialist',
    ],
  },
  {
    name: 'Executive & Strategy',
    weight: 40,
    roles: [
      'VP of Engineering',
      'Chief Financial Officer',
      'Chief Product Officer',
      'Director of Strategic Operations',
    ],
  },
];

const CLEARANCE_LEVELS = ['PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'RESTRICTED', 'HIGHLY_CONFIDENTIAL'];

export interface DemoDataset {
  generatedAt: string;
  totalEmployees: number;
  totalEvents: number;
  employees: DBUser[];
  events: NormalizedEvent[];
  securityLogs: SecurityLog[];
  findings: Finding[];
  riskScores: RiskScore[];
  alerts: Alert[];
  rules: Rule[];
}

export class DemoDatasetService {
  private static instance: DemoDatasetService;
  private dataset: DemoDataset | null = null;
  private isGenerating = false;

  private constructor() {}

  public static getInstance(): DemoDatasetService {
    if (!DemoDatasetService.instance) {
      DemoDatasetService.instance = new DemoDatasetService();
    }
    return DemoDatasetService.instance;
  }

  /**
   * Deterministic Pseudo-Random Generator
   */
  private createPrng(seed: number = 42) {
    let s = seed;
    return () => {
      s = (s * 9301 + 49297) % 233280;
      return s / 233280;
    };
  }

  /**
   * Generates or retrieves the cached Demo Dataset
   * - 1,000 Demo Employees (tagged isDemo: true, dataset: 'DEMO', strictly NOT manual)
   * - ~15,000 Security Events (10,000-20,000 range)
   * - 7 Detection Rules evaluated
   * - Full Risk Scoring (0-100)
   * - Correlated Alerts
   */
  public getOrCreateDataset(): DemoDataset {
    if (this.dataset) {
      return this.dataset;
    }
    return this.generateDataset();
  }

  public generateDataset(): DemoDataset {
    if (this.isGenerating && this.dataset) {
      return this.dataset;
    }
    this.isGenerating = true;

    const startTime = Date.now();
    const rand = this.createPrng(1337);

    // -----------------------------------------------------------------
    // 1. Generate 1,000 Demo Employees
    // -----------------------------------------------------------------
    const employees: DBUser[] = [];
    const usedUsernames = new Set<string>();

    let deptIdx = 0;
    let deptCount = 0;

    for (let i = 1; i <= 1000; i++) {
      const fn = FIRST_NAMES[Math.floor(rand() * FIRST_NAMES.length)];
      const ln = LAST_NAMES[Math.floor(rand() * LAST_NAMES.length)];
      const fullName = `${fn} ${ln}`;

      let baseUsername = `${fn[0].toLowerCase()}${ln.toLowerCase()}`.replace(/[^a-z0-9]/g, '');
      let username = baseUsername;
      let counter = 1;
      while (usedUsernames.has(username) || username.length < 3) {
        username = `${baseUsername}${counter++}`;
      }
      usedUsernames.add(username);

      const deptObj = DEPARTMENTS[deptIdx];
      deptCount++;
      if (deptCount >= deptObj.weight && deptIdx < DEPARTMENTS.length - 1) {
        deptIdx++;
        deptCount = 0;
      }

      const roleInDept = deptObj.roles[Math.floor(rand() * deptObj.roles.length)];

      // Clearance distribution
      let clearanceLevel = 'INTERNAL';
      const cRoll = rand();
      if (deptObj.name === 'Executive & Strategy' || deptObj.name === 'Finance & Accounting' || deptObj.name === 'Legal & Compliance') {
        clearanceLevel = cRoll > 0.4 ? (cRoll > 0.8 ? 'HIGHLY_CONFIDENTIAL' : 'CONFIDENTIAL') : 'RESTRICTED';
      } else {
        clearanceLevel = cRoll > 0.85 ? 'CONFIDENTIAL' : cRoll > 0.5 ? 'INTERNAL' : 'PUBLIC';
      }

      // Status distribution
      const sRoll = rand();
      const status: 'ACTIVE' | 'SUSPENDED' | 'DISABLED' = sRoll > 0.97 ? 'SUSPENDED' : sRoll > 0.95 ? 'DISABLED' : 'ACTIVE';

      // User system role
      const userRole = (deptObj.name === 'IT & Security' && rand() > 0.5)
        ? (rand() > 0.7 ? 'ADMIN' : 'SECURITY_ANALYST')
        : 'EMPLOYEE';

      const padId = String(i).padStart(4, '0');
      const employeeId = `EMP-D${padId}`;
      const subnetA = 10;
      const subnetB = 14 + Math.floor(rand() * 4);
      const subnetC = Math.floor(rand() * 254) + 1;
      const subnetD = Math.floor(rand() * 254) + 1;
      const ipAddress = `${subnetA}.${subnetB}.${subnetC}.${subnetD}`;

      const createdAtDaysAgo = Math.floor(rand() * 365) + 30;
      const createdAt = new Date(Date.now() - createdAtDaysAgo * 86400000).toISOString();
      const lastLoginHoursAgo = Math.floor(rand() * 72);
      const lastLogin = new Date(Date.now() - lastLoginHoursAgo * 3600000).toISOString();

      employees.push({
        id: 1000 + i,
        username,
        email: `${username}@corp-apex.internal`,
        passwordHash: '$2a$10$demoHashedPasswordDummyStringFor1000Employees...',
        fullName,
        department: deptObj.name,
        role: userRole as any,
        status,
        employeeId,
        designation: roleInDept,
        clearanceLevel,
        createdAt,
        lastLogin,
        ipAddress,
        isManual: false, // Explicitly false! Keeps manually created employees isolated and unchanged
      });
    }

    // -----------------------------------------------------------------
    // 2. Select Threat Target Subjects for Specific Rule Violations
    // -----------------------------------------------------------------
    // 8 Malicious / Flagged Subjects (CRITICAL Threat Actors)
    const criticalSubjects = employees.slice(0, 8);
    // 20 High-Risk Subjects (Frequent single or dual rule violations)
    const highRiskSubjects = employees.slice(8, 28);
    // 50 Medium-Risk Subjects (Occasional policy violation)
    const mediumRiskSubjects = employees.slice(28, 78);
    // The rest (922 employees) are nominal baseline employees

    // -----------------------------------------------------------------
    // 3. Generate ~15,000 Security Events across 30 days
    // -----------------------------------------------------------------
    const events: NormalizedEvent[] = [];
    const securityLogs: SecurityLog[] = [];
    const findings: Finding[] = [];

    const now = Date.now();
    const thirtyDaysMs = 30 * 86400000;

    let eventIdCounter = 1;
    let logIdCounter = 1;
    let findingIdCounter = 1;

    const pushEvent = (
      user: DBUser,
      eventType: EventType,
      action: string,
      resource: string,
      severity: Severity,
      timestamp: string,
      details: Record<string, any> = {},
      source: string = 'endpoint-agent'
    ) => {
      const eid = eventIdCounter++;
      const lid = logIdCounter++;

      const log: SecurityLog = {
        id: lid,
        userId: user.id,
        username: user.username,
        timestamp,
        source,
        eventType,
        action,
        resource,
        ipAddress: details.ipAddress || user.ipAddress || '10.14.88.102',
        severity,
        details,
      };
      securityLogs.push(log);

      const ev: NormalizedEvent = {
        id: eid,
        logId: lid,
        userId: user.id,
        username: user.username,
        eventType,
        timestamp,
        normalizedData: {
          action,
          resource,
          severity,
          ipAddress: log.ipAddress,
          ...details,
        },
        processed: true,
        createdAt: timestamp,
      };
      events.push(ev);

      return ev;
    };

    const pushFinding = (
      rule: Rule,
      ev: NormalizedEvent,
      user: DBUser,
      reason: string,
      metadata: Record<string, any> = {}
    ) => {
      const fid = findingIdCounter++;
      const finding: Finding = {
        id: fid,
        ruleId: rule.id,
        ruleCode: rule.ruleCode,
        ruleName: rule.name,
        eventId: ev.id,
        userId: user.id,
        username: user.username,
        severity: rule.severity,
        riskWeight: rule.riskWeight,
        reason,
        metadata: {
          ruleId: rule.ruleCode,
          employeeId: user.employeeId,
          action: ev.normalizedData.action,
          resource: ev.normalizedData.resource,
          data: ev.normalizedData,
          ...metadata,
        },
        status: 'OPEN',
        createdAt: ev.timestamp,
      };
      findings.push(finding);
      return finding;
    };

    // A. Generate Baseline Nominal Telemetry (~11,000 events)
    // Routine successful logins, standard internal file views
    for (let i = 0; i < 7500; i++) {
      const user = employees[Math.floor(rand() * employees.length)];
      const ts = new Date(now - Math.floor(rand() * thirtyDaysMs)).toISOString();
      pushEvent(user, 'LOGIN', 'AUTH_SUCCESS', 'SSO-Enterprise-Gateway', 'LOW', ts, {
        mfa_verified: true,
        client: 'Workstation-Client',
      });
    }

    for (let i = 0; i < 3500; i++) {
      const user = employees[Math.floor(rand() * employees.length)];
      const ts = new Date(now - Math.floor(rand() * thirtyDaysMs)).toISOString();
      pushEvent(user, 'FILE_ACCESS', 'VIEW', `/share/${user.department.toLowerCase().replace(/[^a-z]/g, '_')}/general_notes.docx`, 'LOW', ts, {
        classification: 'INTERNAL',
        sizeMb: Math.floor(rand() * 15) + 1,
      });
    }

    // B. RULE-001: Multiple Failed Logins (~1,200 events)
    // Dispersed failed logins + 25 dedicated rapid attack bursts
    const rule001 = SEVEN_DETECTION_RULES[0];
    for (let i = 0; i < 800; i++) {
      const user = employees[Math.floor(rand() * employees.length)];
      const ts = new Date(now - Math.floor(rand() * thirtyDaysMs)).toISOString();
      pushEvent(user, 'FAILED_LOGIN', 'AUTH_FAILED', 'SSO-Enterprise-Gateway', 'MEDIUM', ts, {
        failure_reason: 'Invalid password or expired token',
        attempt_number: 1,
      });
    }

    // Concentrated Brute-force bursts (5-8 attempts within 10 minutes) targeting specific subjects
    const bruteForceTargets = [...criticalSubjects, ...highRiskSubjects.slice(0, 15)];
    bruteForceTargets.forEach((target, burstIdx) => {
      const burstBaseTime = now - (burstIdx + 1) * 3600000 * 18;
      const burstCount = 6 + Math.floor(rand() * 3);
      for (let attempt = 1; attempt <= burstCount; attempt++) {
        const attemptTs = new Date(burstBaseTime + attempt * 40000).toISOString();
        const ev = pushEvent(target, 'FAILED_LOGIN', 'AUTH_FAILED', 'SSO-Enterprise-Gateway', 'HIGH', attemptTs, {
          failure_reason: 'Bad password hash mismatch',
          attempt_number: attempt,
          threshold: 5,
          detection_window_minutes: 10,
        });

        if (attempt >= 5) {
          pushFinding(
            rule001,
            ev,
            target,
            `${attempt} failed login attempts detected for ${target.employeeId} within 10 minutes (Threshold: 5).`,
            { attemptCount: attempt, windowMinutes: 10 }
          );
        }
      }
    });

    // C. RULE-002: Unauthorized Access (~450 events)
    // 403 Forbidden / RBAC boundary violations
    const rule002 = SEVEN_DETECTION_RULES[1];
    const unauthTargets = [...criticalSubjects, ...highRiskSubjects.slice(5, 20)];
    const protectedResources = [
      '/api/admin/settings',
      '/vault/executive/compensation.xlsx',
      '/api/security/master-keys',
      '/vault/hr/termination_letters_q3.pdf',
      '/api/system/firewall-rules',
    ];

    unauthTargets.forEach((target, idx) => {
      const attempts = 3 + Math.floor(rand() * 4);
      for (let a = 0; a < attempts; a++) {
        const targetRes = protectedResources[Math.floor(rand() * protectedResources.length)];
        const ts = new Date(now - (idx * 24 + a * 2) * 3600000).toISOString();
        const ev = pushEvent(target, 'UNAUTHORIZED_ACCESS', 'ACCESS_DENIED', targetRes, 'HIGH', ts, {
          resource: targetRes,
          userRole: target.role,
          employeeId: target.employeeId,
          statusCode: 403,
          reason: `User ${target.employeeId} (Role: ${target.role}) attempted unauthorized access to resource: ${targetRes}`,
        });

        pushFinding(
          rule002,
          ev,
          target,
          `User ${target.employeeId} (Role: ${target.role}) attempted unauthorized access to resource: ${targetRes}`,
          { resource: targetRes, userRole: target.role, statusCode: 403 }
        );
      }
    });

    // D. RULE-003: Sensitive File Access (~900 events)
    const rule003 = SEVEN_DETECTION_RULES[2];
    const sensitiveFiles = [
      { name: 'Strategic_Business_Plan.pdf', path: '/vault/executive/Strategic_Business_Plan.pdf', cls: 'HIGHLY_CONFIDENTIAL', sizeMb: 750 },
      { name: 'Payroll_Records.xlsx', path: '/vault/hr/Payroll_Records.xlsx', cls: 'CONFIDENTIAL', sizeMb: 300 },
      { name: 'Customer_Database_Backup.zip', path: '/vault/ops/Customer_Database_Backup.zip', cls: 'CONFIDENTIAL', sizeMb: 450 },
      { name: 'Financial_Report_2026.xlsx', path: '/vault/finance/Financial_Report_2026.xlsx', cls: 'CONFIDENTIAL', sizeMb: 150 },
      { name: 'M&A_Strategy_Document.pdf', path: '/vault/executive/M&A_Strategy_Document.pdf', cls: 'HIGHLY_CONFIDENTIAL', sizeMb: 800 },
    ];

    const sensitiveTargets = [...criticalSubjects, ...highRiskSubjects, ...mediumRiskSubjects];
    sensitiveTargets.forEach((target, idx) => {
      const count = (criticalSubjects.includes(target) ? 8 : 2) + Math.floor(rand() * 3);
      for (let c = 0; c < count; c++) {
        const fileObj = sensitiveFiles[Math.floor(rand() * sensitiveFiles.length)];
        const ts = new Date(now - (idx * 12 + c * 3) * 3600000).toISOString();
        const ev = pushEvent(target, 'FILE_ACCESS', 'OPEN', fileObj.path, 'MEDIUM', ts, {
          classification: fileObj.cls,
          fileName: fileObj.name,
          sizeMb: fileObj.sizeMb,
        });

        pushFinding(
          rule003,
          ev,
          target,
          `Matched detection rule [RULE-003]: User ${target.employeeId} accessed ${fileObj.cls} repository: ${fileObj.name}`,
          { classification: fileObj.cls, fileName: fileObj.name, sizeMb: fileObj.sizeMb }
        );
      }
    });

    // E. RULE-004: Large File Download (>500MB) (~320 events)
    const rule004 = SEVEN_DETECTION_RULES[3];
    const largeDownloadTargets = [...criticalSubjects, ...highRiskSubjects.slice(0, 10)];
    largeDownloadTargets.forEach((target, idx) => {
      const downloadsCount = 2 + Math.floor(rand() * 3);
      for (let d = 0; d < downloadsCount; d++) {
        const sizeMb = 550 + Math.floor(rand() * 700);
        const fileObj = sensitiveFiles[Math.floor(rand() * sensitiveFiles.length)];
        const ts = new Date(now - (idx * 15 + d * 4) * 3600000).toISOString();
        const ev = pushEvent(target, 'FILE_ACCESS', 'DOWNLOAD', fileObj.path, 'HIGH', ts, {
          action: 'DOWNLOAD',
          sizeMb,
          classification: fileObj.cls,
          fileName: fileObj.name,
          protocol: 'HTTPS_BULK_EXPORT',
        });

        pushFinding(
          rule004,
          ev,
          target,
          `Matched detection rule [RULE-004]: User ${target.employeeId} downloaded ${sizeMb} MB exceeding 500MB egress threshold.`,
          { action: 'DOWNLOAD', sizeMb, fileName: fileObj.name }
        );
      }
    });

    // F. RULE-005: Unauthorized USB Device Inserted (~380 events)
    const rule005 = SEVEN_DETECTION_RULES[4];
    const rogueDrives = [
      { id: 'USB-PERS-404', name: 'Generic Mass Storage Device (Unidentified)', vendor: 'Generic USB' },
      { id: 'USB-ROGUE-911', name: 'Crucial X8 Portable SSD (Personal)', vendor: 'Crucial' },
      { id: 'USB-UNKNOWN-02', name: 'SanDisk Ultra Dual Drive (Blacklisted)', vendor: 'SanDisk' },
    ];

    const usbTargets = [...criticalSubjects, ...highRiskSubjects.slice(2, 14)];
    usbTargets.forEach((target, idx) => {
      const inserts = 2 + Math.floor(rand() * 3);
      for (let u = 0; u < inserts; u++) {
        const drive = rogueDrives[Math.floor(rand() * rogueDrives.length)];
        const ts = new Date(now - (idx * 20 + u * 5) * 3600000).toISOString();
        const ev = pushEvent(target, 'USB_INSERT', 'DEVICE_ATTACHED', drive.id, 'HIGH', ts, {
          authorized: false,
          deviceId: drive.id,
          deviceName: drive.name,
          vendor: drive.vendor,
        }, 'usb-monitor');

        pushFinding(
          rule005,
          ev,
          target,
          `Matched detection rule [RULE-005]: User ${target.employeeId} inserted unauthorized external storage device [${drive.id}]: ${drive.name}.`,
          { authorized: false, deviceId: drive.id }
        );
      }
    });

    // G. RULE-006: High-Volume USB Transfer (>500MB) (~260 events)
    const rule006 = SEVEN_DETECTION_RULES[5];
    const usbTransferTargets = [...criticalSubjects, ...highRiskSubjects.slice(0, 8)];
    usbTransferTargets.forEach((target, idx) => {
      const transfers = 1 + Math.floor(rand() * 3);
      for (let t = 0; t < transfers; t++) {
        const totalSizeMb = 550 + Math.floor(rand() * 650);
        const ts = new Date(now - (idx * 22 + t * 6) * 3600000).toISOString();
        const ev = pushEvent(target, 'USB_TRANSFER_REQUEST', 'TRANSFER_BLOCK', 'USB-PERS-404', 'HIGH', ts, {
          totalSizeMb,
          total_size_mb: totalSizeMb,
          deviceId: 'USB-PERS-404',
          fileCount: 4,
          decision: 'BLOCK',
        }, 'usb-monitor');

        pushFinding(
          rule006,
          ev,
          target,
          `Matched detection rule [RULE-006]: User ${target.employeeId} attempted ${totalSizeMb} MB external USB transfer exceeding 500MB threshold.`,
          { totalSizeMb, decision: 'BLOCK' }
        );
      }
    });

    // H. RULE-007: Privilege Escalation Attempt (~160 events)
    const rule007 = SEVEN_DETECTION_RULES[6];
    const privEscTargets = criticalSubjects;
    privEscTargets.forEach((target, idx) => {
      const attempts = 2 + Math.floor(rand() * 2);
      for (let p = 0; p < attempts; p++) {
        const ts = new Date(now - (idx * 25 + p * 8) * 3600000).toISOString();
        const ev = pushEvent(target, 'PRIVILEGE_CHANGE', 'SUDO_PRIVILEGE_ELEVATION_ATTEMPT', '/etc/sudoers.d/backdoor', 'CRITICAL', ts, {
          action: 'SUDO_PRIVILEGE_ELEVATION_ATTEMPT',
          command: `sudo -s echo "${target.username} ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers`,
          granted: false,
          escalation_target: 'ROOT_SUPERADMIN',
        }, 'os-kernel-audit');

        pushFinding(
          rule007,
          ev,
          target,
          `Matched detection rule [RULE-007]: Critical privilege escalation attempt by User ${target.employeeId}: unauthorized SUDO modification.`,
          { action: 'SUDO_PRIVILEGE_ELEVATION_ATTEMPT', granted: false }
        );
      }
    });

    // -----------------------------------------------------------------
    // 4. Calculate Risk Scoring for All 1,000 Employees
    // -----------------------------------------------------------------
    const riskScores: RiskScore[] = [];

    employees.forEach((emp) => {
      const userFindings = findings.filter((f) => f.userId === emp.id);

      let baseScore = 0;
      userFindings.forEach((f) => {
        baseScore += f.riskWeight || 25;
      });

      // Factor in critical status or multiple rules
      const ruleCodes = new Set(userFindings.map((f) => f.ruleCode));
      let multiRuleMultiplier = 1.0;
      if (ruleCodes.size >= 4) multiRuleMultiplier = 1.4;
      else if (ruleCodes.size >= 2) multiRuleMultiplier = 1.2;

      let calculatedScore = Math.round(baseScore * multiRuleMultiplier);
      if (userFindings.length === 0) {
        // Nominal enterprise floor
        calculatedScore = Math.floor(rand() * 15) + 5;
      }

      const finalScore = Math.min(100, Math.max(0, calculatedScore));

      let riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' = 'LOW';
      if (finalScore >= 75) riskLevel = 'CRITICAL';
      else if (finalScore >= 50) riskLevel = 'HIGH';
      else if (finalScore >= 25) riskLevel = 'MEDIUM';

      riskScores.push({
        id: emp.id,
        userId: emp.id,
        username: emp.username,
        ruleScore: Math.min(100, baseScore),
        mlScore: Math.min(100, Math.round(baseScore * 0.8)),
        behaviorScore: Math.min(100, Math.round(baseScore * 0.9)),
        finalScore,
        riskLevel,
        contributingFindingsCount: userFindings.length,
        scoreBreakdown: {},
        calculationWindowStart: new Date(Date.now() - 24 * 3600 * 1000).toISOString(),
        calculationWindowEnd: new Date().toISOString(),
        calculatedAt: new Date().toISOString(),
      });
    });

    // -----------------------------------------------------------------
    // 5. Correlate Alerts from Rule Triggers
    // -----------------------------------------------------------------
    const alerts: Alert[] = [];
    let alertIdSeq = 1;

    // A. Generate Critical Alerts for Critical Subjects (Multi-Stage Attacks)
    criticalSubjects.forEach((subject, idx) => {
      const subjectFindings = findings.filter((f) => f.userId === subject.id);
      const risk = riskScores.find((r) => r.userId === subject.id);
      const alertId = `ALT-DEMO-CRIT-${subject.employeeId}`;

      const alert: Alert = {
        id: alertIdSeq++,
        alertId,
        userId: subject.id,
        username: subject.username,
        userDepartment: subject.department,
        title: `Multi-Stage Insider Threat Campaign & Data Egress`,
        description: `Correlated advanced insider threat detected for ${subject.fullName} (${subject.employeeId}). Observed unauthorized access, massive file egress, rogue USB device attachment, and sudo privilege escalation attempts.`,
        severity: 'CRITICAL',
        status: idx < 4 ? 'OPEN' : 'INVESTIGATING',
        riskScore: risk?.finalScore || 92,
        mlAnomalyScore: 94,
        correlationKey: `CORR_CRIT_${subject.id}`,
        firstSeen: subjectFindings[0]?.createdAt || new Date(now - 86400000 * 2).toISOString(),
        lastSeen: new Date().toISOString(),
        eventCount: subjectFindings.length * 3,
        findingCount: subjectFindings.length,
        evidence: [
          `Failed login burst detected exceeding RULE-001 threshold`,
          `Unauthorized access attempt to /api/admin/settings (RULE-002)`,
          `Confidential documents accessed & downloaded > 500MB (RULE-003, RULE-004)`,
          `Unapproved external storage device attached [USB-PERS-404] (RULE-005)`,
          `High-volume 850MB USB egress attempt blocked by DLP (RULE-006)`,
          `Unauthorized sudoers file modification / elevation attempt (RULE-007)`,
        ],
        recommendations: [
          'Immediate IAM credential revocation and session kill',
          'Quarantine endpoint workstation from enterprise corporate VLAN',
          'Deploy emergency DLP hardware lock to USB bus controller',
          'Initiate high-priority Security Operations Center incident response ticket',
        ],
        policyViolations: ['RULE-001', 'RULE-002', 'RULE-004', 'RULE-005', 'RULE-006', 'RULE-007'],
        createdAt: new Date(now - (idx + 1) * 3600000 * 4).toISOString(),
      };
      alerts.push(alert);
    });

    // B. Generate High Alerts for High-Risk Subjects (Specific Rule Clusters)
    highRiskSubjects.forEach((subject, idx) => {
      const subjectFindings = findings.filter((f) => f.userId === subject.id);
      const risk = riskScores.find((r) => r.userId === subject.id);
      const alertId = `ALT-DEMO-HIGH-${subject.employeeId}`;

      const primaryRule = subjectFindings[0]?.ruleCode || 'RULE-001';
      let title = `Multiple Failed Logins & Credential Probing`;
      let desc = `Multiple rapid authentication failures detected for ${subject.fullName} [${subject.employeeId}]. Potential brute-force or credential stuffing activity.`;

      if (primaryRule === 'RULE-002') {
        title = `Unauthorized Resource Access & RBAC Violations`;
        desc = `User ${subject.fullName} [${subject.employeeId}] attempted repeated unauthorized access to restricted endpoints.`;
      } else if (primaryRule === 'RULE-004' || primaryRule === 'RULE-006') {
        title = `High-Volume Enterprise Data Egress Threshold Breached`;
        desc = `Bulk data egress operation (>500MB) initiated by user ${subject.fullName} [${subject.employeeId}].`;
      } else if (primaryRule === 'RULE-005') {
        title = `Rogue External Peripheral Attachment`;
        desc = `Unwhitelisted USB drive attached to endpoint belonging to ${subject.fullName} [${subject.employeeId}].`;
      }

      const alert: Alert = {
        id: alertIdSeq++,
        alertId,
        userId: subject.id,
        username: subject.username,
        userDepartment: subject.department,
        title,
        description: desc,
        severity: 'HIGH',
        status: idx % 3 === 0 ? 'INVESTIGATING' : 'OPEN',
        riskScore: risk?.finalScore || 68,
        mlAnomalyScore: 78,
        correlationKey: `CORR_HIGH_${subject.id}`,
        firstSeen: subjectFindings[0]?.createdAt || new Date(now - 86400000 * 5).toISOString(),
        lastSeen: new Date().toISOString(),
        eventCount: subjectFindings.length * 2,
        findingCount: subjectFindings.length,
        evidence: subjectFindings.map((f) => f.reason).slice(0, 5),
        recommendations: [
          'Verify legitimate business necessity with department manager',
          'Review endpoint event history and process trees',
          'Inspect network connection logs for external exfiltration destinations',
        ],
        policyViolations: Array.from(new Set(subjectFindings.map((f) => f.ruleCode))),
        createdAt: new Date(now - (idx + 1) * 3600000 * 12).toISOString(),
      };
      alerts.push(alert);
    });

    const durationMs = Date.now() - startTime;
    console.log(
      `[DEMO_DATASET_GENERATED] 1,000 Demo Employees, ${events.length} Security Events, ${findings.length} Rule Findings, 7 Detection Rules, ${alerts.length} Alerts in ${durationMs}ms.`
    );

    this.dataset = {
      generatedAt: new Date().toISOString(),
      totalEmployees: employees.length,
      totalEvents: events.length,
      employees,
      events,
      securityLogs,
      findings,
      riskScores,
      alerts,
      rules: SEVEN_DETECTION_RULES,
    };

    this.isGenerating = false;
    return this.dataset;
  }

  public getSOCSummary(): SOCSummary {
    const data = this.getOrCreateDataset();
    const openAlerts = data.alerts.filter((a) => a.status === 'OPEN' || a.status === 'INVESTIGATING');
    const criticalAlerts = openAlerts.filter((a) => a.severity === 'CRITICAL');
    const highRiskUsers = data.riskScores.filter((s) => s.finalScore >= 50).length;
    const avgRiskScore = Math.round(
      data.riskScores.reduce((acc, s) => acc + s.finalScore, 0) / data.riskScores.length
    );

    return {
      totalEvents: data.totalEvents,
      events24h: Math.round(data.totalEvents * 0.12),
      openAlerts: openAlerts.length,
      criticalAlerts: criticalAlerts.length,
      highRiskUsers,
      avgRiskScore,
      usbTransfersBlocked: 42,
      usbTransfersProtected: 18,
      usbTransfersAllowed: 120,
      activeMlAnomalies: 28,
      rulesActive: 7, // Exactly 7 Detection Rules
    };
  }
}

export const demoDataset = DemoDatasetService.getInstance();
