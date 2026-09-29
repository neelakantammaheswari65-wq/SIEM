import {
  Alert,
  AlertStatus,
  AuditLog,
  DemoFile,
  EventType,
  FileActivityRecord,
  FileClassification,
  Finding,
  MLAnomaly,
  NormalizedEvent,
  RiskLevel,
  RiskScore,
  Rule,
  RuleCondition,
  SecurityLog,
  Severity,
  SOCSummary,
  USBDecision,
  USBDevice,
  USBTransferRequest,
  User,
} from '../types/siem';
import { isFailedLoginEvent, isUnauthorizedAccessEvent } from '../utils/siemRules';

// Configuration constants
export const USB_TRANSFER_THRESHOLD_MB = 500;
export const LARGE_FILE_THRESHOLD_MB = 500;
export const CORRELATION_WINDOW_MINUTES = 15;
export const RISK_WINDOW_HOURS = 24;

// Realistic Demo Files for Employee Repository & Simulation Testing
export const DEMO_FILES: DemoFile[] = [
  {
    id: 'f-handbook-001',
    name: 'Employee_Handbook.pdf',
    sizeMb: 2,
    classification: 'PUBLIC',
    type: 'PDF Document',
    department: 'Human Resources',
    accessPermission: 'GRANTED',
    description: 'Corporate workplace policies, code of conduct, and organizational guidelines.',
    lastModified: '2026-01-10T09:00:00Z',
  },
  {
    id: 'f-report-002',
    name: 'Team_Project_Report.docx',
    sizeMb: 20,
    classification: 'INTERNAL',
    type: 'Word Document',
    department: 'Engineering',
    accessPermission: 'GRANTED',
    description: 'Sprint retrospective and Q1 delivery milestone summary.',
    lastModified: '2026-02-14T14:30:00Z',
  },
  {
    id: 'f-finance-003',
    name: 'Financial_Report_2026.xlsx',
    sizeMb: 150,
    classification: 'CONFIDENTIAL',
    type: 'Excel Spreadsheet',
    department: 'Finance & Compliance',
    accessPermission: 'RESTRICTED_CONFIDENTIAL',
    description: 'Consolidated balance sheet, revenue forecasts, and departmental budget allocations.',
    lastModified: '2026-02-28T18:00:00Z',
  },
  {
    id: 'f-custdb-004',
    name: 'Customer_Database_Backup.zip',
    sizeMb: 450,
    classification: 'CONFIDENTIAL',
    type: 'Zip Archive',
    department: 'IT Infrastructure',
    accessPermission: 'CONFIDENTIAL',
    description: 'Production customer relational database snapshots and encrypted transaction logs.',
    lastModified: '2026-03-01T02:00:00Z',
  },
  {
    id: 'f-archive-005',
    name: 'Company_Data_Archive.zip',
    sizeMb: 600,
    classification: 'CONFIDENTIAL',
    type: 'Zip Archive',
    department: 'Corporate Operations',
    accessPermission: 'CONFIDENTIAL',
    description: 'Comprehensive historical corporate operations records, vendor contracts, and emails.',
    lastModified: '2026-02-20T11:45:00Z',
  },
  {
    id: 'f-source-006',
    name: 'Source_Code_Repository.zip',
    sizeMb: 750,
    classification: 'RESTRICTED',
    type: 'Source Code Archive',
    department: 'Core R&D',
    accessPermission: 'RESTRICTED',
    description: 'Proprietary core engine codebase, quantum algorithmic modules, and release tags.',
    lastModified: '2026-02-25T16:15:00Z',
  },
  {
    id: 'f-pii-007',
    name: 'Employee_PII_Data.csv',
    sizeMb: 50,
    classification: 'SENSITIVE',
    type: 'CSV Data',
    department: 'Human Resources',
    accessPermission: 'SENSITIVE_PII',
    description: 'Confidential employee personnel records, SSNs, payroll details, and home addresses.',
    lastModified: '2026-02-18T10:20:00Z',
  },
  {
    id: 'f-bizplan-008',
    name: 'Strategic_Business_Plan.pdf',
    sizeMb: 100,
    classification: 'HIGHLY_CONFIDENTIAL',
    type: 'PDF Document',
    department: 'Executive Board',
    accessPermission: 'HIGHLY_CONFIDENTIAL',
    description: 'Long-term corporate M&A strategies, competitive valuations, and executive roadmap.',
    lastModified: '2026-03-01T08:00:00Z',
  },
];

// Default Enterprise Detection Rules
export const DEFAULT_RULES: Rule[] = [
  {
    id: 1,
    ruleCode: 'SENSITIVE_FILE_ACCESS',
    name: 'Sensitive File Access',
    description: 'Detects access to CONFIDENTIAL, RESTRICTED, SENSITIVE, or HIGHLY_CONFIDENTIAL corporate data',
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
    createdAt: new Date(Date.now() - 86400000 * 5).toISOString(),
  },
  {
    id: 2,
    ruleCode: 'LARGE_FILE_DOWNLOAD',
    name: 'Large File Download (>500MB)',
    description: 'Detects bulk file download exceeding 500 MB enterprise data egress threshold',
    eventType: 'FILE_ACCESS',
    severity: 'HIGH',
    enabled: true,
    conditions: [{ field: 'file_size_mb', operator: '>', value: 500 }],
    riskWeight: 35,
    createdAt: new Date(Date.now() - 86400000 * 5).toISOString(),
  },
  {
    id: 3,
    ruleCode: 'LARGE_FILE_TRANSFER',
    name: 'Large File Transfer (>500MB)',
    description: 'Detects bulk data transfers and egress operations exceeding 500 MB volume',
    eventType: 'USB_TRANSFER_REQUEST',
    severity: 'HIGH',
    enabled: true,
    conditions: [{ field: 'total_size_mb', operator: '>', value: 500 }],
    riskWeight: 30,
    createdAt: new Date(Date.now() - 86400000 * 5).toISOString(),
  },
  {
    id: 4,
    ruleCode: 'SENSITIVE_LARGE_TRANSFER',
    name: 'Sensitive Large File Transfer',
    description: 'Detects classified or sensitive data transfers exceeding 500 MB in single egress payload',
    eventType: 'FILE_ACCESS',
    severity: 'CRITICAL',
    enabled: true,
    conditions: [
      {
        field: 'classification',
        operator: 'in',
        value: ['CONFIDENTIAL', 'RESTRICTED', 'SENSITIVE', 'HIGHLY_CONFIDENTIAL'],
      },
      { field: 'file_size_mb', operator: '>', value: 500 },
    ],
    riskWeight: 50,
    createdAt: new Date(Date.now() - 86400000 * 5).toISOString(),
  },
  {
    id: 5,
    ruleCode: 'REPEATED_SENSITIVE_ACCESS',
    name: 'Repeated Sensitive File Access',
    description: 'Detects 3 or more accesses to sensitive/confidential files within a 15-minute window',
    eventType: 'FILE_ACCESS',
    severity: 'HIGH',
    enabled: true,
    conditions: [
      {
        field: 'classification',
        operator: 'in',
        value: ['CONFIDENTIAL', 'RESTRICTED', 'SENSITIVE', 'HIGHLY_CONFIDENTIAL'],
      },
    ],
    isTemporal: true,
    temporalConfig: { countThreshold: 3, windowMinutes: 15 },
    riskWeight: 40,
    createdAt: new Date(Date.now() - 86400000 * 5).toISOString(),
  },
  {
    id: 6,
    ruleCode: 'MULTIPLE_FAILED_LOGINS',
    name: 'Multiple Failed Logins',
    description: 'Detects 5 or more failed login attempts within a 10-minute detection window',
    eventType: 'FAILED_LOGIN',
    severity: 'HIGH',
    enabled: true,
    conditions: [],
    isTemporal: true,
    temporalConfig: { countThreshold: 5, windowMinutes: 10 },
    riskWeight: 35,
    createdAt: new Date(Date.now() - 86400000 * 5).toISOString(),
  },
  {
    id: 7,
    ruleCode: 'USB_UNAUTHORIZED',
    name: 'Unauthorized USB Insertion',
    description: 'Detects attachment of an unapproved, unregistered USB device on corporate perimeter',
    eventType: 'USB_INSERT',
    severity: 'HIGH',
    enabled: true,
    conditions: [{ field: 'authorized', operator: '==', value: false }],
    riskWeight: 40,
    createdAt: new Date(Date.now() - 86400000 * 5).toISOString(),
  },
  {
    id: 8,
    ruleCode: 'PRIVILEGE_CHANGE',
    name: 'Unauthorized Privilege Elevation',
    description: 'Detects critical privilege escalation, role modification, or sudo rights assignment',
    eventType: 'PRIVILEGE_CHANGE',
    severity: 'CRITICAL',
    enabled: true,
    conditions: [],
    riskWeight: 50,
    createdAt: new Date(Date.now() - 86400000 * 5).toISOString(),
  },
  {
    id: 11,
    ruleCode: 'UNAUTHORIZED_ACCESS',
    name: 'Unauthorized Access',
    description: 'Detects unauthorized access attempts to protected endpoints, resources, or operations (403 Forbidden / RBAC violation)',
    eventType: 'UNAUTHORIZED_ACCESS',
    severity: 'HIGH',
    enabled: true,
    conditions: [
      { field: 'action', operator: 'in', value: ['ACCESS_DENIED', 'RBAC_VIOLATION', 'UNAUTHORIZED_ACCESS', '403_FORBIDDEN', 'FORBIDDEN'] },
    ],
    riskWeight: 40,
    createdAt: new Date(Date.now() - 86400000 * 5).toISOString(),
  },
];

// Seed Users - empty by default so no demo/mock employees are auto-created
export const SEED_USERS: User[] = [];

export const SIMULATION_FALLBACK_USER: User = {
  id: 101,
  username: 'amercer',
  email: 'alex.mercer@corp-apex.internal',
  fullName: 'Alex Mercer',
  department: 'R&D Engineering',
  role: 'EMPLOYEE',
  status: 'ACTIVE',
  employeeId: 'EMP-101',
  createdAt: '2025-01-15T08:00:00Z',
  ipAddress: '10.14.88.102',
};

// Seed USB Devices
export const SEED_USB_DEVICES: USBDevice[] = [
  {
    id: 1,
    deviceId: 'USB-APEX-092',
    deviceName: 'Apex Encrypted IronKey',
    vendor: 'Kingston Security Corp',
    serialNumber: 'SN-IK90214-X',
    capacityGb: 64,
    userId: 102,
    username: 'schen',
    authorized: true,
    status: 'CONNECTED',
    insertedAt: new Date(Date.now() - 1000 * 60 * 60 * 2).toISOString(),
    createdAt: '2024-10-01T08:00:00Z',
  },
  {
    id: 2,
    deviceId: 'USB-PERS-404',
    deviceName: 'SanDisk Ultra Luxe (Personal)',
    vendor: 'SanDisk International',
    serialNumber: 'SN-SD88921-P',
    capacityGb: 128,
    userId: 101,
    username: 'amercer',
    authorized: false,
    status: 'BLOCKED',
    insertedAt: new Date(Date.now() - 1000 * 60 * 25).toISOString(),
    createdAt: '2025-02-10T14:22:00Z',
  },
  {
    id: 3,
    deviceId: 'USB-APEX-104',
    deviceName: 'Apex Secure Vault Flash',
    vendor: 'Corsair Enterprise',
    serialNumber: 'SN-CS44102-E',
    capacityGb: 32,
    userId: 103,
    username: 'dkim',
    authorized: true,
    status: 'DISCONNECTED',
    removedAt: new Date(Date.now() - 1000 * 60 * 120).toISOString(),
    createdAt: '2024-12-15T09:00:00Z',
  },
];

// Helper to calculate decay factor based on age
export function calculateDecayFactor(timestampIso: string): number {
  const ageHours = (Date.now() - new Date(timestampIso).getTime()) / (1000 * 60 * 60);
  if (ageHours <= 1) return 1.0;
  if (ageHours <= 6) return 0.75;
  if (ageHours <= 12) return 0.5;
  if (ageHours <= 24) return 0.25;
  return 0.0;
}

// Risk Level classifier
export function getRiskLevel(score: number): RiskLevel {
  if (score >= 75) return 'CRITICAL';
  if (score >= 50) return 'HIGH';
  if (score >= 25) return 'MEDIUM';
  return 'LOW';
}

// Operator condition evaluator
function evaluateOperator(actual: any, op: string, target: any): boolean {
  if (actual === undefined || actual === null) return false;
  switch (op) {
    case '==':
      return actual === target;
    case '!=':
      return actual !== target;
    case '>':
      return Number(actual) > Number(target);
    case '>=':
      return Number(actual) >= Number(target);
    case '<':
      return Number(actual) < Number(target);
    case '<=':
      return Number(actual) <= Number(target);
    case 'contains':
      return typeof actual === 'string' && actual.toLowerCase().includes(String(target).toLowerCase());
    case 'in':
      return Array.isArray(target) && target.includes(actual);
    default:
      return false;
  }
}

class SIEMEngine {
  public users: User[] = [...SEED_USERS];
  public rules: Rule[] = [...DEFAULT_RULES];
  public files: DemoFile[] = [...DEMO_FILES];
  public fileActivities: FileActivityRecord[] = [];
  public logs: SecurityLog[] = [];
  public events: NormalizedEvent[] = [];
  public findings: Finding[] = [];
  public riskScores: Map<number, RiskScore> = new Map();
  public riskHistory: RiskScore[] = [];
  public anomalies: Map<number, MLAnomaly> = new Map();
  public alerts: Alert[] = [];
  public usbDevices: USBDevice[] = [...SEED_USB_DEVICES];
  public usbTransfers: USBTransferRequest[] = [];
  public auditLogs: AuditLog[] = [];
  public mlTrained = true;
  public mlVersion = 'iforest-v1.4';
  public mlContamination = 0.1;
  private listeners: ((event: { type: string; payload: any }) => void)[] = [];

  constructor() {
    // Clean starting state - baseline initialized without fake background events
    this.users.forEach((u) => {
      this.recalculateMLAnomaly(u.id);
      this.recalculateRisk(u.id);
    });
  }

  // Event Subscription for WebSocket simulation
  public subscribe(cb: (event: { type: string; payload: any }) => void) {
    this.listeners.push(cb);
    return () => {
      this.listeners = this.listeners.filter((l) => l !== cb);
    };
  }

  private notify(type: string, payload: any) {
    this.listeners.forEach((cb) => cb({ type, payload }));
  }

  // Realistic File Repository Access Simulation (Silent SIEM Event Pipeline)
  public accessFile(
    fileId: string,
    action: 'OPEN' | 'VIEW' | 'DOWNLOAD' | 'REQUEST_ACCESS',
    user: User
  ): { success: boolean; message: string; file: DemoFile } {
    const file = this.files.find((f) => f.id === fileId) || this.files[0];
    const timestamp = new Date().toISOString();

    // 1. Record in user file activity ledger
    const activityRecord: FileActivityRecord = {
      id: `fa-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 6)}`,
      fileId: file.id,
      fileName: file.name,
      sizeMb: file.sizeMb,
      classification: file.classification,
      action,
      timestamp,
      status: action === 'REQUEST_ACCESS' ? 'PENDING' : 'SUCCESS',
      userId: user.id,
      username: user.username,
    };
    this.fileActivities.unshift(activityRecord);

    // 2. Determine security log severity based on file classification & size
    let severity: Severity = 'LOW';
    if (file.classification === 'RESTRICTED' || file.classification === 'HIGHLY_CONFIDENTIAL') {
      severity = file.sizeMb > 500 ? 'CRITICAL' : 'HIGH';
    } else if (file.classification === 'CONFIDENTIAL' || file.classification === 'SENSITIVE') {
      severity = file.sizeMb > 500 ? 'HIGH' : 'MEDIUM';
    } else if (file.sizeMb > 500) {
      severity = 'HIGH';
    }

    // 3. Silently Ingest into the SIEM Log Pipeline
    const eventType: EventType = 'FILE_ACCESS';

    this.ingestLog({
      timestamp,
      userId: user.id,
      username: user.username,
      source: 'file-repository',
      eventType,
      action: `FILE_${action}`,
      resource: `/shares/${file.department.toLowerCase().replace(/\s+/g, '-')}/${file.name}`,
      ipAddress: user.ipAddress || '10.14.88.102',
      severity,
      details: {
        file_id: file.id,
        file_name: file.name,
        file_size_mb: file.sizeMb,
        classification: file.classification,
        department: file.department,
        action,
        status: 'SUCCESS',
        source: 'corporate-share',
      },
    });

    // 4. Audit Log for compliance
    this.recordAudit(
      user.username,
      `FILE_${action}`,
      `file:${file.name}`,
      `User performed ${action} on ${file.classification} document (${file.sizeMb}MB)`
    );

    // 5. Return a clean, non-security corporate response for employee display
    let corporateMsg = 'File download started.';
    if (action === 'OPEN' || action === 'VIEW') {
      corporateMsg = `Opened ${file.name} in secure document viewer.`;
    } else if (action === 'REQUEST_ACCESS') {
      corporateMsg = `Access clearance request submitted for ${file.name}.`;
    } else if (action === 'DOWNLOAD') {
      corporateMsg = `File download started: ${file.name} (${file.sizeMb} MB).`;
    }

    return {
      success: true,
      message: corporateMsg,
      file,
    };
  }

  // Pre-Transfer USB Policy Evaluator (Phase 8 Requirement)
  public evaluateUSBTransferPolicy(
    device: USBDevice,
    files: { name: string; sizeMb: number; sensitive: boolean; type: string }[]
  ): { decision: USBDecision; reasons: string[]; totalSizeMb: number; sensitiveCount: number } {
    const totalSizeMb = files.reduce((acc, f) => acc + f.sizeMb, 0);
    const sensitiveCount = files.filter((f) => f.sensitive).length;
    const reasons: string[] = [];
    let decision: USBDecision = 'ALLOW';

    // RULE 1 & 5: Unauthorized USB -> BLOCK (Strict Priority)
    if (!device.authorized) {
      decision = 'BLOCK';
      reasons.push('Hardware Authorization Policy: USB device is unauthorized on the corporate perimeter.');
    } else {
      // Authorized device checks
      if (totalSizeMb > USB_TRANSFER_THRESHOLD_MB) {
        decision = 'PROTECT';
        reasons.push(
          `Payload Size Policy: Transfer volume (${totalSizeMb.toFixed(1)} MB) exceeds standard ${USB_TRANSFER_THRESHOLD_MB} MB limit.`
        );
      }
      if (sensitiveCount > 0) {
        decision = 'PROTECT';
        reasons.push(
          `Data Classification DLP: ${sensitiveCount} file(s) contain classified, financial, or PII sensitive markers.`
        );
      }
      if (decision === 'ALLOW') {
        reasons.push('Authorized device and transfer parameters conform to enterprise data egress baseline.');
      }
    }

    return { decision, reasons, totalSizeMb, sensitiveCount };
  }

  // Execute USB Transfer with simulated DLP Encryption on PROTECT
  public requestUSBTransfer(
    userId: number,
    deviceIdStr: string,
    files: { name: string; sizeMb: number; sensitive: boolean; type: string }[]
  ): USBTransferRequest {
    const user = this.users.find((u) => u.id === userId) || this.users[0];
    let device = this.usbDevices.find((d) => d.deviceId === deviceIdStr);

    if (!device) {
      device = {
        id: this.usbDevices.length + 1,
        deviceId: deviceIdStr,
        deviceName: 'Generic USB Storage',
        vendor: 'Unknown Vendor',
        serialNumber: `SN-GEN-${Date.now().toString(36).toUpperCase()}`,
        capacityGb: 32,
        userId: user.id,
        username: user.username,
        authorized: false,
        status: 'BLOCKED',
        insertedAt: new Date().toISOString(),
        createdAt: new Date().toISOString(),
      };
      this.usbDevices.unshift(device);
    }

    const { decision, reasons, totalSizeMb, sensitiveCount } = this.evaluateUSBTransferPolicy(device, files);

    // Process simulated protected file hashes if decision is PROTECT
    const processedFiles = files.map((f) => ({
      ...f,
      protectedHash:
        decision === 'PROTECT'
          ? `AES256-GCM-${Math.random().toString(36).substring(2, 10).toUpperCase()}-QSEC`
          : undefined,
    }));

    const transfer: USBTransferRequest = {
      id: this.usbTransfers.length + 1,
      transferId: `TR-${Math.random().toString(36).substring(2, 8).toUpperCase()}`,
      deviceId: device.deviceId,
      deviceName: device.deviceName,
      userId: user.id,
      username: user.username,
      totalSizeMb,
      fileCount: files.length,
      sensitiveFileCount: sensitiveCount,
      files: processedFiles,
      decision,
      reasons,
      requestedAt: new Date().toISOString(),
    };

    this.usbTransfers.unshift(transfer);

    // Log the event into the SIEM pipeline
    const logSeverity: Severity = decision === 'BLOCK' ? 'CRITICAL' : decision === 'PROTECT' ? 'HIGH' : 'LOW';

    this.ingestLog({
      timestamp: transfer.requestedAt,
      userId: user.id,
      username: user.username,
      source: 'usb-monitor',
      eventType: 'USB_TRANSFER_REQUEST',
      action: `USB_TRANSFER_${decision}`,
      resource: files.map((f) => f.name).join(', '),
      deviceId: device.deviceId,
      ipAddress: user.ipAddress,
      severity: logSeverity,
      details: {
        transfer_id: transfer.transferId,
        total_size_mb: totalSizeMb,
        file_count: files.length,
        sensitive_file_count: sensitiveCount,
        decision,
        authorized: device.authorized,
        reasons,
      },
    });

    this.recordAudit(
      user.username,
      'USB_TRANSFER_EVALUATION',
      `device:${device.deviceId}`,
      `Decision: ${decision} for ${files.length} file(s) (${totalSizeMb.toFixed(1)}MB). Reasons: ${reasons.join('; ')}`
    );

    return transfer;
  }

  // 1. Log Ingestion & Normalization
  public ingestLog(rawLog: Omit<SecurityLog, 'id'>): { log: SecurityLog; event: NormalizedEvent } {
    const logId = this.logs.length + 1;
    const eventId = this.events.length + 1;
    const nowIso = rawLog.timestamp || new Date().toISOString();

    // User resolution
    let uId = rawLog.userId;
    let uName = rawLog.username;
    if (uId && !uName) {
      const u = this.users.find((user) => user.id === uId);
      if (u) uName = u.username;
    } else if (uName && !uId) {
      const u = this.users.find((user) => user.username === uName);
      if (u) uId = u.id;
    }

    const log: SecurityLog = {
      ...rawLog,
      id: logId,
      timestamp: nowIso,
      userId: uId,
      username: uName,
    };
    this.logs.unshift(log);

    const event: NormalizedEvent = {
      id: eventId,
      logId: log.id,
      userId: uId,
      username: uName,
      eventType: log.eventType,
      timestamp: nowIso,
      normalizedData: {
        action: log.action,
        resource: log.resource,
        severity: log.severity,
        deviceId: log.deviceId,
        ipAddress: log.ipAddress,
        ...log.details,
      },
      processed: false,
      createdAt: nowIso,
    };
    this.events.unshift(event);

    // 2. Pass through Rule Engine
    const newFindings = this.evaluateRulesForEvent(event);

    // 3. Recalculate Risk Score for user if findings or user exists
    if (uId) {
      this.recalculateRisk(uId);
      this.recalculateMLAnomaly(uId);
      this.correlateAlertsForUser(uId);
    }

    this.notify('NEW_EVENT', { event, findings: newFindings });
    return { log, event };
  }

  // 2. Centralized Rule Engine (Phase 9)
  public evaluateRulesForEvent(event: NormalizedEvent): Finding[] {
    const matchedFindings: Finding[] = [];
    const isFailedEvent = isFailedLoginEvent(event);
    const activeRules = this.rules.filter((r) => {
      if (!r.enabled) return false;
      if (r.eventType === event.eventType) return true;
      if (
        (r.ruleCode === 'MULTIPLE_FAILED_LOGINS' || r.eventType === 'FAILED_LOGIN') &&
        isFailedEvent
      ) {
        return true;
      }
      if (
        r.eventType === 'FILE_ACCESS' &&
        ['FILE_ACCESS', 'SENSITIVE_FILE_ACCESS', 'FILE_DOWNLOAD', 'FILE_UPLOAD'].includes(event.eventType)
      ) {
        return true;
      }
      return false;
    });
    const eventData: Record<string, any> = { ...event.normalizedData, severity: event.normalizedData.severity };

    for (const rule of activeRules) {
      let isMatch = true;

      // Regular conditions
      if (rule.conditions && rule.conditions.length > 0) {
        for (const cond of rule.conditions) {
          let actualVal = eventData[cond.field];
          if (actualVal === undefined) {
            if (cond.field === 'sizeMb' || cond.field === 'file_size_mb' || cond.field === 'size_mb') {
              actualVal =
                eventData.sizeMb ??
                eventData.file_size_mb ??
                eventData.size_mb ??
                eventData.total_size_mb ??
                eventData.totalSizeMb;
            } else if (cond.field === 'total_size_mb' || cond.field === 'totalSizeMb') {
              actualVal =
                eventData.total_size_mb ??
                eventData.totalSizeMb ??
                eventData.sizeMb ??
                eventData.file_size_mb;
            }
          }
          if (!evaluateOperator(actualVal, cond.operator, cond.value)) {
            isMatch = false;
            break;
          }
        }
      }

      if (rule.ruleCode === 'UNAUTHORIZED_ACCESS' || rule.ruleCode === 'RULE-002') {
        isMatch = isUnauthorizedAccessEvent(event);
      }

      // Temporal rules (e.g. MULTIPLE_FAILED_LOGINS, REPEATED_SENSITIVE_ACCESS)
      const targetUserId = event.userId || this.users.find((u) => u.username === event.username || u.employeeId === event.username)?.id;
      if (rule.isTemporal && rule.temporalConfig) {
        if (!targetUserId && !event.username) {
          isMatch = false;
        } else {
          const { countThreshold, windowMinutes } = rule.temporalConfig;
          const curTime = new Date(event.timestamp || Date.now()).getTime();
          const windowStart = new Date(curTime - windowMinutes * 60 * 1000);

          const matchingCount = this.events.filter((e) => {
            let matchesUser = false;
            if (targetUserId && e.userId) {
              matchesUser = e.userId === targetUserId;
            } else if (targetUserId && !e.userId && event.username && e.username) {
              matchesUser = e.username.toLowerCase() === event.username.toLowerCase();
            } else if (!targetUserId && event.username && e.username) {
              matchesUser = e.username.toLowerCase() === event.username.toLowerCase();
            }
            if (!matchesUser) return false;

            const eTime = new Date(e.timestamp).getTime();
            if (isNaN(eTime) || eTime < windowStart.getTime() || eTime > curTime) return false;

            if (rule.ruleCode === 'MULTIPLE_FAILED_LOGINS' || rule.eventType === 'FAILED_LOGIN') {
              return isFailedLoginEvent(e);
            }
            if (rule.ruleCode === 'REPEATED_SENSITIVE_ACCESS') {
              const cls = e.normalizedData?.classification;
              return ['CONFIDENTIAL', 'RESTRICTED', 'SENSITIVE', 'HIGHLY_CONFIDENTIAL'].includes(cls);
            }
            if (rule.eventType === 'FILE_ACCESS') {
              return ['FILE_ACCESS', 'SENSITIVE_FILE_ACCESS', 'FILE_DOWNLOAD', 'FILE_UPLOAD'].includes(e.eventType);
            }
            return e.eventType === rule.eventType;
          }).length;

          if (matchingCount < countThreshold) {
            isMatch = false;
          }
        }
      }

      const resolvedUserId = targetUserId || event.userId || 0;
      if (isMatch && (resolvedUserId || event.username)) {
        // Prevent duplicate finding for same event & rule
        const alreadyExists = this.findings.some(
          (f) => f.ruleId === rule.id && f.eventId === event.id
        );
        if (!alreadyExists) {
          const userObj = this.users.find((u) => u.id === resolvedUserId);
          const empId = userObj?.employeeId || event.username || `EMP-${resolvedUserId}`;

          let findingReason = `Rule [${rule.ruleCode}] triggered: ${rule.description}`;
          if (rule.ruleCode === 'MULTIPLE_FAILED_LOGINS' || rule.ruleCode === 'RULE-001') {
            const count = this.events.filter((e) => {
              let matchesUser = false;
              if (resolvedUserId && e.userId) {
                matchesUser = e.userId === resolvedUserId;
              } else if (resolvedUserId && !e.userId && event.username && e.username) {
                matchesUser = e.username.toLowerCase() === event.username.toLowerCase();
              } else if (!resolvedUserId && event.username && e.username) {
                matchesUser = e.username.toLowerCase() === event.username.toLowerCase();
              }
              if (!matchesUser) return false;
              const curTime = new Date(event.timestamp || Date.now()).getTime();
              const windowStart = curTime - (rule.temporalConfig?.windowMinutes || 10) * 60 * 1000;
              const eTime = new Date(e.timestamp).getTime();
              return !isNaN(eTime) && eTime >= windowStart && eTime <= curTime && isFailedLoginEvent(e);
            }).length;

            findingReason = `${count || rule.temporalConfig?.countThreshold || 5} failed login attempts detected for ${empId} within ${rule.temporalConfig?.windowMinutes || 10} minutes.`;
          } else if (rule.ruleCode === 'UNAUTHORIZED_ACCESS' || rule.ruleCode === 'RULE-002') {
            const resTarget =
              event.normalizedData?.resource ||
              event.normalizedData?.details?.resource ||
              event.normalizedData?.action ||
              'PROTECTED_RESOURCE';
            const role =
              event.normalizedData?.userRole ||
              event.normalizedData?.details?.userRole ||
              userObj?.role ||
              'EMPLOYEE';
            findingReason = `User ${empId} (Role: ${role}) attempted unauthorized access to resource: ${resTarget}`;
          }

          const finding: Finding = {
            id: this.findings.length + 1,
            ruleId: rule.id,
            ruleCode: rule.ruleCode,
            ruleName:
              rule.ruleCode === 'MULTIPLE_FAILED_LOGINS'
                ? 'Multiple Failed Logins'
                : rule.ruleCode === 'UNAUTHORIZED_ACCESS' || rule.ruleCode === 'RULE-002'
                ? 'Unauthorized Access'
                : rule.name,
            eventId: event.id,
            userId: resolvedUserId,
            username: event.username || userObj?.username || `user-${resolvedUserId}`,
            severity: rule.severity,
            riskWeight: rule.riskWeight,
            reason: findingReason,
            metadata: {
              ruleId:
                rule.ruleCode === 'MULTIPLE_FAILED_LOGINS'
                  ? 'RULE-001'
                  : rule.ruleCode === 'UNAUTHORIZED_ACCESS' || rule.ruleCode === 'RULE-002'
                  ? 'RULE-002'
                  : `RULE-${rule.id}`,
              employeeId: empId,
              ...eventData,
            },
            status: 'OPEN',
            createdAt: event.timestamp,
          };
          this.findings.unshift(finding);
          matchedFindings.push(finding);
        }
      }
    }

    event.processed = true;
    return matchedFindings;
  }

  // 3. User Risk Scoring Engine with Time Decay (Phase 10)
  public recalculateRisk(userId: number): RiskScore {
    const user = this.users.find((u) => u.id === userId);
    const username = user ? user.username : `user-${userId}`;
    const windowStart = new Date(Date.now() - RISK_WINDOW_HOURS * 60 * 60 * 1000);

    const userFindings = this.findings.filter(
      (f) => f.userId === userId && new Date(f.createdAt) >= windowStart
    );

    let rawScore = 0;
    const breakdown: Record<string, number> = {};

    for (const f of userFindings) {
      const decay = calculateDecayFactor(f.createdAt);
      const contribution = f.riskWeight * decay;
      rawScore += contribution;
      breakdown[f.ruleCode] = Number(((breakdown[f.ruleCode] || 0) + contribution).toFixed(1));
    }

    const finalScore = Number(Math.min(rawScore, 100).toFixed(1));
    const riskLevel = getRiskLevel(finalScore);

    const scoreRecord: RiskScore = {
      id: this.riskHistory.length + 1,
      userId,
      username,
      ruleScore: finalScore,
      mlScore: this.anomalies.get(userId)?.anomalyScore || 0,
      behaviorScore: finalScore,
      finalScore,
      riskLevel,
      contributingFindingsCount: userFindings.length,
      scoreBreakdown: breakdown,
      calculationWindowStart: windowStart.toISOString(),
      calculationWindowEnd: new Date().toISOString(),
      calculatedAt: new Date().toISOString(),
    };

    this.riskScores.set(userId, scoreRecord);
    this.riskHistory.unshift(scoreRecord);
    return scoreRecord;
  }

  // 4. ML Anomaly Detection Simulation (Isolation Forest / Feature Vector) (Phase 11)
  public recalculateMLAnomaly(userId: number): MLAnomaly {
    const user = this.users.find((u) => u.id === userId);
    const username = user ? user.username : `user-${userId}`;
    const window24h = new Date(Date.now() - 24 * 60 * 60 * 1000);

    const userLogs = this.logs.filter((l) => l.userId === userId && new Date(l.timestamp) >= window24h);
    const userTransfers = this.usbTransfers.filter(
      (t) => t.userId === userId && new Date(t.requestedAt) >= window24h
    );
    const userFindings = this.findings.filter(
      (f) => f.userId === userId && new Date(f.createdAt) >= window24h
    );

    const features = {
      login_count: userLogs.filter((l) => l.eventType === 'LOGIN').length,
      failed_login_count: userLogs.filter((l) => l.eventType === 'FAILED_LOGIN').length,
      usb_insert_count: userLogs.filter((l) => l.eventType === 'USB_INSERT').length,
      usb_transfer_count: userTransfers.length,
      total_usb_mb: userTransfers.reduce((acc, t) => acc + t.totalSizeMb, 0),
      sensitive_access_count: userLogs.filter((l) => l.eventType === 'SENSITIVE_FILE_ACCESS').length,
      finding_count: userFindings.length,
    };

    // Isolation Forest anomaly estimation
    let rawAnomaly = 10; // Baseline
    const indicators: string[] = [];

    if (features.total_usb_mb > 500) {
      rawAnomaly += 35;
      indicators.push(`Exorbitant USB egress volume (${features.total_usb_mb.toFixed(0)} MB) deviates from 99th percentile.`);
    }
    if (features.failed_login_count >= 4) {
      rawAnomaly += 30;
      indicators.push(`High failed authentication burst (${features.failed_login_count} attempts) anomalous for identity baseline.`);
    }
    if (features.sensitive_access_count >= 3) {
      rawAnomaly += 25;
      indicators.push(`Unusual frequency of sensitive records access (${features.sensitive_access_count} files).`);
    }
    if (features.finding_count >= 3) {
      rawAnomaly += 20;
      indicators.push(`Multi-rule trigger velocity (${features.finding_count} security findings in 24h).`);
    }

    const anomalyScore = Math.min(Math.max(rawAnomaly, 5), 100);
    const anomalyLevel =
      anomalyScore >= 75 ? 'HIGH' : anomalyScore >= 50 ? 'MEDIUM' : anomalyScore >= 25 ? 'LOW' : 'NORMAL';

    const anomalyRecord: MLAnomaly = {
      id: (this.anomalies.get(userId)?.id || this.anomalies.size) + 1,
      userId,
      username,
      anomalyScore,
      anomalyLevel,
      modelVersion: this.mlVersion,
      featureSnapshot: features,
      indicators: indicators.length > 0 ? indicators : ['User behavioral telemetry within statistical baseline bounds.'],
      calculatedAt: new Date().toISOString(),
    };

    this.anomalies.set(userId, anomalyRecord);
    return anomalyRecord;
  }

  // 5. Alert Correlation Engine (Phase 12)
  public correlateAlertsForUser(userId: number) {
    const user = this.users.find((u) => u.id === userId);
    const username = user ? user.username : `user-${userId}`;
    const windowStart = new Date(Date.now() - CORRELATION_WINDOW_MINUTES * 60 * 1000);

    const recentFindings = this.findings.filter(
      (f) => f.userId === userId && new Date(f.createdAt) >= windowStart
    );

    const riskRecord = this.riskScores.get(userId);
    const mlRecord = this.anomalies.get(userId);
    const riskScore = riskRecord?.finalScore || 0;
    const mlScore = mlRecord?.anomalyScore || 0;

    if (recentFindings.length === 0 && riskScore < 45 && mlScore < 60) {
      return;
    }

    // Determine Severity
    let severity: Severity = 'LOW';
    const hasCriticalFinding = recentFindings.some((f) => f.severity === 'CRITICAL');
    const hasHighFinding = recentFindings.some((f) => f.severity === 'HIGH');

    if (riskScore >= 75 || (riskScore >= 65 && mlScore >= 70) || hasCriticalFinding) {
      severity = 'CRITICAL';
    } else if (riskScore >= 50 || mlScore >= 75 || hasHighFinding) {
      severity = 'HIGH';
    } else if (riskScore >= 25 || mlScore >= 50) {
      severity = 'MEDIUM';
    }

    // Rule 1: Multiple Failed Logins Dedicated Correlator
    const hasRule1 = recentFindings.some(
      (f) => f.ruleCode === 'MULTIPLE_FAILED_LOGINS' || f.ruleCode === 'RULE-001'
    );
    if (hasRule1) {
      const empId = user?.employeeId || `EMP-${userId}`;
      const userFailedEvents = this.events.filter((ev) => {
        let matchesUser = false;
        if (ev.userId && userId) {
          matchesUser = ev.userId === userId;
        } else if (!ev.userId && username && ev.username) {
          matchesUser = ev.username.toLowerCase() === username.toLowerCase();
        }
        return matchesUser && isFailedLoginEvent(ev);
      });

      const nowTime = Date.now();
      const window10m = nowTime - 10 * 60 * 1000;
      const recentFailedEvents = userFailedEvents.filter((ev) => {
        const t = new Date(ev.timestamp).getTime();
        return !isNaN(t) && t >= window10m;
      });

      const failedCount = recentFailedEvents.length >= 5 ? recentFailedEvents.length : Math.max(userFailedEvents.length, 5);
      const firstFailedTime = recentFailedEvents[0]?.timestamp || userFailedEvents[0]?.timestamp || new Date().toISOString();
      const latestFailedTime = recentFailedEvents[recentFailedEvents.length - 1]?.timestamp || userFailedEvents[userFailedEvents.length - 1]?.timestamp || new Date().toISOString();
      const sourceIp = recentFailedEvents[recentFailedEvents.length - 1]?.normalizedData?.ipAddress || user?.ipAddress || '192.168.100.250';

      const detectionReason = `${failedCount} failed login attempts detected for ${empId} within 10 minutes.`;

      const existingRule1Alert = this.alerts.find(
        (a) => (a.correlationKey === `RULE-001_${userId}` || a.title === 'Multiple Failed Logins') && a.status === 'OPEN'
      );

      const evidence = [
        `Rule ID: RULE-001`,
        `Rule Name: Multiple Failed Logins`,
        `User/Employee ID: ${empId}`,
        `Username: @${username}`,
        `Number of failed attempts: ${failedCount}`,
        `Detection window: 10 minutes`,
        `First failed-login timestamp: ${firstFailedTime}`,
        `Latest failed-login timestamp: ${latestFailedTime}`,
        `Source IP: ${sourceIp}`,
        `Detection reason: ${detectionReason}`,
      ];

      if (existingRule1Alert) {
        existingRule1Alert.lastSeen = latestFailedTime;
        existingRule1Alert.eventCount = failedCount;
        existingRule1Alert.findingCount = recentFindings.filter(
          (f) => f.ruleCode === 'MULTIPLE_FAILED_LOGINS' || f.ruleCode === 'RULE-001'
        ).length;
        existingRule1Alert.riskScore = riskScore;
        existingRule1Alert.mlAnomalyScore = mlScore;
        existingRule1Alert.description = detectionReason;
        existingRule1Alert.evidence = evidence;
        this.notify('ALERT_UPDATED', existingRule1Alert);
      } else {
        const rule1Alert: Alert = {
          id: this.alerts.length + 1,
          alertId: `ALT-RULE001-${userId}-${Date.now().toString(36).toUpperCase()}`,
          userId,
          username,
          userDepartment: user?.department,
          title: `Multiple Failed Logins`,
          description: detectionReason,
          severity: 'HIGH',
          status: 'OPEN',
          riskScore,
          mlAnomalyScore: mlScore,
          correlationKey: `RULE-001_${userId}`,
          firstSeen: firstFailedTime,
          lastSeen: latestFailedTime,
          eventCount: failedCount,
          findingCount: recentFindings.filter(
            (f) => f.ruleCode === 'MULTIPLE_FAILED_LOGINS' || f.ruleCode === 'RULE-001'
          ).length,
          evidence,
          recommendations: [
            'Temporarily lock account credentials pending MFA challenge',
            'Inspect origin IP subnet for credential stuffing / brute-force botnet signatures',
            `Contact employee @${username} (${empId}) to verify recent authentication activity`,
          ],
          policyViolations: ['RULE-001', 'AUTH-RATE-LIMIT', 'MULTIPLE_FAILED_LOGINS'],
          createdAt: new Date().toISOString(),
        };
        this.alerts.unshift(rule1Alert);
        this.notify('NEW_ALERT', rule1Alert);

        this.recordAudit(
          'SIEM_RULE_ENGINE',
          'RULE_TRIGGER_ALERT',
          `alert:${rule1Alert.alertId}`,
          `RULE-001 (Multiple Failed Logins) triggered: ${detectionReason}`
        );
      }
    }

    // 5b. Rule 2 (RULE-002: Unauthorized Access) Correlation
    const hasRule2 = recentFindings.some(
      (f) => f.ruleCode === 'UNAUTHORIZED_ACCESS' || f.ruleCode === 'RULE-002'
    );
    if (hasRule2) {
      const userObj = this.users.find((u) => u.id === userId);
      const empId = userObj?.employeeId || `EMP-${userId}`;
      const latestRule2Finding = recentFindings.find(
        (f) => f.ruleCode === 'UNAUTHORIZED_ACCESS' || f.ruleCode === 'RULE-002'
      );
      const resourceName =
        latestRule2Finding?.metadata?.resource ||
        latestRule2Finding?.metadata?.data?.resource ||
        'ADMIN_SETTINGS';
      const userRole =
        latestRule2Finding?.metadata?.data?.userRole ||
        userObj?.role ||
        'EMPLOYEE';

      const detectionReason = `User ${empId} (Role: ${userRole}) attempted unauthorized access to resource: ${resourceName}`;

      const existingRule2Alert = this.alerts.find(
        (a) => a.correlationKey === `RULE-002_${userId}` && a.status === 'OPEN'
      );

      const evidence = [
        `Rule ID: RULE-002`,
        `Rule Name: Unauthorized Access`,
        `User/Employee ID: ${empId}`,
        `Username: @${username}`,
        `User Role: ${userRole}`,
        `Attempted Target Resource: ${resourceName}`,
        `Risk Score Escalation: ${riskScore}/100`,
        `ML Anomaly Score: ${mlScore}/100`,
        `Detection Reason: ${detectionReason}`,
        `Enforcement Action: 403 Forbidden / Access Denied by Zero-Trust RBAC Layer`,
        `Timestamp: ${new Date().toISOString()}`,
      ];

      if (existingRule2Alert) {
        existingRule2Alert.lastSeen = new Date().toISOString();
        existingRule2Alert.eventCount = (existingRule2Alert.eventCount || 1) + 1;
        existingRule2Alert.findingCount = recentFindings.filter(
          (f) => f.ruleCode === 'UNAUTHORIZED_ACCESS' || f.ruleCode === 'RULE-002'
        ).length;
        existingRule2Alert.riskScore = riskScore;
        existingRule2Alert.mlAnomalyScore = mlScore;
        existingRule2Alert.description = detectionReason;
        existingRule2Alert.evidence = evidence;
        this.notify('ALERT_UPDATED', existingRule2Alert);
      } else {
        const rule2Alert: Alert = {
          id: this.alerts.length + 1,
          alertId: `ALT-RULE002-${userId}-${Date.now().toString(36).toUpperCase()}`,
          userId,
          username,
          userDepartment: user?.department,
          title: `Unauthorized Resource Access`,
          description: detectionReason,
          severity: 'HIGH',
          status: 'OPEN',
          riskScore,
          mlAnomalyScore: mlScore,
          correlationKey: `RULE-002_${userId}`,
          firstSeen: new Date().toISOString(),
          lastSeen: new Date().toISOString(),
          eventCount: 1,
          findingCount: recentFindings.filter(
            (f) => f.ruleCode === 'UNAUTHORIZED_ACCESS' || f.ruleCode === 'RULE-002'
          ).length,
          evidence,
          recommendations: [
            'Audit user permissions and check for lateral privilege escalation attempts.',
            'Confirm if employee requires role elevation or clearance adjustments.',
            'Immediately restrict account if suspicious lateral movement or API probing is observed.',
          ],
          policyViolations: ['RULE-002', 'RBAC-VIOLATION', 'UNAUTHORIZED_ACCESS'],
          createdAt: new Date().toISOString(),
        };
        this.alerts.unshift(rule2Alert);
        this.notify('NEW_ALERT', rule2Alert);

        this.recordAudit(
          'SIEM_RULE_ENGINE',
          'RULE_TRIGGER_ALERT',
          `alert:${rule2Alert.alertId}`,
          `RULE-002 (Unauthorized Access) triggered: ${detectionReason}`
        );
      }
    }

    // Check for open alert in correlation window for other activities
    const otherFindings = recentFindings.filter(
      (f) =>
        f.ruleCode !== 'MULTIPLE_FAILED_LOGINS' &&
        f.ruleCode !== 'RULE-001' &&
        f.ruleCode !== 'UNAUTHORIZED_ACCESS' &&
        f.ruleCode !== 'RULE-002'
    );
    if ((!hasRule1 && !hasRule2) || otherFindings.length > 0) {
      const existingAlert = this.alerts.find(
        (a) =>
          a.userId === userId &&
          a.status === 'OPEN' &&
          a.correlationKey !== `RULE-001_${userId}` &&
          a.correlationKey !== `RULE-002_${userId}` &&
          new Date(a.lastSeen) >= windowStart
      );

      const evidenceSet = new Set<string>();
      recentFindings.forEach((f) => evidenceSet.add(`Finding [${f.ruleCode}]: ${f.reason}`));
      if (mlScore >= 50) {
        evidenceSet.add(`ML Isolation Forest detected anomalous pattern (Anomaly Score: ${mlScore}/100)`);
      }

      const recommendations = [
        'Initiate SOC Level-2 triage and verify user identity credentials.',
        'Audit host filesystem and review DLP quarantine logs.',
        'Check if user has submitted approved change management / transfer authorization tickets.',
      ];
      if (severity === 'CRITICAL') {
        recommendations.unshift('URGENT: Temporarily isolate endpoint and suspend active SSO session.');
      }

      if (existingAlert) {
        existingAlert.lastSeen = new Date().toISOString();
        existingAlert.eventCount += 1;
        existingAlert.findingCount = recentFindings.length;
        existingAlert.riskScore = riskScore;
        existingAlert.mlAnomalyScore = mlScore;
        existingAlert.severity = severity;
        existingAlert.evidence = Array.from(evidenceSet);
        this.notify('ALERT_UPDATED', existingAlert);
      } else if (otherFindings.length > 0 || (riskScore >= 50 && !hasRule1 && !hasRule2)) {
        const newAlert: Alert = {
          id: this.alerts.length + 1,
          alertId: `ALT-${Math.random().toString(36).substring(2, 7).toUpperCase()}-${Date.now().toString(36).toUpperCase()}`,
          userId,
          username,
          userDepartment: user?.department,
          title: `Insider Threat: High-Risk Activity Detected (${username})`,
          description: `Correlated ${recentFindings.length} security finding(s) with user behavioral deviation. Risk Score: ${riskScore}, ML Anomaly: ${mlScore}.`,
          severity,
          status: 'OPEN',
          riskScore,
          mlAnomalyScore: mlScore,
          correlationKey: `CORR-U${userId}-${new Date().toISOString().substring(0, 13)}`,
          firstSeen: recentFindings[0]?.createdAt || new Date().toISOString(),
          lastSeen: new Date().toISOString(),
          eventCount: recentFindings.length,
          findingCount: recentFindings.length,
          evidence: Array.from(evidenceSet),
          recommendations,
          policyViolations: recentFindings.map((f) => f.ruleCode),
          createdAt: new Date().toISOString(),
        };
        this.alerts.unshift(newAlert);
        this.notify('NEW_ALERT', newAlert);

        this.recordAudit(
          'SYSTEM_CORRELATOR',
          'ALERT_GENERATION',
          `alert:${newAlert.alertId}`,
          `Generated ${severity} alert for user ${username}. Risk: ${riskScore}, Findings: ${recentFindings.length}`
        );
      }
    }
  }

  // Alert Actions
  public updateAlertStatus(alertId: string, status: AlertStatus, actorUsername: string): Alert | null {
    const alert = this.alerts.find((a) => a.alertId === alertId);
    if (!alert) return null;

    const oldStatus = alert.status;
    alert.status = status;
    alert.updatedAt = new Date().toISOString();
    if (status === 'RESOLVED' || status === 'FALSE_POSITIVE') {
      alert.resolvedAt = new Date().toISOString();
    }

    this.recordAudit(
      actorUsername,
      'ALERT_STATUS_UPDATE',
      `alert:${alertId}`,
      `Transitioned status from [${oldStatus}] to [${status}]`
    );

    this.notify('ALERT_UPDATED', alert);
    return alert;
  }

  // Device Authorization
  public toggleUSBAuthorization(deviceId: string, authorized: boolean, actorUsername: string): USBDevice | null {
    const device = this.usbDevices.find((d) => d.deviceId === deviceId);
    if (!device) return null;

    device.authorized = authorized;
    if (authorized && device.status === 'BLOCKED') {
      device.status = 'CONNECTED';
    }

    this.recordAudit(
      actorUsername,
      'USB_AUTH_OVERRIDE',
      `device:${deviceId}`,
      `Device authorization set to: ${authorized}`
    );

    return device;
  }

  // Audit Recorder
  public recordAudit(actor: string, action: string, resource: string, details: string) {
    const log: AuditLog = {
      id: this.auditLogs.length + 1,
      actor,
      action,
      resource,
      details,
      timestamp: new Date().toISOString(),
    };
    this.auditLogs.unshift(log);
  }

  // Summary Metrics
  public getSOCSummary(): SOCSummary {
    const now = Date.now();
    const dayAgo = now - 24 * 60 * 60 * 1000;
    const events24h = this.events.filter((e) => new Date(e.timestamp).getTime() >= dayAgo).length;

    const openAlerts = this.alerts.filter((a) => a.status === 'OPEN' || a.status === 'INVESTIGATING').length;
    const criticalAlerts = this.alerts.filter((a) => a.severity === 'CRITICAL' && a.status !== 'RESOLVED').length;

    let highRiskUsers = 0;
    let totalRisk = 0;
    this.riskScores.forEach((r) => {
      if (r.finalScore >= 50) highRiskUsers++;
      totalRisk += r.finalScore;
    });

    const avgRisk = this.riskScores.size > 0 ? Number((totalRisk / this.riskScores.size).toFixed(1)) : 0;

    const blocked = this.usbTransfers.filter((t) => t.decision === 'BLOCK').length;
    const protectedCount = this.usbTransfers.filter((t) => t.decision === 'PROTECT').length;
    const allowed = this.usbTransfers.filter((t) => t.decision === 'ALLOW').length;

    const activeAnomalies = Array.from(this.anomalies.values()).filter((a) => a.anomalyScore >= 50).length;

    return {
      totalEvents: this.events.length,
      events24h,
      openAlerts,
      criticalAlerts,
      highRiskUsers,
      avgRiskScore: avgRisk,
      usbTransfersBlocked: blocked,
      usbTransfersProtected: protectedCount,
      usbTransfersAllowed: allowed,
      activeMlAnomalies: activeAnomalies,
      rulesActive: this.rules.filter((r) => r.enabled).length,
    };
  }

  // Seed realistic demo logs, findings, and alerts on demand
  public seedDemoData() {
    // 1. Calculate baselines for all users
    this.users.forEach((u) => {
      this.recalculateMLAnomaly(u.id);
      this.recalculateRisk(u.id);
    });

    // 2. Ingest past events for Alex Mercer (Suspicious Rogue Insider)
    const baseTime = Date.now() - 1000 * 60 * 240; // 4 hours ago

    // Scenario 1: Multiple failed login attempts (4 rapid authentication failures)
    for (let i = 0; i < 4; i++) {
      this.ingestLog({
        timestamp: new Date(baseTime + i * 45000).toISOString(),
        userId: 101,
        username: 'amercer',
        source: 'auth-service',
        eventType: 'FAILED_LOGIN',
        action: 'AUTH_FAILED',
        resource: 'SSO-Enterprise-Gateway',
        ipAddress: '10.14.88.102',
        severity: 'MEDIUM',
        details: { failure_reason: 'Invalid Kerberos Token', attempt_count: i + 1, threshold: 3 },
      });
    }

    // Scenario 2: Login from an unusual location (External IP outside corporate geo-fence)
    this.ingestLog({
      timestamp: new Date(baseTime + 1000 * 60 * 60).toISOString(),
      userId: 101,
      username: 'amercer',
      source: 'auth-service',
      eventType: 'LOGIN',
      action: 'AUTH_SUCCESS_UNUSUAL_GEO',
      resource: 'Cloud-VPN-Gateway',
      ipAddress: '198.51.100.42',
      severity: 'HIGH',
      details: {
        geo_location: 'Kyiv, Ukraine',
        corporate_geofence: false,
        previous_known_ip: '10.14.88.102',
        anomaly: 'Unusual Geographical Origin',
      },
    });

    // Scenario 3: Unusual login time (Off-hours access at 03:14 AM UTC)
    this.ingestLog({
      timestamp: new Date(baseTime + 1000 * 60 * 90).toISOString(),
      userId: 101,
      username: 'amercer',
      source: 'endpoint-agent',
      eventType: 'LOGIN',
      action: 'OFF_HOURS_AUTH',
      resource: 'Workstation-Win11',
      ipAddress: '10.14.88.102',
      severity: 'MEDIUM',
      details: {
        login_hour_utc: '03:14:00',
        standard_shift_start: '09:00:00',
        is_off_hours: true,
        deviation_hours: 5.75,
      },
    });

    // Scenario 4: Sensitive file access (Accessing classified Executive M&A Strategy Document)
    this.ingestLog({
      timestamp: new Date(baseTime + 1000 * 60 * 120).toISOString(),
      userId: 101,
      username: 'amercer',
      source: 'endpoint-agent',
      eventType: 'SENSITIVE_FILE_ACCESS',
      action: 'FILE_READ_RESTRICTED',
      resource: '/vault/executive/M&A_Strategy_Document.pdf',
      ipAddress: '10.14.88.102',
      severity: 'HIGH',
      details: {
        file_id: 'f-ma-008',
        file_name: 'M&A_Strategy_Document.pdf',
        classification: 'HIGHLY_CONFIDENTIAL',
        size_mb: 800,
      },
    });

    // Scenario 5: Repeated access-denied events (3 unauthorized access attempts to restricted HR directory)
    for (let j = 0; j < 3; j++) {
      this.ingestLog({
        timestamp: new Date(baseTime + 1000 * 60 * 140 + j * 60000).toISOString(),
        userId: 101,
        username: 'amercer',
        source: 'iam-access-control',
        eventType: 'FILE_ACCESS',
        action: 'ACCESS_DENIED',
        resource: '/vault/hr/executive_compensation.csv',
        ipAddress: '10.14.88.102',
        severity: 'HIGH',
        details: {
          permission_required: 'EXECUTIVE_COMPENSATION_READ',
          attempt_index: j + 1,
          status: 'BLOCKED_BY_ACL',
        },
      });
    }

    // Scenario 6: Large file download (Bulk archive egress exceeding threshold)
    this.ingestLog({
      timestamp: new Date(baseTime + 1000 * 60 * 170).toISOString(),
      userId: 101,
      username: 'amercer',
      source: 'endpoint-agent',
      eventType: 'FILE_ACCESS',
      action: 'DOWNLOAD',
      resource: '/shares/rnd/source_code_archive.zip',
      ipAddress: '10.14.88.102',
      severity: 'HIGH',
      details: {
        file_id: 'f-source-007',
        file_name: 'source_code_archive.zip',
        sizeMb: 600,
        classification: 'INTERNAL',
        protocol: 'SFTP_PULL',
      },
    });

    // Scenario 7: Unauthorized USB insertion (USB/device activity)
    this.ingestLog({
      timestamp: new Date(baseTime + 1000 * 60 * 180).toISOString(),
      userId: 101,
      username: 'amercer',
      source: 'usb-monitor',
      eventType: 'USB_INSERT',
      action: 'DEVICE_ATTACHED',
      deviceId: 'USB-PERS-404',
      ipAddress: '10.14.88.102',
      severity: 'HIGH',
      details: {
        authorized: false,
        device_name: 'SanDisk Ultra Luxe (Personal)',
        vendor: 'SanDisk International',
      },
    });

    // Scenario 8: Abnormal data transfer (Attempted high-volume egress with confidential files to external drive)
    this.requestUSBTransfer(101, 'USB-PERS-404', [
      { name: 'M&A_Strategy_Document.pdf', sizeMb: 800, sensitive: true, type: 'application/pdf' },
      { name: 'financial_report_2026.xlsx', sizeMb: 35, sensitive: true, type: 'application/vnd.ms-excel' },
    ]);

    // Scenario 9: Privilege escalation (Attempted SUDO root elevation / sudoers modification)
    this.ingestLog({
      timestamp: new Date(baseTime + 1000 * 60 * 210).toISOString(),
      userId: 101,
      username: 'amercer',
      source: 'os-kernel-audit',
      eventType: 'PRIVILEGE_CHANGE',
      action: 'SUDO_PRIVILEGE_ELEVATION_ATTEMPT',
      resource: '/etc/sudoers.d/backdoor',
      ipAddress: '10.14.88.102',
      severity: 'CRITICAL',
      details: {
        command: 'sudo -s echo "amercer ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers',
        granted: false,
        escalation_target: 'ROOT_SUPERADMIN',
      },
    });

    // Authorized USB transfer for Sarah Chen (>500MB -> PROTECT)
    this.requestUSBTransfer(102, 'USB-APEX-092', [
      { name: 'database_backup_20260831.sql', sizeMb: 620, sensitive: false, type: 'application/sql' },
    ]);

    // Routine normal logs for David Kim
    this.ingestLog({
      timestamp: new Date(Date.now() - 1000 * 60 * 30).toISOString(),
      userId: 103,
      username: 'dkim',
      source: 'auth-service',
      eventType: 'LOGIN',
      action: 'AUTH_SUCCESS',
      resource: 'SOC-Console',
      ipAddress: '10.14.88.22',
      severity: 'LOW',
      details: { mfa_verified: true },
    });

    this.ingestLog({
      timestamp: new Date(Date.now() - 1000 * 60 * 20).toISOString(),
      userId: 103,
      username: 'dkim',
      source: 'endpoint-agent',
      eventType: 'FILE_ACCESS',
      action: 'READ_DOC',
      resource: '/docs/incident_response_sop_2026.pdf',
      ipAddress: '10.14.88.22',
      severity: 'LOW',
      details: { file_size_mb: 4.2 },
    });
  }

  // Predefined Attack Scenario Simulator
  public injectScenario(
    scenarioType: 'DISGRUNTLED_EXFIL' | 'BRUTE_FORCE' | 'MASS_DOWNLOAD' | 'PRIVILEGE_ESCALATION' | 'UNAUTHORIZED_ACCESS'
  ) {
    const targetUser = this.users.find((u) => u.username === 'amercer') || this.users[0] || SIMULATION_FALLBACK_USER;
    const now = new Date();

    if (scenarioType === 'DISGRUNTLED_EXFIL') {
      // Unauthorized USB attach
      this.ingestLog({
        timestamp: new Date(now.getTime() - 1000 * 60 * 5).toISOString(),
        userId: targetUser.id,
        username: targetUser.username,
        source: 'usb-monitor',
        eventType: 'USB_INSERT',
        action: 'DEVICE_ATTACHED',
        deviceId: 'USB-PERS-404',
        ipAddress: targetUser.ipAddress || '10.14.88.102',
        severity: 'HIGH',
        details: { authorized: false, device_name: 'SanDisk Rogue Flash', vendor: 'SanDisk' },
      });

      // Sensitive file accesses
      ['/vault/finance/M&A_Confidential_Brief.pdf', '/vault/rnd/Quantum_Algorithm_Seed.bin'].forEach(
        (resPath, idx) => {
          this.ingestLog({
            timestamp: new Date(now.getTime() - 1000 * 60 * (4 - idx)).toISOString(),
            userId: targetUser.id,
            username: targetUser.username,
            source: 'endpoint-agent',
            eventType: 'SENSITIVE_FILE_ACCESS',
            action: 'FILE_READ_RESTRICTED',
            resource: resPath,
            ipAddress: targetUser.ipAddress || '10.14.88.102',
            severity: 'HIGH',
            details: { classification: 'HIGHLY_CONFIDENTIAL', file_size_mb: 34.5, sizeMb: 34.5 },
          });
        }
      );

      // High volume USB transfer request (>500MB)
      this.requestUSBTransfer(targetUser.id, 'USB-PERS-404', [
        { name: 'M&A_Confidential_Brief.pdf', sizeMb: 34.5, sensitive: true, type: 'application/pdf' },
        { name: 'Quantum_Algorithm_Seed.bin', sizeMb: 520.0, sensitive: true, type: 'application/octet-stream' },
        { name: 'Customer_Master_Database_2026.csv', sizeMb: 110.0, sensitive: true, type: 'text/csv' },
      ]);
    } else if (scenarioType === 'BRUTE_FORCE') {
      for (let i = 0; i < 6; i++) {
        this.ingestLog({
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
      this.ingestLog({
        timestamp: now.toISOString(),
        userId: targetUser.id,
        username: targetUser.username,
        source: 'endpoint-agent',
        eventType: 'FILE_DOWNLOAD',
        action: 'DOWNLOAD',
        resource: '/share/corporate_archive_2026_full.tar.gz',
        ipAddress: targetUser.ipAddress || '10.14.88.102',
        severity: 'HIGH',
        details: { file_size_mb: 840.0, sizeMb: 840.0, classification: 'CONFIDENTIAL', protocol: 'SFTP' },
      });
    } else if (scenarioType === 'PRIVILEGE_ESCALATION') {
      this.ingestLog({
        timestamp: now.toISOString(),
        userId: targetUser.id,
        username: targetUser.username,
        source: 'server',
        eventType: 'PRIVILEGE_CHANGE',
        action: 'SUDO_PRIVILEGE_ELEVATION_ATTEMPT',
        resource: '/etc/sudoers.d/backdoor',
        ipAddress: targetUser.ipAddress || '10.14.88.102',
        severity: 'CRITICAL',
        details: {
          executed_by: targetUser.username,
          granted_role: 'ROOT_SUPERADMIN',
          command: 'sudo -s echo "amercer ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers',
        },
      });
    } else if (scenarioType === 'UNAUTHORIZED_ACCESS') {
      const empId = targetUser.employeeId || `EMP-${targetUser.id}`;
      const resource = '/api/admin/system/security-keys';
      const reason = `User ${empId} (Role: ${targetUser.role}) attempted unauthorized access to resource: ${resource}`;

      this.ingestLog({
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

      this.recordAudit(
        targetUser.username,
        'UNAUTHORIZED_ACCESS_ATTEMPT',
        resource,
        `Blocked 403 Forbidden: ${empId} (${targetUser.role}) attempted unauthorized access to ${resource}. Required: ADMIN`
      );
    }

    // Recalculate Risk, ML Anomaly, and correlate alerts
    this.recalculateRisk(targetUser.id);
    this.recalculateMLAnomaly(targetUser.id);
    this.correlateAlertsForUser(targetUser.id);
  }
}

// Global Singleton Instance
export const siemEngine = new SIEMEngine();
