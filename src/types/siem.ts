export type Severity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type UserRole = 'ADMIN' | 'SECURITY_ANALYST' | 'VIEWER' | 'EMPLOYEE';

export type UserStatus = 'ACTIVE' | 'DISABLED' | 'SUSPENDED';

export type AlertStatus = 'OPEN' | 'ACKNOWLEDGED' | 'INVESTIGATING' | 'RESOLVED' | 'FALSE_POSITIVE';

export type USBDecision = 'ALLOW' | 'BLOCK' | 'PROTECT';

export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type FileClassification =
  | 'PUBLIC'
  | 'INTERNAL'
  | 'CONFIDENTIAL'
  | 'RESTRICTED'
  | 'SENSITIVE'
  | 'HIGHLY_CONFIDENTIAL';

export type EventType =
  | 'LOGIN'
  | 'LOGOUT'
  | 'FAILED_LOGIN'
  | 'FILE_ACCESS'
  | 'SENSITIVE_FILE_ACCESS'
  | 'FILE_DOWNLOAD'
  | 'FILE_UPLOAD'
  | 'USB_INSERT'
  | 'USB_REMOVE'
  | 'USB_TRANSFER_REQUEST'
  | 'PRIVILEGE_CHANGE'
  | 'UNUSUAL_ACTIVITY'
  | 'SYSTEM_EVENT'
  | 'UNAUTHORIZED_ACCESS';

export interface DemoFile {
  id: string;
  name: string;
  sizeMb: number;
  classification: FileClassification;
  type: string;
  department: string;
  accessPermission: string;
  description: string;
  lastModified: string;
}

export interface FileActivityRecord {
  id: string;
  fileId: string;
  fileName: string;
  sizeMb: number;
  classification: FileClassification;
  action: 'OPEN' | 'VIEW' | 'DOWNLOAD' | 'REQUEST_ACCESS';
  timestamp: string;
  status: 'SUCCESS' | 'PENDING' | 'DENIED';
  userId: number;
  username: string;
}

export interface User {
  id: number;
  username: string;
  email: string;
  fullName: string;
  department: string;
  role: UserRole;
  status: UserStatus;
  createdAt: string;
  lastLogin?: string;
  ipAddress?: string;
  avatarUrl?: string;
  employeeId?: string;
  designation?: string;
  clearanceLevel?: string;
  mustChangePassword?: boolean;
  isManual?: boolean;
}

export interface SecurityLog {
  id: number;
  timestamp: string;
  userId?: number;
  username?: string;
  source: string; // 'endpoint-agent' | 'usb-monitor' | 'auth-service' | 'firewall' | 'demo-simulator'
  eventType: EventType;
  action: string;
  resource?: string;
  ipAddress?: string;
  deviceId?: string;
  location?: string;
  severity: Severity;
  details: Record<string, any>;
}

export interface NormalizedEvent {
  id: number;
  logId: number;
  userId?: number;
  username?: string;
  eventType: EventType;
  timestamp: string;
  normalizedData: {
    action: string;
    resource?: string;
    severity: Severity;
    [key: string]: any;
  };
  processed: boolean;
  createdAt: string;
}

export interface RuleCondition {
  field: string;
  operator: '==' | '!=' | '>' | '>=' | '<' | '<=' | 'contains' | 'in';
  value: any;
}

export interface Rule {
  id: number;
  ruleCode: string;
  name: string;
  description: string;
  eventType: EventType;
  severity: Severity;
  enabled: boolean;
  conditions: RuleCondition[];
  riskWeight: number;
  isTemporal?: boolean;
  temporalConfig?: {
    countThreshold: number;
    windowMinutes: number;
  };
  createdAt: string;
  updatedAt?: string;
}

export interface Finding {
  id: number;
  ruleId: number;
  ruleCode: string;
  ruleName: string;
  eventId: number;
  userId: number;
  username: string;
  severity: Severity;
  riskWeight: number;
  reason: string;
  metadata?: Record<string, any>;
  status: 'OPEN' | 'ACKNOWLEDGED' | 'RESOLVED';
  createdAt: string;
}

export interface RiskScoreBreakdown {
  [ruleCode: string]: number;
}

export interface RiskScore {
  id: number;
  userId: number;
  username: string;
  ruleScore: number;
  mlScore: number;
  behaviorScore: number;
  finalScore: number; // 0-100
  riskLevel: RiskLevel;
  contributingFindingsCount: number;
  scoreBreakdown: RiskScoreBreakdown;
  calculationWindowStart: string;
  calculationWindowEnd: string;
  calculatedAt: string;
}

export interface MLAnomaly {
  id: number;
  userId: number;
  username: string;
  anomalyScore: number; // 0-100
  anomalyLevel: 'NORMAL' | 'LOW' | 'MEDIUM' | 'HIGH';
  modelVersion: string;
  featureSnapshot: {
    login_count: number;
    failed_login_count: number;
    usb_insert_count: number;
    usb_transfer_count: number;
    total_usb_mb: number;
    sensitive_access_count: number;
    finding_count: number;
  };
  indicators: string[];
  calculatedAt: string;
}

export interface Alert {
  id: number;
  alertId: string;
  userId: number;
  username: string;
  userDepartment?: string;
  title: string;
  description: string;
  severity: Severity;
  status: AlertStatus;
  riskScore: number;
  mlAnomalyScore: number;
  correlationKey: string;
  firstSeen: string;
  lastSeen: string;
  eventCount: number;
  findingCount: number;
  assignedTo?: string;
  evidence: string[];
  recommendations: string[];
  policyViolations?: string[];
  createdAt: string;
  updatedAt?: string;
  resolvedAt?: string;
}

export interface USBDevice {
  id: number;
  deviceId: string;
  deviceName: string;
  vendor: string;
  serialNumber: string;
  capacityGb: number;
  userId?: number;
  username?: string;
  authorized: boolean;
  status: 'CONNECTED' | 'DISCONNECTED' | 'BLOCKED';
  insertedAt?: string;
  removedAt?: string;
  createdAt: string;
}

export interface USBTransferRequest {
  id: number;
  transferId: string;
  deviceId: string;
  deviceName: string;
  userId: number;
  username: string;
  totalSizeMb: number;
  fileCount: number;
  sensitiveFileCount: number;
  files: {
    name: string;
    sizeMb: number;
    sensitive: boolean;
    type: string;
    protectedHash?: string;
  }[];
  decision: USBDecision;
  reasons: string[];
  requestedAt: string;
}

export interface AuditLog {
  id: number;
  actor: string;
  userId?: number;
  action: string;
  resource: string;
  details: string;
  ipAddress?: string;
  timestamp: string;
}

export interface SOCSummary {
  totalEvents: number;
  events24h: number;
  openAlerts: number;
  criticalAlerts: number;
  highRiskUsers: number;
  avgRiskScore: number;
  usbTransfersBlocked: number;
  usbTransfersProtected: number;
  usbTransfersAllowed: number;
  activeMlAnomalies: number;
  rulesActive: number;
}
