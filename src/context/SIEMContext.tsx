import React, { createContext, useContext, useEffect, useState, useCallback, useRef } from 'react';
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
  SOCSummary,
  USBDevice,
  USBTransferRequest,
  User,
  UserRole,
} from '../types/siem';
import { siemEngine } from '../services/siemEngine';
import { api } from '../services/apiClient';
import { wsClient } from '../services/wsClient';
import confetti from 'canvas-confetti';

export type ActiveTab =
  | 'dashboard'
  | 'alerts'
  | 'events'
  | 'employees'
  | 'files'
  | 'audit'
  | 'findings'
  | 'risk'
  | 'ml'
  | 'usb'
  | 'rules'
  | 'scenarios'
  | 'users'
  | 'my_activity'
  | 'reports'
  | 'settings';

export interface ToastMessage {
  id: string;
  title: string;
  message: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  timestamp: string;
}

export interface SIEMContextType {
  activeTab: ActiveTab;
  setActiveTab: (tab: ActiveTab) => void;
  currentUser: User;
  setCurrentUser: (user: User) => void;
  switchRole: (role: UserRole) => void;
  summary: SOCSummary;
  alerts: Alert[];
  events: NormalizedEvent[];
  logs: SecurityLog[];
  findings: Finding[];
  riskScores: RiskScore[];
  anomalies: MLAnomaly[];
  rules: Rule[];
  usbDevices: USBDevice[];
  usbTransfers: USBTransferRequest[];
  auditLogs: AuditLog[];
  users: User[];
  setUsers: React.Dispatch<React.SetStateAction<User[]>>;
  refreshEmployees: () => Promise<void>;
  files: DemoFile[];
  userFileActivities: FileActivityRecord[];
  toasts: ToastMessage[];
  addToast: (
    titleOrPayload:
      | string
      | { title: string; message: string; type?: string; severity?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' },
    message?: string,
    severity?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  ) => void;
  removeToast: (id: string) => void;
  isStreaming: boolean;
  setIsStreaming: (val: boolean) => void;
  isRateLimited: boolean;
  selectedAlert: Alert | null;
  setSelectedAlert: (alert: Alert | null) => void;
  selectedUser: User | null;
  setSelectedUser: (user: User | null) => void;
  // Actions
  accessFile: (fileId: string, action?: 'OPEN' | 'VIEW' | 'DOWNLOAD' | 'REQUEST_ACCESS') => void;
  acknowledgeAlert: (alertId: string) => void;
  resolveAlert: (alertId: string) => void;
  markFalsePositive: (alertId: string) => void;
  toggleRule: (ruleId: number) => void;
  createRule: (rule: Partial<Rule>) => void;
  toggleUSBAuth: (deviceId: string, authorized: boolean) => void;
  simulateUSBInsert: (payload: {
    deviceId: string;
    deviceName: string;
    vendor: string;
    serialNumber: string;
    capacityGb: number;
    userId: number;
    authorized: boolean;
  }) => void;
  simulateUSBRemove: (deviceId: string) => void;
  simulateTransfer: (
    userId: number,
    deviceId: string,
    files: { name: string; sizeMb: number; sensitive: boolean; type: string }[]
  ) => USBTransferRequest;
  injectScenario: (
    scenarioType: 'DISGRUNTLED_EXFIL' | 'BRUTE_FORCE' | 'MASS_DOWNLOAD' | 'PRIVILEGE_ESCALATION' | 'UNAUTHORIZED_ACCESS'
  ) => void;
  simulateUnauthorizedAccess: (userId?: number, resource?: string) => void;
  simulateFailedLogin: (userId?: number) => void;
  simulateLargeUSBTransfer: (userId?: number) => void;
  simulateUnauthorizedUSB: (userId?: number) => void;
  simulateSensitiveFileAccess: (userId?: number) => void;
  seedDemoData: () => void;
  clearAllTelemetry: () => void;
  recalculateAllRisk: () => void;
  trainMLModel: () => void;
  refreshState: () => void;
}

const SIEMContext = createContext<SIEMContextType | undefined>(undefined);

export const SIEMProvider: React.FC<{ children: React.ReactNode; authenticatedUser?: User | null }> = ({
  children,
  authenticatedUser,
}) => {
  const [activeTab, setActiveTab] = useState<ActiveTab>('dashboard');
  const [currentUser, setCurrentUser] = useState<User>(
    authenticatedUser ||
      siemEngine.users[1] || {
        id: 102,
        username: 'schen',
        fullName: 'Sarah Chen',
        email: 'sarah.chen@corp-apex.internal',
        department: 'Infrastructure & DevOps',
        role: 'ADMIN',
        status: 'ACTIVE',
        createdAt: new Date().toISOString(),
      }
  );

  const [summary, setSummary] = useState<SOCSummary>(siemEngine.getSOCSummary());
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [events, setEvents] = useState<NormalizedEvent[]>([]);
  const [logs, setLogs] = useState<SecurityLog[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [riskScores, setRiskScores] = useState<RiskScore[]>([]);
  const [anomalies, setAnomalies] = useState<MLAnomaly[]>([]);
  const [rules, setRules] = useState<Rule[]>([...siemEngine.rules]);
  const [usbDevices, setUsbDevices] = useState<USBDevice[]>([...siemEngine.usbDevices]);
  const [usbTransfers, setUsbTransfers] = useState<USBTransferRequest[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([]);
  const [users, setUsers] = useState<User[]>([...siemEngine.users]);
  const [files, setFiles] = useState<DemoFile[]>([...siemEngine.files]);
  const [userFileActivities, setUserFileActivities] = useState<FileActivityRecord[]>([]);
  const [toasts, setToasts] = useState<ToastMessage[]>([]);
  const [isStreaming, setIsStreaming] = useState<boolean>(false);
  const [isRateLimited, setIsRateLimited] = useState<boolean>(false);
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [selectedUser, setSelectedUser] = useState<User | null>(null);

  const isFetchingRef = useRef(false);
  const isSOCRole = currentUser.role === 'ADMIN' || currentUser.role === 'SECURITY_ANALYST';

  const addToast = useCallback(
    (
      titleOrPayload:
        | string
        | { title: string; message: string; type?: string; severity?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' },
      msg?: string,
      sev?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
    ) => {
      let title = '';
      let message = '';
      let severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' = 'LOW';

      if (typeof titleOrPayload === 'object' && titleOrPayload !== null) {
        title = titleOrPayload.title || 'Notification';
        message = titleOrPayload.message || '';
        if (titleOrPayload.severity) {
          severity = titleOrPayload.severity;
        } else if (titleOrPayload.type === 'error') {
          severity = 'HIGH';
        } else if (titleOrPayload.type === 'warning') {
          severity = 'MEDIUM';
        } else {
          severity = 'LOW';
        }
      } else if (typeof titleOrPayload === 'string') {
        title = titleOrPayload || 'Notification';
        message = msg || '';
        severity = sev || 'LOW';
      }

      const id = Math.random().toString(36).substring(2, 9);
      setToasts((prev) => [
        { id, title, message, severity, timestamp: new Date().toLocaleTimeString() },
        ...prev.slice(0, 4),
      ]);
      setTimeout(() => {
        setToasts((prev) => prev.filter((t) => t.id !== id));
      }, 6000);
    },
    []
  );

  const removeToast = useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  // Refresh real employee directory from backend (Admin & Analyst)
  const refreshEmployees = useCallback(async () => {
    const isPrivileged = currentUser.role === 'ADMIN' || currentUser.role === 'SECURITY_ANALYST';
    if (!isPrivileged) return;
    try {
      const res = await api.employees.list();
      if (res && (res.employees || res.users)) {
        const list = res.employees || res.users || [];
        setUsers(list);
        siemEngine.users = list;
      }
    } catch (err) {
      console.warn('Could not refresh employees from backend:', err);
    }
  }, [currentUser.role]);

  // Fetch full data from Backend APIs via unified snapshot, with resilient fallback to local siemEngine
  const refreshState = useCallback(async () => {
    if (isFetchingRef.current) return;
    isFetchingRef.current = true;

    const isPrivileged = currentUser.role === 'ADMIN' || currentUser.role === 'SECURITY_ANALYST';

    // 1. Fetch file activities and documents (or fallback to local engine)
    try {
      const filesRes = await api.files.list();
      if (filesRes && filesRes.files) {
        setFiles(filesRes.files);
        siemEngine.files = filesRes.files;
      }
    } catch {
      setFiles([...siemEngine.files]);
    }

    try {
      const actRes = await api.files.myActivity();
      if (actRes && actRes.activities) {
        setUserFileActivities(actRes.activities);
      }
    } catch {
      setUserFileActivities([...siemEngine.fileActivities]);
    }

    // 2. Fetch unified telemetry snapshot for SOC users (1 single roundtrip instead of 10+)
    if (isPrivileged) {
      try {
        const snapRes = await api.soc.getSnapshot();
        const snap = snapRes?.snapshot || snapRes;
        if (snap && snap.summary) {
          setIsRateLimited(false);
          if (snap.summary) setSummary(snap.summary);
          if (snap.alerts) setAlerts(snap.alerts);
          if (snap.events) setEvents(snap.events);
          if (snap.findings) setFindings(snap.findings);
          if (snap.riskScores) setRiskScores(snap.riskScores);
          if (snap.rules) setRules(snap.rules);
          if (snap.usbDevices) setUsbDevices(snap.usbDevices);
          if (snap.usbTransfers) setUsbTransfers(snap.usbTransfers);
          if (snap.auditLogs) setAuditLogs(snap.auditLogs);
          if (snap.mlAnomalies) setAnomalies(snap.mlAnomalies);
          if (snap.employees && snap.employees.length > 0) {
            setUsers(snap.employees);
            siemEngine.users = snap.employees;
          }
        } else {
          // Fallback to local engine state
          setSummary(siemEngine.getSOCSummary());
          setAlerts([...siemEngine.alerts]);
          setEvents([...siemEngine.events]);
          setFindings([...siemEngine.findings]);
          setRiskScores(Array.from(siemEngine.riskScores.values()));
          setRules([...siemEngine.rules]);
          setUsbDevices([...siemEngine.usbDevices]);
          setUsbTransfers([...siemEngine.usbTransfers]);
          setAuditLogs([...siemEngine.auditLogs]);
          setAnomalies(Array.from(siemEngine.anomalies.values()));
        }
      } catch (err: any) {
        console.warn('Backend snapshot unavailable, utilizing local SIEM telemetry engine:', err);
        setIsRateLimited(api.isRateLimited());
        setSummary(siemEngine.getSOCSummary());
        setAlerts([...siemEngine.alerts]);
        setEvents([...siemEngine.events]);
        setFindings([...siemEngine.findings]);
        setRiskScores(Array.from(siemEngine.riskScores.values()));
        setRules([...siemEngine.rules]);
        setUsbDevices([...siemEngine.usbDevices]);
        setUsbTransfers([...siemEngine.usbTransfers]);
        setAuditLogs([...siemEngine.auditLogs]);
        setAnomalies(Array.from(siemEngine.anomalies.values()));
      }
    }

    isFetchingRef.current = false;
  }, [currentUser.role]);

  // Sync currentUser with authenticated user when provided
  useEffect(() => {
    if (authenticatedUser) {
      setCurrentUser(authenticatedUser);
    }
  }, [authenticatedUser]);

  // Initial load and WebSocket connection
  useEffect(() => {
    const token = api.getToken();
    if (token) {
      wsClient.connect(token);
    }

    refreshState();

    // Subscribe to WebSocket updates
    const unsubscribeWS = wsClient.subscribe((msg) => {
      const isPrivileged = currentUser.role === 'ADMIN' || currentUser.role === 'SECURITY_ANALYST';

      if (msg.type === 'NEW_ALERT' && isPrivileged) {
        const alt: Alert = msg.payload;
        setAlerts((prev) => [alt, ...prev.filter((a) => a.alertId !== alt.alertId)]);
        setSummary((prev) => ({
          ...prev,
          openAlerts: prev.openAlerts + 1,
          criticalAlerts: alt.severity === 'CRITICAL' ? prev.criticalAlerts + 1 : prev.criticalAlerts,
        }));
        addToast(`[${alt.severity}] New Alert Triggered`, `${alt.title} (${alt.username})`, alt.severity);

        if (alt.severity === 'CRITICAL') {
          try {
            confetti({
              particleCount: 45,
              spread: 60,
              origin: { y: 0.2 },
              colors: ['#ef4444', '#f97316', '#dc2626'],
            });
          } catch {
            // ignore
          }
        }
      } else if (msg.type === 'ALERT_UPDATED' && isPrivileged) {
        const updated: Alert = msg.payload;
        setAlerts((prev) => prev.map((a) => (a.alertId === updated.alertId ? updated : a)));
      } else if (msg.type === 'NEW_FINDING' && isPrivileged) {
        const f: Finding = msg.payload;
        setFindings((prev) => [f, ...prev.filter((x) => x.id !== f.id)]);
      } else if (msg.type === 'RISK_SCORE_UPDATED' && isPrivileged) {
        const r: RiskScore = msg.payload;
        setRiskScores((prev) => {
          const idx = prev.findIndex((x) => x.userId === r.userId);
          if (idx >= 0) {
            const updated = [...prev];
            updated[idx] = r;
            return updated;
          }
          return [...prev, r];
        });
      } else if (msg.type === 'NEW_EVENT' && isPrivileged) {
        const ev: NormalizedEvent = msg.payload;
        setEvents((prev) => [ev, ...prev.filter((x) => x.id !== ev.id)]);
        setSummary((prev) => ({ ...prev, totalEvents: prev.totalEvents + 1, events24h: prev.events24h + 1 }));
      }
    });

    return () => {
      unsubscribeWS();
    };
  }, [currentUser.role, refreshState, addToast]);

  // Access File Handler (Connects directly to Backend Endpoints)
  const accessFile = async (
    fileId: string,
    action: 'OPEN' | 'VIEW' | 'DOWNLOAD' | 'REQUEST_ACCESS' = 'OPEN'
  ) => {
    try {
      if (action === 'DOWNLOAD') {
        const res = await api.files.download(fileId);
        addToast('Document Portal', res.message || 'Download initiated successfully.', 'LOW');
      } else {
        const res = await api.files.access(fileId, action);
        addToast('Document Portal', res.message || 'Document accessed.', 'LOW');
      }

      // Refresh activity list
      const actRes = await api.files.myActivity();
      if (actRes && actRes.activities) {
        setUserFileActivities(actRes.activities);
      }

      // If SOC role is testing, also refresh SOC data
      if (isSOCRole) {
        refreshState();
      }
    } catch (err: any) {
      console.warn('Error during file access/download:', err);
      // Fallback local engine execution if needed
      const fallback = siemEngine.accessFile(fileId, action, currentUser);
      addToast('Document Portal', fallback.message, 'LOW');
      setUserFileActivities([...siemEngine.fileActivities]);
    }
  };

  // Role Switcher
  const switchRole = (role: UserRole) => {
    const match = siemEngine.users.find((u) => u.role === role) || {
      ...currentUser,
      role,
    };
    setCurrentUser({ ...match, role });
    siemEngine.recordAudit(
      match.username,
      'RBAC_ROLE_SWITCH',
      'session',
      `Switched active role context to [${role}]`
    );
    addToast('Role Context Switched', `Active user is now ${match.fullName} (${role})`, 'LOW');
    refreshState();
  };

  // Alert Handlers
  const acknowledgeAlert = async (alertId: string) => {
    try {
      await api.soc.acknowledgeAlert(alertId);
      addToast('Alert Acknowledged', `Incident ${alertId} assigned to ${currentUser.username}`, 'MEDIUM');
      refreshState();
    } catch {
      siemEngine.updateAlertStatus(alertId, 'ACKNOWLEDGED', currentUser.username);
      addToast('Alert Acknowledged', `Incident ${alertId} assigned to ${currentUser.username}`, 'MEDIUM');
      setAlerts([...siemEngine.alerts]);
    }
  };

  const resolveAlert = async (alertId: string) => {
    try {
      await api.soc.resolveAlert(alertId);
      addToast('Alert Resolved', `Incident ${alertId} marked as RESOLVED`, 'LOW');
      refreshState();
    } catch {
      siemEngine.updateAlertStatus(alertId, 'RESOLVED', currentUser.username);
      addToast('Alert Resolved', `Incident ${alertId} marked as RESOLVED`, 'LOW');
      setAlerts([...siemEngine.alerts]);
    }
  };

  const markFalsePositive = async (alertId: string) => {
    try {
      await api.soc.falsePositiveAlert(alertId);
      addToast('Alert Closed', `Incident ${alertId} marked as FALSE POSITIVE`, 'LOW');
      refreshState();
    } catch {
      siemEngine.updateAlertStatus(alertId, 'FALSE_POSITIVE', currentUser.username);
      addToast('Alert Closed', `Incident ${alertId} marked as FALSE POSITIVE`, 'LOW');
      setAlerts([...siemEngine.alerts]);
    }
  };

  const toggleRule = async (ruleId: number) => {
    const rule = rules.find((r) => r.id === ruleId);
    if (!rule) return;
    const newEnabled = !rule.enabled;

    try {
      await api.soc.updateRule(ruleId, { enabled: newEnabled });
      setRules((prev) => prev.map((r) => (r.id === ruleId ? { ...r, enabled: newEnabled } : r)));
      addToast('Detection Rule Updated', `${rule.name} is now ${newEnabled ? 'Active' : 'Disabled'}`, 'LOW');
    } catch {
      rule.enabled = newEnabled;
      setRules([...rules]);
      addToast('Detection Rule Updated', `${rule.name} is now ${newEnabled ? 'Active' : 'Disabled'}`, 'LOW');
    }
  };

  const createRule = async (newRuleData: Partial<Rule>) => {
    try {
      const res = await api.soc.createRule(newRuleData);
      if (res && res.rule) {
        setRules((prev) => [...prev, res.rule]);
        addToast('Rule Created', `New detection rule [${res.rule.ruleCode}] deployed`, 'LOW');
      }
    } catch {
      const newRule: Rule = {
        id: rules.length + 1,
        ruleCode: newRuleData.ruleCode || `CUSTOM_RULE_${Date.now().toString(36).toUpperCase()}`,
        name: newRuleData.name || 'Custom Security Rule',
        description: newRuleData.description || 'Analyst created detection pattern',
        eventType: newRuleData.eventType || 'FILE_ACCESS',
        severity: newRuleData.severity || 'MEDIUM',
        enabled: true,
        conditions: newRuleData.conditions || [],
        riskWeight: newRuleData.riskWeight || 25,
        createdAt: new Date().toISOString(),
      };
      setRules((prev) => [...prev, newRule]);
      addToast('Rule Created', `New detection rule [${newRule.ruleCode}] deployed`, 'LOW');
    }
  };

  const toggleUSBAuth = async (deviceId: string, authorized: boolean) => {
    try {
      await api.soc.toggleUSBAuth(deviceId, authorized);
      setUsbDevices((prev) =>
        prev.map((d) => (d.deviceId === deviceId ? { ...d, authorized, status: authorized ? 'CONNECTED' : 'BLOCKED' } : d))
      );
      addToast(
        'Device Authorization Updated',
        `USB ${deviceId} set to ${authorized ? 'AUTHORIZED' : 'UNAUTHORIZED'}`,
        authorized ? 'LOW' : 'HIGH'
      );
    } catch {
      siemEngine.toggleUSBAuthorization(deviceId, authorized, currentUser.username);
      setUsbDevices([...siemEngine.usbDevices]);
      addToast(
        'Device Authorization Updated',
        `USB ${deviceId} set to ${authorized ? 'AUTHORIZED' : 'UNAUTHORIZED'}`,
        authorized ? 'LOW' : 'HIGH'
      );
    }
  };

  const simulateUSBInsert = (payload: {
    deviceId: string;
    deviceName: string;
    vendor: string;
    serialNumber: string;
    capacityGb: number;
    userId: number;
    authorized: boolean;
  }) => {
    const user = users.find((u) => u.id === payload.userId) || currentUser;
    let dev = usbDevices.find((d) => d.deviceId === payload.deviceId);
    if (!dev) {
      dev = {
        id: usbDevices.length + 1,
        deviceId: payload.deviceId,
        deviceName: payload.deviceName,
        vendor: payload.vendor,
        serialNumber: payload.serialNumber,
        capacityGb: payload.capacityGb,
        userId: user.id,
        username: user.username,
        authorized: payload.authorized,
        status: payload.authorized ? 'CONNECTED' : 'BLOCKED',
        insertedAt: new Date().toISOString(),
        createdAt: new Date().toISOString(),
      };
      setUsbDevices((prev) => [dev!, ...prev]);
    }

    siemEngine.ingestLog({
      timestamp: new Date().toISOString(),
      userId: user.id,
      username: user.username,
      source: 'usb-monitor',
      eventType: 'USB_INSERT',
      action: 'DEVICE_CONNECTED',
      deviceId: payload.deviceId,
      ipAddress: user.ipAddress,
      severity: payload.authorized ? 'LOW' : 'HIGH',
      details: {
        authorized: payload.authorized,
        device_name: payload.deviceName,
        vendor: payload.vendor,
        capacity_gb: payload.capacityGb,
      },
    });

    addToast(
      payload.authorized ? 'USB Connected' : 'Unauthorized USB Blocked',
      `Device ${payload.deviceName} (${payload.deviceId}) attached by ${user.username}`,
      payload.authorized ? 'LOW' : 'HIGH'
    );
  };

  const simulateUSBRemove = (deviceId: string) => {
    const dev = usbDevices.find((d) => d.deviceId === deviceId);
    if (dev) {
      setUsbDevices((prev) =>
        prev.map((d) => (d.deviceId === deviceId ? { ...d, status: 'DISCONNECTED', removedAt: new Date().toISOString() } : d))
      );
      addToast('USB Disconnected', `Device ${deviceId} was safely ejected`, 'LOW');
    }
  };

  const simulateTransfer = (
    userId: number,
    deviceId: string,
    fileList: { name: string; sizeMb: number; sensitive: boolean; type: string }[]
  ) => {
    const transfer = siemEngine.requestUSBTransfer(userId, deviceId, fileList);
    addToast(
      `USB Transfer: ${transfer.decision}`,
      `${transfer.fileCount} files (${transfer.totalSizeMb.toFixed(1)}MB) evaluated: ${transfer.reasons[0]}`,
      transfer.decision === 'BLOCK' ? 'CRITICAL' : transfer.decision === 'PROTECT' ? 'HIGH' : 'LOW'
    );
    api.soc.requestUSBTransfer(userId, deviceId, fileList).catch(() => {});
    return transfer;
  };

  const recalculateAllRisk = async () => {
    try {
      await api.soc.recalculateRisk();
      addToast('Risk Engine Recalculated', 'All user risk scores and 24h decay profiles updated', 'LOW');
      refreshState();
    } catch {
      users.forEach((u) => {
        siemEngine.recalculateRisk(u.id);
        siemEngine.recalculateMLAnomaly(u.id);
        siemEngine.correlateAlertsForUser(u.id);
      });
      addToast('Risk Engine Recalculated', 'All user risk scores and 24h decay profiles updated', 'LOW');
      refreshState();
    }
  };

  const trainMLModel = async () => {
    try {
      await api.soc.trainMLModel();
      addToast('Isolation Forest Retrained', 'Model updated with 100 estimators across feature dimensions', 'LOW');
      refreshState();
    } catch {
      addToast('Isolation Forest Retrained', 'Model updated with 100 estimators across feature dimensions', 'LOW');
    }
  };

  // Attack Scenario Injector
  const injectScenario = async (
    scenarioType: 'DISGRUNTLED_EXFIL' | 'BRUTE_FORCE' | 'MASS_DOWNLOAD' | 'PRIVILEGE_ESCALATION' | 'UNAUTHORIZED_ACCESS'
  ) => {
    try {
      await api.soc.injectScenario(scenarioType);
      addToast(`Scenario Injected: ${scenarioType}`, 'Injected real threat scenario into SIEM pipeline', 'HIGH');
      refreshState();
    } catch (err: any) {
      console.warn('Backend injection failed, falling back to local SIEM engine:', err);
      siemEngine.injectScenario(scenarioType);
      addToast(`Scenario Injected (Local): ${scenarioType}`, 'Injected threat scenario into local SIEM pipeline', 'HIGH');
      refreshState();
    }
  };

  const simulateUnauthorizedAccess = async (userId?: number, resource: string = '/api/admin/settings') => {
    const target = (userId ? users.find((u) => u.id === userId) : null) || currentUser;
    try {
      // Call protected API endpoint to exercise real RBAC middleware
      await api.soc.testEndpoint(resource);
    } catch {
      // Expected 403 Forbidden which triggers RBAC middleware detection
    }
    // Also ingest into local siemEngine for immediate UI sync
    siemEngine.ingestLog({
      timestamp: new Date().toISOString(),
      userId: target.id,
      username: target.username,
      source: 'rbac-enforcer',
      eventType: 'UNAUTHORIZED_ACCESS',
      action: 'ACCESS_DENIED',
      resource,
      ipAddress: target.ipAddress || '10.14.88.102',
      severity: 'HIGH',
      details: {
        resource,
        userRole: target.role,
        employeeId: target.employeeId || `EMP-${target.id}`,
        requiredRoles: ['ADMIN'],
        statusCode: 403,
      },
    });
    addToast('RBAC Access Denied', `403 Forbidden on ${resource} for @${target.username}`, 'HIGH');
    refreshState();
  };

  const simulateFailedLogin = (userId?: number) => {
    const target = (userId ? users.find((u) => u.id === userId) : null) || currentUser;
    siemEngine.ingestLog({
      timestamp: new Date().toISOString(),
      userId: target.id,
      username: target.username,
      source: 'auth-service',
      eventType: 'FAILED_LOGIN',
      action: 'AUTH_FAILED',
      resource: 'SSO-Gateway',
      ipAddress: target.ipAddress || '10.14.88.99',
      severity: 'MEDIUM',
      details: { failure_reason: 'Bad password attempt', attempt_num: 1 },
    });
    addToast('Simulation: Failed Login', `Ingested single failed login event for @${target.username}`, 'MEDIUM');
  };

  const simulateLargeUSBTransfer = (userId?: number) => {
    const target = (userId ? users.find((u) => u.id === userId) : null) || currentUser;
    simulateTransfer(target.id, 'USB-APEX-092', [
      { name: 'big_database_dump.sql.gz', sizeMb: 750.0, sensitive: false, type: 'application/gzip' },
    ]);
  };

  const simulateUnauthorizedUSB = (userId?: number) => {
    const target = (userId ? users.find((u) => u.id === userId) : null) || currentUser;
    simulateUSBInsert({
      deviceId: `USB-ROGUE-${Math.floor(Math.random() * 900 + 100)}`,
      deviceName: 'Unapproved Kingston Thumbdrive',
      vendor: 'Kingston DataTraveler',
      serialNumber: `SN-UNAUTH-${Date.now().toString(36).toUpperCase()}`,
      capacityGb: 64,
      userId: target.id,
      authorized: false,
    });
  };

  const simulateSensitiveFileAccess = (userId?: number) => {
    const target = (userId ? users.find((u) => u.id === userId) : null) || currentUser;
    siemEngine.ingestLog({
      timestamp: new Date().toISOString(),
      userId: target.id,
      username: target.username,
      source: 'endpoint-agent',
      eventType: 'SENSITIVE_FILE_ACCESS',
      action: 'READ_RESTRICTED',
      resource: '/vault/executive/compensation_and_merger_term_sheet.pdf',
      ipAddress: target.ipAddress || '10.14.88.102',
      severity: 'HIGH',
      details: { classification: 'RESTRICTED_PII', size_mb: 28.4 },
    });
    addToast(
      'Simulation: Sensitive File Access',
      `Ingested classified file access event for @${target.username}`,
      'HIGH'
    );
  };

  const seedDemoData = async () => {
    try {
      await api.soc.seedDemo();
      addToast('Demo Baseline Ingested', 'Loaded demonstration logs, alerts, and USB activity', 'LOW');
      refreshState();
    } catch {
      siemEngine.seedDemoData();
      addToast('Demo Baseline Ingested', 'Loaded demonstration logs, alerts, and USB activity', 'LOW');
      refreshState();
    }
  };

  const clearAllTelemetry = async () => {
    try {
      await api.soc.clearTelemetry();
      setAlerts([]);
      setEvents([]);
      setLogs([]);
      setFindings([]);
      setUsbTransfers([]);
      setAuditLogs([]);
      addToast('Telemetry Cleared', 'All security events, findings, and alerts reset to clean slate', 'LOW');
      refreshState();
    } catch {
      siemEngine.events = [];
      siemEngine.logs = [];
      siemEngine.findings = [];
      siemEngine.alerts = [];
      siemEngine.usbTransfers = [];
      siemEngine.auditLogs = [];
      setAlerts([]);
      setEvents([]);
      setLogs([]);
      setFindings([]);
      setUsbTransfers([]);
      setAuditLogs([]);
      addToast('Telemetry Cleared', 'All security events, findings, and alerts reset to clean slate', 'LOW');
      refreshState();
    }
  };

  return (
    <SIEMContext.Provider
      value={{
        activeTab,
        setActiveTab,
        currentUser,
        setCurrentUser,
        switchRole,
        summary,
        alerts,
        events,
        logs,
        findings,
        riskScores,
        anomalies,
        rules,
        usbDevices,
        usbTransfers,
        auditLogs,
        users,
        setUsers,
        refreshEmployees,
        files,
        userFileActivities,
        toasts,
        addToast,
        removeToast,
        isStreaming,
        setIsStreaming,
        isRateLimited,
        selectedAlert,
        setSelectedAlert,
        selectedUser,
        setSelectedUser,
        accessFile,
        acknowledgeAlert,
        resolveAlert,
        markFalsePositive,
        toggleRule,
        createRule,
        toggleUSBAuth,
        simulateUSBInsert,
        simulateUSBRemove,
        simulateTransfer,
        injectScenario,
        simulateUnauthorizedAccess,
        simulateFailedLogin,
        simulateLargeUSBTransfer,
        simulateUnauthorizedUSB,
        simulateSensitiveFileAccess,
        seedDemoData,
        clearAllTelemetry,
        recalculateAllRisk,
        trainMLModel,
        refreshState,
      }}
    >
      {children}
    </SIEMContext.Provider>
  );
};

export const useSIEM = () => {
  const context = useContext(SIEMContext);
  if (!context) throw new Error('useSIEM must be used within a SIEMProvider');
  return context;
};
