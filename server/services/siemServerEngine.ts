import { db, DBUser } from '../db/database';
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
} from '../../src/types/siem';
import { wsManager } from './wsServer';
import { isFailedLoginEvent, isUnauthorizedAccessEvent } from '../../src/utils/siemRules';
import { demoDataset, SEVEN_DETECTION_RULES } from './demoDatasetService';

export const USB_TRANSFER_THRESHOLD_MB = parseInt(process.env.USB_TRANSFER_THRESHOLD_MB || '500', 10);
export const LARGE_FILE_THRESHOLD_MB = parseInt(process.env.LARGE_FILE_THRESHOLD_MB || '500', 10);
export const CORRELATION_WINDOW_MINUTES = 30;
export const RISK_WINDOW_HOURS = 24;

export class SIEMServerEngine {
  private static instance: SIEMServerEngine;

  public mlTrained: boolean = true;
  public mlVersion: string = 'iforest-v1.4';

  private constructor() {}

  public static getInstance(): SIEMServerEngine {
    if (!SIEMServerEngine.instance) {
      SIEMServerEngine.instance = new SIEMServerEngine();
    }
    return SIEMServerEngine.instance;
  }

  // -------------------------------------------------------------
  // 1. Log Ingestion & Normalization
  // -------------------------------------------------------------
  public ingestLog(rawLog: Omit<SecurityLog, 'id'>): {
    log: SecurityLog;
    event: NormalizedEvent;
    findings: Finding[];
  } {
    const logId = db.getSecurityLogs().length + 1;
    const log: SecurityLog = {
      ...rawLog,
      id: logId,
    };
    db.addSecurityLog(log);

    // Normalize
    const eventId = db.getNormalizedEvents().length + 1;
    const normalized: NormalizedEvent = {
      id: eventId,
      logId: log.id,
      userId: log.userId,
      username: log.username,
      eventType: log.eventType,
      timestamp: log.timestamp,
      normalizedData: {
        action: log.action,
        resource: log.resource,
        severity: log.severity,
        ipAddress: log.ipAddress,
        deviceId: log.deviceId,
        location: log.location,
        ...log.details,
      },
      processed: false,
      createdAt: new Date().toISOString(),
    };
    db.addNormalizedEvent(normalized);

    // Broadcast normalized event to SOC Admin WebSocket
    wsManager.broadcastNewEvent(normalized);

    // Resolve userId if missing but username is provided
    if (!normalized.userId && normalized.username) {
      const u = db.getUserByUsername(normalized.username) || db.getUserByEmployeeId(normalized.username);
      if (u) {
        normalized.userId = u.id;
      }
    }

    // Evaluate Rules
    const findings = this.evaluateRulesForEvent(normalized);
    normalized.processed = true;

    // Trigger Risk & Alert Correlation
    if (normalized.userId) {
      this.recalculateRisk(normalized.userId);
      this.recalculateMLAnomaly(normalized.userId);
      if (findings.length > 0) {
        this.correlateAlertsForUser(normalized.userId);
      }
    }

    return { log, event: normalized, findings };
  }

  // -------------------------------------------------------------
  // 2. Rule Evaluation Engine
  // -------------------------------------------------------------
  public evaluateRulesForEvent(event: NormalizedEvent): Finding[] {
    const findings: Finding[] = [];
    const activeRules = db.getRules().filter((r) => {
      if (!r.enabled) return false;
      if (r.eventType === event.eventType) return true;
      if (
        (r.ruleCode === 'MULTIPLE_FAILED_LOGINS' || r.eventType === 'FAILED_LOGIN') &&
        isFailedLoginEvent(event)
      ) {
        return true;
      }
      if (
        (r.ruleCode === 'UNAUTHORIZED_ACCESS' || r.ruleCode === 'RULE-002' || r.eventType === 'UNAUTHORIZED_ACCESS') &&
        isUnauthorizedAccessEvent(event)
      ) {
        return true;
      }
      return false;
    });

    for (const rule of activeRules) {
      let matched = false;

      if (rule.ruleCode === 'UNAUTHORIZED_ACCESS' || rule.ruleCode === 'RULE-002') {
        matched = isUnauthorizedAccessEvent(event);
      } else if (rule.isTemporal && rule.temporalConfig) {
        matched = this.evaluateTemporalRule(rule, event);
      } else {
        matched = this.evaluateSimpleConditions(rule.conditions, event.normalizedData);
      }

      if (matched) {
        const targetUserId = event.userId || 0;
        const userObj = targetUserId ? db.getUserById(targetUserId) : (event.username ? (db.getUserByUsername(event.username) || db.getUserByEmployeeId(event.username)) : null);
        const resolvedUserId = userObj ? userObj.id : targetUserId;
        const empId = userObj?.employeeId || event.username || (resolvedUserId ? `EMP-${resolvedUserId}` : 'UNKNOWN');

        let findingReason = `Matched detection rule [${rule.ruleCode}]: ${rule.description}`;
        if (rule.ruleCode === 'MULTIPLE_FAILED_LOGINS') {
          const windowMinutes = rule.temporalConfig?.windowMinutes || 10;
          const curTime = new Date(event.timestamp || Date.now()).getTime();
          const windowStart = curTime - windowMinutes * 60 * 1000;

          const recentCount = db.getNormalizedEvents().filter((ev) => {
            let evMatchesUser = false;
            if (resolvedUserId && ev.userId) {
              evMatchesUser = ev.userId === resolvedUserId;
            } else if (resolvedUserId && !ev.userId && event.username && ev.username) {
              evMatchesUser = ev.username.toLowerCase() === event.username.toLowerCase();
            } else if (!resolvedUserId && event.username && ev.username) {
              evMatchesUser = ev.username.toLowerCase() === event.username.toLowerCase();
            }
            if (!evMatchesUser) return false;
            const t = new Date(ev.timestamp).getTime();
            return !isNaN(t) && t >= windowStart && t <= curTime && isFailedLoginEvent(ev);
          }).length;

          findingReason = `${recentCount || rule.temporalConfig?.countThreshold || 5} failed login attempts detected for ${empId} within ${windowMinutes} minutes.`;
        } else if (rule.ruleCode === 'UNAUTHORIZED_ACCESS' || rule.ruleCode === 'RULE-002') {
          const resource = event.normalizedData?.resource || event.normalizedData?.details?.resource || 'PROTECTED_RESOURCE';
          const userRole = event.normalizedData?.userRole || event.normalizedData?.details?.userRole || userObj?.role || 'EMPLOYEE';
          findingReason = `User ${empId} (Role: ${userRole}) attempted unauthorized access to resource: ${resource}`;
        }

        const finding: Finding = {
          id: db.getFindings().length + 1,
          ruleId: rule.id,
          ruleCode: rule.ruleCode,
          ruleName: rule.ruleCode === 'MULTIPLE_FAILED_LOGINS' ? 'Multiple Failed Logins' : (rule.ruleCode === 'UNAUTHORIZED_ACCESS' || rule.ruleCode === 'RULE-002') ? 'Unauthorized Access' : rule.name,
          eventId: event.id,
          userId: resolvedUserId,
          username: event.username || userObj?.username || 'unknown',
          severity: rule.severity,
          riskWeight: rule.riskWeight,
          reason: findingReason,
          metadata: {
            ruleId: rule.ruleCode === 'MULTIPLE_FAILED_LOGINS' ? 'RULE-001' : (rule.ruleCode === 'UNAUTHORIZED_ACCESS' || rule.ruleCode === 'RULE-002') ? 'RULE-002' : `RULE-${rule.id}`,
            employeeId: empId,
            action: event.normalizedData?.action,
            resource: event.normalizedData?.resource,
            data: event.normalizedData,
          },
          status: 'OPEN',
          createdAt: new Date().toISOString(),
        };

        db.addFinding(finding);
        findings.push(finding);

        // Server-side logging for RULE_MATCH (Phase 8 Diagnostics)
        console.log(
          `[RULE_MATCH] Rule: ${rule.ruleCode} [${rule.severity}] matched for User: ${event.username} (Event: ${event.eventType}, Action: ${event.normalizedData?.action || 'N/A'}, Weight: ${rule.riskWeight})`
        );

        // Broadcast finding to Admin WebSocket
        wsManager.broadcastNewFinding(finding);
      }
    }

    return findings;
  }

  private resolveFieldValue(field: string, data: Record<string, any>): any {
    if (field === 'sizeMb' || field === 'size_mb' || field === 'file_size_mb') {
      return data.sizeMb ?? data.size_mb ?? data.file_size_mb ?? data.totalSizeMb;
    }
    if (field === 'totalSizeMb') {
      return data.totalSizeMb ?? data.sizeMb ?? data.size_mb;
    }
    if (field === 'fileName' || field === 'file_name' || field === 'filename') {
      return data.fileName ?? data.file_name ?? data.filename;
    }
    return data[field];
  }

  private evaluateSimpleConditions(conditions: RuleCondition[], data: Record<string, any>): boolean {
    if (!conditions || conditions.length === 0) return true;

    return conditions.every((cond) => {
      const fieldVal = this.resolveFieldValue(cond.field, data);
      if (fieldVal === undefined && cond.operator !== '!=') return false;

      switch (cond.operator) {
        case '==':
          return fieldVal === cond.value;
        case '!=':
          return fieldVal !== cond.value;
        case '>':
          return typeof fieldVal === 'number' && fieldVal > Number(cond.value);
        case '>=':
          return typeof fieldVal === 'number' && fieldVal >= Number(cond.value);
        case '<':
          return typeof fieldVal === 'number' && fieldVal < Number(cond.value);
        case '<=':
          return typeof fieldVal === 'number' && fieldVal <= Number(cond.value);
        case 'contains':
          if (typeof fieldVal === 'string') {
            return fieldVal.toLowerCase().includes(String(cond.value).toLowerCase());
          }
          return false;
        case 'in':
          if (Array.isArray(cond.value)) {
            return cond.value.includes(fieldVal);
          }
          return false;
        default:
          return false;
      }
    });
  }

  private evaluateTemporalRule(rule: Rule, currentEvent: NormalizedEvent): boolean {
    if (!rule.temporalConfig) return false;
    let targetUserId = currentEvent.userId;
    if (!targetUserId && currentEvent.username) {
      const u = db.getUserByUsername(currentEvent.username) || db.getUserByEmployeeId(currentEvent.username);
      if (u) targetUserId = u.id;
    }
    if (!targetUserId && !currentEvent.username) return false;

    const { countThreshold, windowMinutes } = rule.temporalConfig;
    const windowMs = windowMinutes * 60 * 1000;
    const currentTime = new Date(currentEvent.timestamp || Date.now()).getTime();
    if (isNaN(currentTime)) return false;
    const windowStart = currentTime - windowMs;

    const isFailedLoginRule = rule.ruleCode === 'MULTIPLE_FAILED_LOGINS' || rule.eventType === 'FAILED_LOGIN';

    const matchingEvents = db.getNormalizedEvents().filter((ev) => {
      // Must match target user strictly - do not combine different users
      let evMatchesUser = false;
      if (targetUserId && ev.userId) {
        evMatchesUser = ev.userId === targetUserId;
      } else if (targetUserId && !ev.userId && currentEvent.username && ev.username) {
        evMatchesUser = ev.username.toLowerCase() === currentEvent.username.toLowerCase();
      } else if (!targetUserId && currentEvent.username && ev.username) {
        evMatchesUser = ev.username.toLowerCase() === currentEvent.username.toLowerCase();
      }
      if (!evMatchesUser) {
        return false;
      }

      const evTime = new Date(ev.timestamp).getTime();
      if (isNaN(evTime) || evTime < windowStart || evTime > currentTime) {
        return false;
      }

      if (isFailedLoginRule) {
        return isFailedLoginEvent(ev);
      }

      if (ev.eventType !== rule.eventType) {
        return false;
      }

      return this.evaluateSimpleConditions(rule.conditions, ev.normalizedData);
    });

    return matchingEvents.length >= countThreshold;
  }

  // -------------------------------------------------------------
  // 3. User Risk Scoring (24h Window with Decay)
  // -------------------------------------------------------------
  public recalculateRisk(userId: number): RiskScore {
    const user = db.getUserById(userId);
    const username = user ? user.username : `user_${userId}`;

    const now = Date.now();
    const windowStart = new Date(now - RISK_WINDOW_HOURS * 3600 * 1000).toISOString();
    const windowEnd = new Date(now).toISOString();

    const userFindings = db.getFindings().filter((f) => {
      if (f.userId !== userId) return false;
      const fTime = new Date(f.createdAt).getTime();
      return fTime >= now - RISK_WINDOW_HOURS * 3600 * 1000;
    });

    const breakdown: Record<string, number> = {};
    let totalRulePoints = 0;

    userFindings.forEach((f) => {
      const ageHours = (now - new Date(f.createdAt).getTime()) / (3600 * 1000);
      const decayFactor = Math.max(0.2, 1 - ageHours / RISK_WINDOW_HOURS);
      const points = f.riskWeight * decayFactor;

      breakdown[f.ruleCode] = (breakdown[f.ruleCode] || 0) + Math.round(points);
      totalRulePoints += points;
    });

    const ruleScore = Math.min(100, Math.round(totalRulePoints));
    const anomaly = this.recalculateMLAnomaly(userId);
    const mlScore = anomaly.anomalyScore;

    const userEvents = db.getNormalizedEvents().filter((e) => e.userId === userId);
    let behaviorPoints = 0;
    userEvents.slice(0, 50).forEach((e) => {
      if (e.eventType === 'FAILED_LOGIN' || isFailedLoginEvent(e)) behaviorPoints += 5;
      if (e.eventType === 'USB_INSERT' && e.normalizedData.authorized === false) behaviorPoints += 15;
      if (
        e.eventType === 'FILE_ACCESS' &&
        ['CONFIDENTIAL', 'RESTRICTED', 'SENSITIVE', 'HIGHLY_CONFIDENTIAL'].includes(
          e.normalizedData.classification
        )
      ) {
        behaviorPoints += 10;
      }
    });
    const behaviorScore = Math.min(100, behaviorPoints);

    const finalScore = Math.min(
      100,
      Math.round(ruleScore * 0.55 + mlScore * 0.30 + behaviorScore * 0.15)
    );

    let riskLevel: RiskLevel = 'LOW';
    if (finalScore >= 75) riskLevel = 'CRITICAL';
    else if (finalScore >= 50) riskLevel = 'HIGH';
    else if (finalScore >= 25) riskLevel = 'MEDIUM';

    const riskRecord: RiskScore = {
      id: userId,
      userId,
      username,
      ruleScore,
      mlScore,
      behaviorScore,
      finalScore,
      riskLevel,
      contributingFindingsCount: userFindings.length,
      scoreBreakdown: breakdown,
      calculationWindowStart: windowStart,
      calculationWindowEnd: windowEnd,
      calculatedAt: new Date().toISOString(),
    };

    db.setRiskScore(riskRecord);
    wsManager.broadcastRiskScore(riskRecord);

    // Server-side logging for RISK_UPDATE (Phase 8 Diagnostics)
    console.log(
      `[RISK_UPDATE] User: ${username} (ID: ${userId}) Risk Score updated: ${finalScore}/100 [Level: ${riskLevel}] (Active Findings: ${userFindings.length})`
    );

    return riskRecord;
  }

  // -------------------------------------------------------------
  // 4. ML Anomaly Scoring (Isolation Forest Simulation)
  // -------------------------------------------------------------
  public recalculateMLAnomaly(userId: number): MLAnomaly {
    const user = db.getUserById(userId);
    const username = user ? user.username : `user_${userId}`;

    const userEvents = db.getNormalizedEvents().filter((e) => e.userId === userId);
    const userFindings = db.getFindings().filter((f) => f.userId === userId);
    const userTransfers = db.getUSBTransfers().filter((t) => t.userId === userId);

    let loginCount = 0;
    let failedLoginCount = 0;
    let usbInsertCount = 0;
    let sensitiveAccessCount = 0;

    userEvents.forEach((e) => {
      if (e.eventType === 'LOGIN') loginCount++;
      if (e.eventType === 'FAILED_LOGIN' || isFailedLoginEvent(e)) failedLoginCount++;
      if (e.eventType === 'USB_INSERT') usbInsertCount++;
      if (
        e.eventType === 'SENSITIVE_FILE_ACCESS' ||
        (e.eventType === 'FILE_ACCESS' &&
          ['CONFIDENTIAL', 'RESTRICTED', 'SENSITIVE', 'HIGHLY_CONFIDENTIAL'].includes(
            e.normalizedData.classification
          ))
      ) {
        sensitiveAccessCount++;
      }
    });

    let totalUsbMb = 0;
    userTransfers.forEach((t) => (totalUsbMb += t.totalSizeMb));

    const indicators: string[] = [];
    let featureAnomalyPoints = 0;

    if (failedLoginCount >= 3) {
      featureAnomalyPoints += 30;
      indicators.push(`Excessive authentication failures (${failedLoginCount} failed)`);
    }
    if (totalUsbMb > 500) {
      featureAnomalyPoints += 35;
      indicators.push(`High-volume external drive egress (${totalUsbMb.toFixed(0)} MB)`);
    }
    if (sensitiveAccessCount >= 3) {
      featureAnomalyPoints += 25;
      indicators.push(`Atypical confidential file access velocity (${sensitiveAccessCount} files)`);
    }
    if (userFindings.length >= 2) {
      featureAnomalyPoints += 20;
      indicators.push(`Multiple correlate policy breaches (${userFindings.length} active findings)`);
    }

    const anomalyScore = Math.min(100, Math.round(featureAnomalyPoints));
    let anomalyLevel: 'NORMAL' | 'LOW' | 'MEDIUM' | 'HIGH' = 'NORMAL';
    if (anomalyScore >= 70) anomalyLevel = 'HIGH';
    else if (anomalyScore >= 40) anomalyLevel = 'MEDIUM';
    else if (anomalyScore >= 15) anomalyLevel = 'LOW';

    const anomaly: MLAnomaly = {
      id: userId,
      userId,
      username,
      anomalyScore,
      anomalyLevel,
      modelVersion: this.mlVersion,
      featureSnapshot: {
        login_count: loginCount,
        failed_login_count: failedLoginCount,
        usb_insert_count: usbInsertCount,
        usb_transfer_count: userTransfers.length,
        total_usb_mb: Math.round(totalUsbMb),
        sensitive_access_count: sensitiveAccessCount,
        finding_count: userFindings.length,
      },
      indicators: indicators.length > 0 ? indicators : ['Routine baseline behavioral activity'],
      calculatedAt: new Date().toISOString(),
    };

    db.setMLAnomaly(anomaly);
    return anomaly;
  }

  // -------------------------------------------------------------
  // 5. Alert Correlation Engine
  // -------------------------------------------------------------
  public correlateAlertsForUser(userId: number): Alert[] {
    const user = db.getUserById(userId);
    if (!user) return [];

    const now = Date.now();
    const windowMs = CORRELATION_WINDOW_MINUTES * 60 * 1000;
    const windowStart = now - windowMs;

    const recentFindings = db.getFindings().filter((f) => {
      if (f.userId !== userId) return false;
      const fTime = new Date(f.createdAt).getTime();
      return fTime >= windowStart;
    });

    if (recentFindings.length === 0) return [];

    const risk = db.getRiskScoreByUserId(userId) || this.recalculateRisk(userId);
    const anomaly = db.getMLAnomalyByUserId(userId) || this.recalculateMLAnomaly(userId);

    const hasUnauthorizedUSB = recentFindings.some((f) => f.ruleCode === 'UNAUTHORIZED_USB_INSERT');
    const hasSensitiveAccess = recentFindings.some(
      (f) =>
        f.ruleCode === 'SENSITIVE_FILE_ACCESS' ||
        f.ruleCode === 'REPEATED_SENSITIVE_ACCESS' ||
        f.ruleCode === 'CONFIDENTIAL_FILE_ACCESS' ||
        f.ruleCode === 'HIGHLY_CONFIDENTIAL_FILE_ACCESS'
    );
    const hasLargeTransfer = recentFindings.some((f) => f.ruleCode === 'LARGE_USB_TRANSFER');
    const hasLargeDownload = recentFindings.some(
      (f) => f.ruleCode === 'LARGE_FILE_DOWNLOAD' || f.ruleCode === 'HIGHLY_CONFIDENTIAL_LARGE_DOWNLOAD'
    );
    const hasSensitiveDownload = recentFindings.some(
      (f) => f.ruleCode === 'SENSITIVE_FILE_DOWNLOAD' || f.ruleCode === 'HIGHLY_CONFIDENTIAL_LARGE_DOWNLOAD'
    );
    const hasHighlyConfidential = recentFindings.some(
      (f) => f.ruleCode === 'HIGHLY_CONFIDENTIAL_LARGE_DOWNLOAD' || f.ruleCode === 'HIGHLY_CONFIDENTIAL_FILE_ACCESS'
    );
    const hasPrivEsc = recentFindings.some((f) => f.ruleCode === 'PRIVILEGE_CHANGE');
    const hasBruteForce = recentFindings.some(
      (f) => f.ruleCode === 'MULTIPLE_FAILED_LOGINS' || f.ruleCode === 'RULE-001'
    );

    const generatedAlerts: Alert[] = [];

    // Scenario 1: Large or Sensitive File Download / Exfiltration
    if (hasLargeDownload || hasSensitiveDownload || hasHighlyConfidential) {
      const alertId = `ALT-EXFIL-DL-${userId}-${new Date().toISOString().slice(0, 10)}`;
      const existing = db.getAlertById(alertId);

      const isCritical = hasHighlyConfidential || (hasLargeDownload && hasSensitiveDownload);
      const title = hasHighlyConfidential
        ? 'Critical Data Loss Prevention Alert: Highly Confidential File Egress'
        : isCritical
        ? 'Critical Data Loss Prevention Alert: High-Volume Sensitive File Download'
        : hasLargeDownload
        ? 'Data Loss Prevention Alert: Large File Egress Detected'
        : 'Data Loss Prevention Alert: Confidential File Download Detected';

      const desc = `Employee ${user.fullName} (${user.username}) downloaded classified enterprise data exceeding DLP compliance threshold. Risk score elevated to ${risk.finalScore}/100.`;

      const evidence = [
        `User: ${user.fullName} (${user.username}) | Department: ${user.department}`,
        `Action Executed: DOWNLOAD`,
        `Risk Score Escalation: ${risk.finalScore}/100 (${risk.riskLevel})`,
        `ML Anomaly Score: ${anomaly.anomalyScore}/100`,
        `Triggered Detection Rules: ${recentFindings.map((f) => f.ruleCode).join(', ')}`,
      ];

      if (!existing) {
        const newAlert: Alert = {
          id: db.getAlerts().length + 1,
          alertId,
          userId,
          username: user.username,
          userDepartment: user.department,
          title,
          description: desc,
          severity: isCritical ? 'CRITICAL' : 'HIGH',
          status: 'OPEN',
          riskScore: risk.finalScore,
          mlAnomalyScore: anomaly.anomalyScore,
          correlationKey: `EXFIL_DL_${userId}`,
          firstSeen: recentFindings[0]?.createdAt || new Date().toISOString(),
          lastSeen: new Date().toISOString(),
          eventCount: recentFindings.length,
          findingCount: recentFindings.length,
          evidence,
          recommendations: [
            'Revoke active session tokens immediately via IAM Console',
            'Isolate workstation network interface from enterprise VLAN',
            'Perform forensic audit on workstation local download directory',
            'Notify Security Operations Lead and Compliance Officer',
          ],
          policyViolations: [
            'DLP-002-BULK-EGRESS',
            'DLP-004-HIGHLY-CONFIDENTIAL-EXFIL',
            'SEC-008-INSIDER-THREAT',
          ],
          createdAt: new Date().toISOString(),
        };
        db.addAlert(newAlert);
        generatedAlerts.push(newAlert);
        wsManager.broadcastNewAlert(newAlert);
      } else {
        const updated = db.updateAlert(alertId, {
          lastSeen: new Date().toISOString(),
          eventCount: existing.eventCount + 1,
          findingCount: recentFindings.length,
          riskScore: risk.finalScore,
          mlAnomalyScore: anomaly.anomalyScore,
          evidence,
        });
        if (updated) {
          wsManager.broadcastAlertUpdated(updated);
        }
      }
    }

    // Scenario 2: Multi-Stage USB Exfiltration Attack
    if (hasUnauthorizedUSB && (hasSensitiveAccess || hasLargeTransfer || hasLargeDownload)) {
      const alertId = `ALT-EXFIL-USB-${userId}-${new Date().toISOString().slice(0, 10)}`;
      const existing = db.getAlertById(alertId);

      const title = `Multi-Stage Data Exfiltration Sequence Detected`;
      const desc = `Correlated attack pattern: User ${user.fullName} attached an unauthorized external storage device and initiated confidential file egress exceeding policy thresholds.`;

      const evidence = [
        `Unauthorized USB device connected by user ${user.username}`,
        `Multiple sensitive/classified file operations detected`,
        `Risk Score Escalation: ${risk.finalScore}/100`,
        `ML Anomaly Score: ${anomaly.anomalyScore}/100`,
      ];

      if (!existing) {
        const newAlert: Alert = {
          id: db.getAlerts().length + 1,
          alertId,
          userId,
          username: user.username,
          userDepartment: user.department,
          title,
          description: desc,
          severity: 'CRITICAL',
          status: 'OPEN',
          riskScore: risk.finalScore,
          mlAnomalyScore: anomaly.anomalyScore,
          correlationKey: `EXFIL_USB_${userId}`,
          firstSeen: recentFindings[0]?.createdAt || new Date().toISOString(),
          lastSeen: new Date().toISOString(),
          eventCount: recentFindings.length,
          findingCount: recentFindings.length,
          evidence,
          recommendations: [
            'Revoke active session tokens immediately via IAM Console',
            'Isolate host workstation from enterprise VLAN',
            'Dispatch USB hardware lockdown command to Endpoint Agent',
            'Initiate HR & Security Incident Investigation ticket',
          ],
          policyViolations: ['DLP-001-EXTERNAL-STORAGE', 'IAM-004-CONFIDENTIAL-ACCESS'],
          createdAt: new Date().toISOString(),
        };
        db.addAlert(newAlert);
        generatedAlerts.push(newAlert);
        wsManager.broadcastNewAlert(newAlert);
      } else {
        const updated = db.updateAlert(alertId, {
          lastSeen: new Date().toISOString(),
          eventCount: existing.eventCount + 1,
          findingCount: recentFindings.length,
          riskScore: risk.finalScore,
          mlAnomalyScore: anomaly.anomalyScore,
        });
        if (updated) {
          wsManager.broadcastAlertUpdated(updated);
        }
      }
    }

    // Scenario 3: Privilege Escalation
    if (hasPrivEsc) {
      const alertId = `ALT-PRIVESC-${userId}-${new Date().toISOString().slice(0, 10)}`;
      const existing = db.getAlertById(alertId);
      if (!existing) {
        const newAlert: Alert = {
          id: db.getAlerts().length + 1,
          alertId,
          userId,
          username: user.username,
          userDepartment: user.department,
          title: `Privilege Escalation & Unauthorized Elevation`,
          description: `User ${user.username} executed unauthorized administrative privilege modification or modified system security parameters.`,
          severity: 'CRITICAL',
          status: 'OPEN',
          riskScore: risk.finalScore,
          mlAnomalyScore: anomaly.anomalyScore,
          correlationKey: `PRIV_ESC_${userId}`,
          firstSeen: new Date().toISOString(),
          lastSeen: new Date().toISOString(),
          eventCount: 1,
          findingCount: 1,
          evidence: [
            `Sudoers or elevated security policy modified`,
            `Unauthorized execution outside assigned role context`,
          ],
          recommendations: [
            'Audit recent command execution history via auditd logs',
            'Revert unauthorized permission grant immediately',
            'Review workstation for persistence backdoors',
          ],
          policyViolations: ['SEC-ADM-002-ELEVATION'],
          createdAt: new Date().toISOString(),
        };
        db.addAlert(newAlert);
        generatedAlerts.push(newAlert);
        wsManager.broadcastNewAlert(newAlert);
      }
    }

    // Scenario 4: Multiple Failed Logins (RULE-001)
    if (hasBruteForce) {
      const empId = user.employeeId || `EMP-${userId}`;
      const userFailedEvents = db.getNormalizedEvents().filter((ev) => {
        let matchesUser = false;
        if (ev.userId && userId) {
          matchesUser = ev.userId === userId;
        } else if (!ev.userId && user.username && ev.username) {
          matchesUser = ev.username.toLowerCase() === user.username.toLowerCase();
        }
        return matchesUser && isFailedLoginEvent(ev);
      });

      // Filter to rolling 10m window
      const nowTime = Date.now();
      const window10m = nowTime - 10 * 60 * 1000;
      const recentFailedEvents = userFailedEvents.filter((ev) => {
        const t = new Date(ev.timestamp).getTime();
        return !isNaN(t) && t >= window10m;
      });

      const failedCount = recentFailedEvents.length >= 5 ? recentFailedEvents.length : Math.max(userFailedEvents.length, 5);
      const firstFailedTime = recentFailedEvents[0]?.timestamp || userFailedEvents[0]?.timestamp || new Date().toISOString();
      const latestFailedTime = recentFailedEvents[recentFailedEvents.length - 1]?.timestamp || userFailedEvents[userFailedEvents.length - 1]?.timestamp || new Date().toISOString();
      const sourceIp = recentFailedEvents[recentFailedEvents.length - 1]?.normalizedData?.ipAddress || user.ipAddress || '192.168.100.250';

      const detectionReason = `${failedCount} failed login attempts detected for ${empId} within 10 minutes.`;

      const alertId = `ALT-RULE001-${userId}-${new Date().toISOString().slice(0, 10)}`;
      const existing = db.getAlertById(alertId) || db.getAlerts().find((a) => a.correlationKey === `RULE-001_${userId}` && a.status === 'OPEN');

      const evidence = [
        `Rule ID: RULE-001`,
        `Rule Name: Multiple Failed Logins`,
        `User/Employee ID: ${empId}`,
        `Username: @${user.username}`,
        `Number of failed attempts: ${failedCount}`,
        `Detection window: 10 minutes`,
        `First failed-login timestamp: ${firstFailedTime}`,
        `Latest failed-login timestamp: ${latestFailedTime}`,
        `Source IP: ${sourceIp}`,
        `Detection reason: ${detectionReason}`,
      ];

      if (!existing) {
        const newAlert: Alert = {
          id: db.getAlerts().length + 1,
          alertId,
          userId,
          username: user.username,
          userDepartment: user.department,
          title: `Multiple Failed Logins`,
          description: detectionReason,
          severity: 'HIGH',
          status: 'OPEN',
          riskScore: risk.finalScore,
          mlAnomalyScore: anomaly.anomalyScore,
          correlationKey: `RULE-001_${userId}`,
          firstSeen: firstFailedTime,
          lastSeen: latestFailedTime,
          eventCount: failedCount,
          findingCount: recentFindings.filter((f) => f.ruleCode === 'MULTIPLE_FAILED_LOGINS' || f.ruleCode === 'RULE-001').length,
          evidence,
          recommendations: [
            'Temporarily lock account credentials pending MFA challenge',
            'Inspect origin IP subnet for credential stuffing / brute-force botnet signatures',
            `Contact employee @${user.username} (${empId}) to verify recent authentication activity`,
          ],
          policyViolations: ['RULE-001', 'AUTH-002-RATE-LIMIT', 'MULTIPLE_FAILED_LOGINS'],
          createdAt: new Date().toISOString(),
        };
        db.addAlert(newAlert);
        generatedAlerts.push(newAlert);
        wsManager.broadcastNewAlert(newAlert);

        // Record audit entry for Rule 1 trigger
        db.addAuditLog({
          id: db.getAuditLogs().length + 1,
          actor: 'SIEM_RULE_ENGINE',
          userId,
          action: 'RULE_TRIGGER_ALERT',
          resource: `alert:${newAlert.alertId}`,
          details: `RULE-001 (Multiple Failed Logins) triggered: ${detectionReason}`,
          timestamp: new Date().toISOString(),
        });
      } else {
        // Update existing alert - DUPLICATE ALERT PREVENTION
        const updated = db.updateAlert(existing.alertId, {
          lastSeen: latestFailedTime,
          eventCount: failedCount,
          findingCount: recentFindings.filter((f) => f.ruleCode === 'MULTIPLE_FAILED_LOGINS' || f.ruleCode === 'RULE-001').length,
          riskScore: risk.finalScore,
          mlAnomalyScore: anomaly.anomalyScore,
          description: detectionReason,
          evidence,
        });
        if (updated) {
          wsManager.broadcastAlertUpdated(updated);
        }
      }
    }

    // Scenario 5: Unauthorized Access (RULE-002)
    const hasUnauthorizedAccess = recentFindings.some(
      (f) => f.ruleCode === 'UNAUTHORIZED_ACCESS' || f.ruleCode === 'RULE-002'
    );
    if (hasUnauthorizedAccess) {
      const empId = user.employeeId || `EMP-${userId}`;
      const latestFinding = recentFindings.find(
        (f) => f.ruleCode === 'UNAUTHORIZED_ACCESS' || f.ruleCode === 'RULE-002'
      );
      const resourceName =
        latestFinding?.metadata?.resource ||
        latestFinding?.metadata?.data?.resource ||
        latestFinding?.metadata?.action ||
        'ADMIN_SETTINGS';
      const userRole =
        latestFinding?.metadata?.data?.userRole ||
        user.role ||
        'EMPLOYEE';

      const detectionReason = `User ${empId} (Role: ${userRole}) attempted unauthorized access to resource: ${resourceName}`;

      const alertId = `ALT-RULE002-${userId}-${new Date().toISOString().slice(0, 10)}`;
      const existing =
        db.getAlertById(alertId) ||
        db.getAlerts().find((a) => a.correlationKey === `RULE-002_${userId}` && a.status === 'OPEN');

      const evidence = [
        `Rule ID: RULE-002`,
        `Rule Name: Unauthorized Access`,
        `User/Employee ID: ${empId}`,
        `Username: @${user.username}`,
        `User Role: ${userRole}`,
        `Attempted Target Resource: ${resourceName}`,
        `Risk Score Escalation: ${risk.finalScore}/100 (${risk.riskLevel})`,
        `ML Anomaly Score: ${anomaly.anomalyScore}/100`,
        `Detection Reason: ${detectionReason}`,
        `Enforcement Action: 403 Forbidden / Access Denied by Zero-Trust RBAC Layer`,
        `Timestamp: ${new Date().toISOString()}`,
      ];

      if (!existing) {
        const newAlert: Alert = {
          id: db.getAlerts().length + 1,
          alertId,
          userId,
          username: user.username,
          userDepartment: user.department,
          title: `Unauthorized Resource Access`,
          description: detectionReason,
          severity: 'HIGH',
          status: 'OPEN',
          riskScore: risk.finalScore,
          mlAnomalyScore: anomaly.anomalyScore,
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
        db.addAlert(newAlert);
        generatedAlerts.push(newAlert);
        wsManager.broadcastNewAlert(newAlert);

        // Record audit entry for Rule 2 trigger
        db.addAuditLog({
          id: db.getAuditLogs().length + 1,
          actor: 'SIEM_RULE_ENGINE',
          userId,
          action: 'RULE_TRIGGER_ALERT',
          resource: `alert:${newAlert.alertId}`,
          details: `RULE-002 (Unauthorized Access) triggered: ${detectionReason}`,
          timestamp: new Date().toISOString(),
        });
      } else {
        // Update existing alert - DUPLICATE ALERT PREVENTION
        const updated = db.updateAlert(existing.alertId, {
          lastSeen: new Date().toISOString(),
          eventCount: (existing.eventCount || 1) + 1,
          findingCount: recentFindings.filter(
            (f) => f.ruleCode === 'UNAUTHORIZED_ACCESS' || f.ruleCode === 'RULE-002'
          ).length,
          riskScore: risk.finalScore,
          mlAnomalyScore: anomaly.anomalyScore,
          description: detectionReason,
          evidence,
        });
        if (updated) {
          wsManager.broadcastAlertUpdated(updated);
        }
      }
    }

    return generatedAlerts;
  }

  // -------------------------------------------------------------
  // 6. Corporate File Access & DLP
  // -------------------------------------------------------------
  public accessFile(
    fileId: string,
    action: 'OPEN' | 'VIEW' | 'DOWNLOAD' | 'REQUEST_ACCESS',
    actor: User
  ): { success: boolean; message: string; file?: DemoFile } {
    const file = db.getFileById(fileId);
    if (!file) {
      return { success: false, message: 'File not found in corporate repository.' };
    }

    const activityRecord: FileActivityRecord = {
      id: `act-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`,
      fileId: file.id,
      fileName: file.name,
      sizeMb: file.sizeMb,
      classification: file.classification,
      action,
      timestamp: new Date().toISOString(),
      status: 'SUCCESS',
      userId: actor.id,
      username: actor.username,
    };
    db.addFileActivity(activityRecord);

    const isSensitive = ['CONFIDENTIAL', 'RESTRICTED', 'SENSITIVE', 'HIGHLY_CONFIDENTIAL'].includes(
      file.classification
    );

    let eventType: EventType = 'FILE_ACCESS';
    let severity: Severity = 'LOW';
    let detailsAction = action === 'REQUEST_ACCESS' ? 'REQUEST_ACCESS' : 'OPEN';

    if (action === 'DOWNLOAD') {
      eventType = 'FILE_ACCESS';
      detailsAction = 'DOWNLOAD';
      severity = file.sizeMb > LARGE_FILE_THRESHOLD_MB ? 'HIGH' : isSensitive ? 'MEDIUM' : 'LOW';
      // Server-side logging for FILE_DOWNLOAD (Phase 8 Diagnostics)
      console.log(
        `[FILE_DOWNLOAD] User: ${actor.username} downloaded file: ${file.name} (Classification: ${file.classification}, Size: ${file.sizeMb}MB)`
      );
    } else if (isSensitive) {
      eventType = 'FILE_ACCESS';
      detailsAction = 'FILE_READ_RESTRICTED';
      severity = 'MEDIUM';
      // Server-side logging for FILE_ACCESS (Phase 8 Diagnostics)
      console.log(
        `[FILE_ACCESS] User: ${actor.username} accessed sensitive file: ${file.name} (Action: ${action}, Classification: ${file.classification}, Size: ${file.sizeMb}MB)`
      );
    } else {
      // Server-side logging for FILE_ACCESS (Phase 8 Diagnostics)
      console.log(
        `[FILE_ACCESS] User: ${actor.username} accessed file: ${file.name} (Action: ${action}, Classification: ${file.classification}, Size: ${file.sizeMb}MB)`
      );
    }

    this.ingestLog({
      timestamp: new Date().toISOString(),
      userId: actor.id,
      username: actor.username,
      source: 'endpoint-agent',
      eventType,
      action: detailsAction,
      resource: `/shares/${file.department.toLowerCase().replace(/[\s&]+/g, '_')}/${file.name}`,
      ipAddress: actor.ipAddress || '10.14.88.102',
      severity,
      details: {
        file_id: file.id,
        file_name: file.name,
        filename: file.name,
        size_mb: file.sizeMb,
        sizeMb: file.sizeMb,
        file_size_mb: file.sizeMb,
        classification: file.classification,
        action,
        department: file.department,
        user_id: actor.id,
        username: actor.username,
        user_agent: 'Corporate Workspace / SIEM Desktop Agent',
      },
    });

    let clientMessage = 'Document preview ready.';
    if (action === 'DOWNLOAD') {
      clientMessage = `Download started for ${file.name} (${file.sizeMb} MB).`;
    } else if (action === 'REQUEST_ACCESS') {
      clientMessage = `Access request submitted for ${file.name}.`;
    }

    return {
      success: true,
      message: clientMessage,
      file,
    };
  }

  // -------------------------------------------------------------
  // 7. USB Transfer Policy Engine
  // -------------------------------------------------------------
  public requestUSBTransfer(
    userId: number,
    deviceId: string,
    files: { name: string; sizeMb: number; sensitive: boolean; type: string }[]
  ): USBTransferRequest {
    const user = db.getUserById(userId) || db.getUsers()[0];
    const dev = db.getUSBDeviceById(deviceId);

    const totalSizeMb = files.reduce((sum, f) => sum + f.sizeMb, 0);
    const sensitiveFileCount = files.filter((f) => f.sensitive).length;

    let decision: USBDecision = 'ALLOW';
    const reasons: string[] = [];

    if (!dev || !dev.authorized) {
      decision = 'BLOCK';
      reasons.push('Hardware storage device is not whitelisted by DLP Policy');
    } else if (totalSizeMb > USB_TRANSFER_THRESHOLD_MB) {
      decision = 'BLOCK';
      reasons.push(`Total egress payload (${totalSizeMb.toFixed(1)} MB) exceeds 500 MB quota`);
    } else if (sensitiveFileCount > 0) {
      decision = 'PROTECT';
      reasons.push(
        `Payload contains ${sensitiveFileCount} confidential file(s); AES-256 container wrapper required`
      );
    } else {
      reasons.push('Standard file payload approved for authorized drive transfer');
    }

    const transferId = `TRF-${Date.now().toString(36).toUpperCase()}-${Math.floor(Math.random() * 900 + 100)}`;
    const transfer: USBTransferRequest = {
      id: db.getUSBTransfers().length + 1,
      transferId,
      deviceId,
      deviceName: dev ? dev.deviceName : 'Unknown Device',
      userId: user.id,
      username: user.username,
      totalSizeMb,
      fileCount: files.length,
      sensitiveFileCount,
      files: files.map((f) => ({
        ...f,
        protectedHash: decision === 'PROTECT' ? `sha256:enc-${Date.now()}` : undefined,
      })),
      decision,
      reasons,
      requestedAt: new Date().toISOString(),
    };

    db.addUSBTransfer(transfer);

    this.ingestLog({
      timestamp: new Date().toISOString(),
      userId: user.id,
      username: user.username,
      source: 'usb-monitor',
      eventType: 'USB_TRANSFER_REQUEST',
      action: `TRANSFER_${decision}`,
      deviceId,
      ipAddress: user.ipAddress,
      severity: decision === 'BLOCK' ? 'HIGH' : decision === 'PROTECT' ? 'MEDIUM' : 'LOW',
      details: {
        transfer_id: transferId,
        decision,
        total_size_mb: totalSizeMb,
        totalSizeMb,
        sensitive_count: sensitiveFileCount,
        reasons,
      },
    });

    return transfer;
  }

  // -------------------------------------------------------------
  // 8. SOC Metrics Summary
  // -------------------------------------------------------------
  public getSOCSummary(): SOCSummary {
    const dataset = demoDataset.getOrCreateDataset();
    const demoSummary = demoDataset.getSOCSummary();

    const dbAlerts = db.getAlerts();
    const combinedAlerts = Array.from(new Map([...dataset.alerts, ...dbAlerts].map((a) => [a.alertId, a])).values());
    const openAlerts = combinedAlerts.filter((a) => a.status === 'OPEN' || a.status === 'INVESTIGATING');
    const criticalAlerts = openAlerts.filter((a) => a.severity === 'CRITICAL');

    const totalEvents = dataset.totalEvents + db.getNormalizedEvents().length;
    const scores = dataset.riskScores;
    const highRiskUsers = scores.filter((s) => s.finalScore >= 50).length;
    const avgRiskScore =
      scores.length > 0
        ? Math.round(scores.reduce((acc, s) => acc + s.finalScore, 0) / scores.length)
        : demoSummary.avgRiskScore;

    const transfers = db.getUSBTransfers();
    const usbBlocked = demoSummary.usbTransfersBlocked + transfers.filter((t) => t.decision === 'BLOCK').length;
    const usbProtected = demoSummary.usbTransfersProtected + transfers.filter((t) => t.decision === 'PROTECT').length;
    const usbAllowed = demoSummary.usbTransfersAllowed + transfers.filter((t) => t.decision === 'ALLOW').length;

    const anomalies = db.getMLAnomalies();
    const activeAnomalies = demoSummary.activeMlAnomalies + anomalies.filter(
      (a) => a.anomalyLevel === 'HIGH' || a.anomalyLevel === 'MEDIUM'
    ).length;

    return {
      totalEvents,
      events24h: Math.round(totalEvents * 0.12),
      openAlerts: openAlerts.length,
      criticalAlerts: criticalAlerts.length,
      highRiskUsers,
      avgRiskScore,
      usbTransfersBlocked: usbBlocked,
      usbTransfersProtected: usbProtected,
      usbTransfersAllowed: usbAllowed,
      activeMlAnomalies: activeAnomalies,
      rulesActive: 7, // Exactly 7 Enterprise Detection Rules
    };
  }

  // -------------------------------------------------------------
  // 9. Seed Baseline Demo Telemetry
  // -------------------------------------------------------------
  public seedDemoData(): void {
    // 1. Ensure the 1,000 Demo Employees, ~15k Security Events, 7 Detection Rules, Risk Scoring, & Alerts exist
    const dataset = demoDataset.getOrCreateDataset();

    // 2. Synchronize rules in database to the canonical 7 Enterprise Detection Rules
    db.setRules(JSON.parse(JSON.stringify(SEVEN_DETECTION_RULES)));

    // 3. Populate initial risk scores and alerts from dataset if database is empty
    if (db.getAlerts().length === 0 && dataset.alerts.length > 0) {
      for (const a of dataset.alerts) {
        db.addAlert(a);
      }
    }
    if (db.getRiskScores().length === 0 && dataset.riskScores.length > 0) {
      for (const r of dataset.riskScores) {
        db.setRiskScore(r);
      }
    }

    const users = db.getUsers();
    const user = users[0]; // Alex Mercer (amercer)
    const adminUser = users.find((u) => u.role === 'ADMIN') || users[1]; // Sarah Chen
    const baseTime = Date.now() - 3600000 * 4; // 4 hours ago

    // 1. Multiple failed login attempts (4 rapid authentication failures)
    for (let i = 0; i < 4; i++) {
      this.ingestLog({
        timestamp: new Date(baseTime + i * 45000).toISOString(),
        userId: user.id,
        username: user.username,
        source: 'auth-service',
        eventType: 'FAILED_LOGIN',
        action: 'AUTH_FAILED',
        resource: 'SSO-Enterprise-Gateway',
        ipAddress: user.ipAddress || '10.14.88.102',
        severity: 'MEDIUM',
        details: {
          failure_reason: 'Invalid Kerberos Token / Password Mismatch',
          attempt_number: i + 1,
          threshold: 3,
        },
      });
    }

    // 2. Login from an unusual location (External IP outside corporate geo-fence)
    this.ingestLog({
      timestamp: new Date(baseTime + 3600000 * 1).toISOString(),
      userId: user.id,
      username: user.username,
      source: 'auth-service',
      eventType: 'LOGIN',
      action: 'AUTH_SUCCESS_UNUSUAL_GEO',
      resource: 'Cloud-VPN-Gateway',
      ipAddress: '198.51.100.42',
      severity: 'HIGH',
      details: {
        geo_location: 'Kyiv, Ukraine',
        corporate_geofence: false,
        previous_known_ip: user.ipAddress || '10.14.88.102',
        anomaly: 'Unusual Geographical Origin',
      },
    });

    // 3. Unusual login time (Off-hours access at 03:14 AM UTC)
    this.ingestLog({
      timestamp: new Date(baseTime + 3600000 * 1.5).toISOString(),
      userId: user.id,
      username: user.username,
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

    // 4. Sensitive file access (Accessing classified Executive M&A Strategy Document)
    this.ingestLog({
      timestamp: new Date(baseTime + 3600000 * 2).toISOString(),
      userId: user.id,
      username: user.username,
      source: 'file-monitor',
      eventType: 'FILE_ACCESS',
      action: 'FILE_READ_RESTRICTED',
      resource: '/vault/executive/M&A_Strategy_Document.pdf',
      ipAddress: user.ipAddress || '10.14.88.102',
      severity: 'HIGH',
      details: {
        file_id: 'f-ma-008',
        file_name: 'M&A_Strategy_Document.pdf',
        classification: 'HIGHLY_CONFIDENTIAL',
        size_mb: 800,
        department_access_allowed: false,
      },
    });

    // 5. Repeated access-denied events (3 unauthorized access attempts to restricted HR directory)
    for (let j = 0; j < 3; j++) {
      this.ingestLog({
        timestamp: new Date(baseTime + 3600000 * 2.3 + j * 60000).toISOString(),
        userId: user.id,
        username: user.username,
        source: 'iam-access-control',
        eventType: 'FILE_ACCESS',
        action: 'ACCESS_DENIED',
        resource: '/vault/hr/executive_compensation.csv',
        ipAddress: user.ipAddress || '10.14.88.102',
        severity: 'HIGH',
        details: {
          permission_required: 'EXECUTIVE_COMPENSATION_READ',
          user_clearance: user.clearanceLevel || 'INTERNAL',
          attempt_index: j + 1,
          status: 'BLOCKED_BY_ACL',
        },
      });
    }

    // 6. Large file download (Bulk archive egress exceeding threshold)
    this.ingestLog({
      timestamp: new Date(baseTime + 3600000 * 2.8).toISOString(),
      userId: user.id,
      username: user.username,
      source: 'endpoint-agent',
      eventType: 'FILE_ACCESS',
      action: 'DOWNLOAD',
      resource: '/shares/rnd/source_code_archive.zip',
      ipAddress: user.ipAddress || '10.14.88.102',
      severity: 'HIGH',
      details: {
        file_id: 'f-source-007',
        file_name: 'source_code_archive.zip',
        sizeMb: 600,
        classification: 'INTERNAL',
        protocol: 'SFTP_PULL',
      },
    });

    // 7. USB/device activity (Unauthorized rogue mass storage device connected)
    this.ingestLog({
      timestamp: new Date(baseTime + 3600000 * 3).toISOString(),
      userId: user.id,
      username: user.username,
      source: 'usb-monitor',
      eventType: 'USB_INSERT',
      action: 'DEVICE_ATTACHED',
      deviceId: 'USB-PERS-404',
      ipAddress: user.ipAddress || '10.14.88.102',
      severity: 'HIGH',
      details: {
        authorized: false,
        device_name: 'Generic Mass Storage (Personal Drive)',
        vendor: 'Generic USB',
        serial: 'GEN-8839210',
      },
    });

    // 8. Abnormal data transfer (Attempted high-volume egress with confidential files to external drive)
    this.requestUSBTransfer(user.id, 'USB-PERS-404', [
      { name: 'M&A_Strategy_Document.pdf', sizeMb: 800, sensitive: true, type: 'application/pdf' },
      { name: 'financial_report_2026.xlsx', sizeMb: 35, sensitive: true, type: 'application/vnd.ms-excel' },
    ]);

    // 9. Privilege escalation (Attempted SUDO root elevation / sudoers modification)
    this.ingestLog({
      timestamp: new Date(baseTime + 3600000 * 3.5).toISOString(),
      userId: user.id,
      username: user.username,
      source: 'os-kernel-audit',
      eventType: 'PRIVILEGE_CHANGE',
      action: 'SUDO_PRIVILEGE_ELEVATION_ATTEMPT',
      resource: '/etc/sudoers.d/backdoor',
      ipAddress: user.ipAddress || '10.14.88.102',
      severity: 'CRITICAL',
      details: {
        command: 'sudo -s echo "amercer ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers',
        granted: false,
        escalation_target: 'ROOT_SUPERADMIN',
      },
    });

    // Standard benign telemetry for Admin Sarah Chen to establish comparative baseline
    this.ingestLog({
      timestamp: new Date(Date.now() - 3600000 * 1).toISOString(),
      userId: adminUser.id,
      username: adminUser.username,
      source: 'auth-service',
      eventType: 'LOGIN',
      action: 'AUTH_SUCCESS',
      resource: 'SOC-Admin-Console',
      ipAddress: adminUser.ipAddress || '10.14.88.15',
      severity: 'LOW',
      details: { mfa_method: 'Hardware_FIDO2', session_verified: true },
    });

    db.addAuditLog({
      id: db.getAuditLogs().length + 1,
      actor: 'SYSTEM',
      action: 'BASELINE_DEMO_SEEDED',
      resource: 'system',
      details: 'Populated 9 realistic threat scenarios: failed logins, unusual location, large download, sensitive file access, USB activity, privilege escalation, unusual login time, abnormal data transfer, and repeated access-denied events.',
      timestamp: new Date().toISOString(),
    });
  }
}

export const siemServer = SIEMServerEngine.getInstance();
