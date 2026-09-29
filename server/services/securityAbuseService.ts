import { db, SecurityEventRecord } from '../db/database';
import { Alert, Severity } from '../../src/types/siem';

export interface SignupAttemptRecord {
  identifier: string;
  ipAddress: string;
  timestamp: number;
  success: boolean;
  reason?: string;
}

export interface FailedDownloadRecord {
  userId?: number;
  username?: string;
  fileId: string;
  ipAddress: string;
  timestamp: number;
  reason: string;
}

export class SecurityAbuseService {
  private static instance: SecurityAbuseService;

  // In-memory sliding window trackers
  private signupAttempts: SignupAttemptRecord[] = [];
  private failedDownloads: FailedDownloadRecord[] = [];

  // Configurable thresholds with environment variable overrides
  public get signupAttemptThreshold(): number {
    const val = parseInt(process.env.SIGNUP_ATTEMPT_THRESHOLD || '3', 10);
    return isNaN(val) || val <= 0 ? 3 : val;
  }

  public get signupWindowSeconds(): number {
    const val = parseInt(process.env.SIGNUP_WINDOW_SECONDS || '300', 10); // 5 minutes default
    return isNaN(val) || val <= 0 ? 300 : val;
  }

  public get failedDownloadThreshold(): number {
    const val = parseInt(process.env.FAILED_DOWNLOAD_THRESHOLD || '3', 10);
    return isNaN(val) || val <= 0 ? 3 : val;
  }

  public get failedDownloadWindowSeconds(): number {
    const val = parseInt(process.env.FAILED_DOWNLOAD_WINDOW_SECONDS || '300', 10); // 5 minutes default
    return isNaN(val) || val <= 0 ? 300 : val;
  }

  private constructor() {}

  public static getInstance(): SecurityAbuseService {
    if (!SecurityAbuseService.instance) {
      SecurityAbuseService.instance = new SecurityAbuseService();
    }
    return SecurityAbuseService.instance;
  }

  /**
   * Track a signup attempt (both failed and repeated requests)
   */
  public recordSignupAttempt(
    identifier: string,
    ipAddress: string,
    success: boolean,
    reason?: string
  ): {
    abuseDetected: boolean;
    attemptCount: number;
    securityEvent?: SecurityEventRecord;
    alert?: Alert;
  } {
    const now = Date.now();
    const cleanId = (identifier || 'unknown').trim().toLowerCase();
    const cleanIp = (ipAddress || '127.0.0.1').trim();

    // Record attempt
    this.signupAttempts.push({
      identifier: cleanId,
      ipAddress: cleanIp,
      timestamp: now,
      success,
      reason,
    });

    // Prune expired attempts older than 2x window
    const windowMs = this.signupWindowSeconds * 1000;
    this.signupAttempts = this.signupAttempts.filter((a) => now - a.timestamp <= windowMs * 2);

    // Count attempts in window for matching identifier or IP
    const recentAttempts = this.signupAttempts.filter(
      (a) =>
        now - a.timestamp <= windowMs &&
        (a.identifier === cleanId || (cleanIp !== '127.0.0.1' && a.ipAddress === cleanIp))
    );

    const attemptCount = recentAttempts.length;
    const threshold = this.signupAttemptThreshold;

    // Trigger only when reaching or exceeding threshold
    if (attemptCount >= threshold) {
      const severity: Severity = attemptCount >= threshold + 3 ? 'CRITICAL' : 'HIGH';
      const existingUser = db.getUserByUsername(cleanId) || db.getUserByEmail(cleanId);

      const securityEvent: SecurityEventRecord = {
        id: db.getSecurityEvents().length + 1,
        eventType: 'MULTIPLE_SIGNUP_ATTEMPTS',
        userId: existingUser?.id,
        username: existingUser?.username,
        identifier: cleanId,
        ipAddress: cleanIp,
        timestamp: new Date().toISOString(),
        attemptCount,
        threshold,
        severity,
        description: `Unusually repeated registration attempts (${attemptCount} attempts within ${this.signupWindowSeconds}s window, threshold: ${threshold}) for identifier '${cleanId}'.`,
        status: 'OPEN',
        metadata: {
          identifier: cleanId,
          ipAddress: cleanIp,
          windowSeconds: this.signupWindowSeconds,
          threshold,
          totalRecentAttempts: attemptCount,
          lastReason: reason || 'Rapid registration submissions',
        },
      };

      db.addSecurityEvent(securityEvent);

      // Also create a correlating SIEM Alert
      const alertId = `ALT-SIGNUP-${Date.now().toString(36).toUpperCase()}-${Math.floor(Math.random() * 900 + 100)}`;
      const alert: Alert = {
        id: db.getAlerts().length + 1,
        alertId,
        userId: existingUser?.id || 0,
        username: existingUser?.username || cleanId,
        userDepartment: existingUser?.department || 'External Auth Gateway',
        title: `Suspicious Registration Abuse: ${cleanId}`,
        description: `Excessive registration / sign-up velocity detected from source ${cleanIp} targeting identifier '${cleanId}'. ${attemptCount} attempts in ${this.signupWindowSeconds}s window.`,
        severity,
        status: 'OPEN',
        riskScore: Math.min(100, 30 + attemptCount * 15),
        mlAnomalyScore: Math.min(100, 45 + attemptCount * 10),
        correlationKey: `ABUSE_SIGNUP_${cleanId}_${cleanIp}`,
        firstSeen: new Date(recentAttempts[0].timestamp).toISOString(),
        lastSeen: new Date().toISOString(),
        eventCount: attemptCount,
        findingCount: 1,
        evidence: [
          `Rapid registration burst: ${attemptCount} attempts within ${this.signupWindowSeconds} seconds`,
          `Target Identifier: ${cleanId}`,
          `Origin IP Address: ${cleanIp}`,
          `Configured Alert Threshold: ${threshold} attempts`,
        ],
        recommendations: [
          'Verify source IP address reputation against threat intelligence feeds',
          'Deploy CAPTCHA or progressive proof-of-work on public registration form',
          'Temporarily rate-limit origin IP subnet',
        ],
        policyViolations: ['SEC-POL-AUTH-RATE-LIMIT', 'SEC-POL-ACCOUNT-CREATION-ABUSE'],
        createdAt: new Date().toISOString(),
      };

      db.addAlert(alert);

      // Record in audit log
      db.addAuditLog({
        id: db.getAuditLogs().length + 1,
        actor: 'SECURITY_MONITOR',
        userId: existingUser?.id,
        action: 'ABUSE_ALERT_TRIGGERED',
        resource: `auth:signup:${cleanId}`,
        details: `Multiple signup abuse detected (${attemptCount} attempts, IP: ${cleanIp}). Alert ${alertId} dispatched.`,
        ipAddress: cleanIp,
        timestamp: new Date().toISOString(),
      });

      return {
        abuseDetected: true,
        attemptCount,
        securityEvent,
        alert,
      };
    }

    return {
      abuseDetected: false,
      attemptCount,
    };
  }

  /**
   * Track a failed file download attempt (e.g. non-existent, forbidden classification, corrupted)
   */
  public recordFailedDownload(
    fileId: string,
    reason: string,
    userId?: number,
    username?: string,
    ipAddress?: string
  ): {
    abuseDetected: boolean;
    failureCount: number;
    securityEvent?: SecurityEventRecord;
    alert?: Alert;
  } {
    const now = Date.now();
    const cleanUser = username || (userId ? `user_${userId}` : 'anonymous');
    const cleanIp = ipAddress || '10.14.88.100';

    this.failedDownloads.push({
      userId,
      username: cleanUser,
      fileId,
      ipAddress: cleanIp,
      timestamp: now,
      reason,
    });

    const windowMs = this.failedDownloadWindowSeconds * 1000;
    this.failedDownloads = this.failedDownloads.filter((d) => now - d.timestamp <= windowMs * 2);

    // Count failed downloads for this user or IP in window
    const recentFailures = this.failedDownloads.filter(
      (d) =>
        now - d.timestamp <= windowMs &&
        ((userId && d.userId === userId) || d.username === cleanUser || (cleanIp !== '127.0.0.1' && d.ipAddress === cleanIp))
    );

    const failureCount = recentFailures.length;
    const threshold = this.failedDownloadThreshold;

    if (failureCount >= threshold) {
      const severity: Severity = failureCount >= threshold + 3 ? 'CRITICAL' : 'HIGH';

      const securityEvent: SecurityEventRecord = {
        id: db.getSecurityEvents().length + 1,
        eventType: 'MULTIPLE_FAILED_DOWNLOADS',
        userId,
        username: cleanUser,
        identifier: cleanUser,
        ipAddress: cleanIp,
        timestamp: new Date().toISOString(),
        attemptCount: failureCount,
        threshold,
        severity,
        description: `Repeated failed file download attempts (${failureCount} failed downloads in ${this.failedDownloadWindowSeconds}s window, threshold: ${threshold}). Reason: ${reason}.`,
        status: 'OPEN',
        metadata: {
          fileId,
          failureReason: reason,
          userId,
          username: cleanUser,
          ipAddress: cleanIp,
          windowSeconds: this.failedDownloadWindowSeconds,
          threshold,
          totalRecentFailures: failureCount,
        },
      };

      db.addSecurityEvent(securityEvent);

      // Generate Alert
      const alertId = `ALT-DOWNLOAD-FAIL-${Date.now().toString(36).toUpperCase()}-${Math.floor(Math.random() * 900 + 100)}`;
      const alert: Alert = {
        id: db.getAlerts().length + 1,
        alertId,
        userId: userId || 0,
        username: cleanUser,
        userDepartment: 'Data Access & DLP',
        title: `Repeated Failed Downloads: ${cleanUser}`,
        description: `User ${cleanUser} triggered ${failureCount} failed file download attempts within ${this.failedDownloadWindowSeconds}s window (threshold ${threshold}). Potential probing or automated scraping attempt.`,
        severity,
        status: 'OPEN',
        riskScore: Math.min(100, 35 + failureCount * 15),
        mlAnomalyScore: Math.min(100, 50 + failureCount * 10),
        correlationKey: `ABUSE_FAILED_DOWNLOADS_${cleanUser}`,
        firstSeen: new Date(recentFailures[0].timestamp).toISOString(),
        lastSeen: new Date().toISOString(),
        eventCount: failureCount,
        findingCount: 1,
        evidence: [
          `${failureCount} failed download requests in ${this.failedDownloadWindowSeconds}s`,
          `Target File Resource: ${fileId}`,
          `Last Failure Reason: ${reason}`,
          `User Identifier: ${cleanUser} (IP: ${cleanIp})`,
        ],
        recommendations: [
          'Inspect user access permissions and role tier in file repository',
          'Review endpoint egress logs for unauthorized enumeration scripts',
          'Investigate potential session token hijacking or brute force file ID scanning',
        ],
        policyViolations: ['SEC-POL-FILE-EGRESS', 'SEC-POL-ACCESS-VIOLATION'],
        createdAt: new Date().toISOString(),
      };

      db.addAlert(alert);

      db.addAuditLog({
        id: db.getAuditLogs().length + 1,
        actor: 'SECURITY_MONITOR',
        userId,
        action: 'FAILED_DOWNLOAD_ALERT_TRIGGERED',
        resource: `file:${fileId}`,
        details: `Multiple failed download abuse (${failureCount} failures, user: ${cleanUser}). Alert ${alertId} dispatched.`,
        ipAddress: cleanIp,
        timestamp: new Date().toISOString(),
      });

      return {
        abuseDetected: true,
        failureCount,
        securityEvent,
        alert,
      };
    }

    return {
      abuseDetected: false,
      failureCount,
    };
  }

  /**
   * Reset in-memory trackers (used for testing or maintenance)
   */
  public resetTrackers(): void {
    this.signupAttempts = [];
    this.failedDownloads = [];
  }
}

export const securityAbuse = SecurityAbuseService.getInstance();
