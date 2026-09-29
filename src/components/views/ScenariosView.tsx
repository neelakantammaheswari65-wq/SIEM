import React, { useState } from 'react';
import { useSIEM } from '../../context/SIEMContext';
import { siemEngine } from '../../services/siemEngine';
import {
  PlayCircle,
  Zap,
  ArrowRight,
  ShieldAlert,
  Terminal,
  Activity,
  CheckCircle2,
  Eye,
  Clock,
  Shield,
  User,
} from 'lucide-react';

export const ScenariosView: React.FC = () => {
  const { injectScenario, setActiveTab, alerts, users, recalculateAllRisk } = useSIEM();
  const [runningScenario, setRunningScenario] = useState<string | null>(null);
  const [lastExecuted, setLastExecuted] = useState<string | null>(null);

  const targetUser = users.find((u) => u.username === 'amercer') || users[0];
  const targetEmployeeDisplay = `${targetUser?.fullName || 'Alex Mercer'} (@${targetUser?.username || 'amercer'} - ${targetUser?.employeeId || 'EMP-0101'})`;

  // The 7 canonical attack scenarios requested
  const scenarios = [
    {
      id: 'FAILED_LOGINS',
      threatType: 'Multiple Failed Logins',
      ruleId: 'RULE 001',
      description: 'Rapid series of 6 failed authentication attempts within a 2-minute window from an unverified host IP.',
      riskLevel: 'HIGH',
      affectedEmployee: targetEmployeeDisplay,
      execute: () => {
        injectScenario('BRUTE_FORCE');
      },
    },
    {
      id: 'UNAUTHORIZED_ACCESS',
      threatType: 'Unauthorized Access',
      ruleId: 'RULE 002',
      description: 'Zero-Trust RBAC violation: Standard employee token attempting unauthorized access to /api/admin/system/security-keys.',
      riskLevel: 'HIGH',
      affectedEmployee: targetEmployeeDisplay,
      execute: () => {
        injectScenario('UNAUTHORIZED_ACCESS');
      },
    },
    {
      id: 'UNUSUAL_TIME',
      threatType: 'Unusual Login Time',
      ruleId: 'RULE 003',
      description: 'Authentication activity detected at 03:15 AM UTC, well outside the employee’s regular baseline shift window.',
      riskLevel: 'MEDIUM',
      affectedEmployee: targetEmployeeDisplay,
      execute: () => {
        siemEngine.ingestLog({
          timestamp: new Date().toISOString(),
          userId: targetUser.id,
          username: targetUser.username,
          source: 'endpoint-agent',
          eventType: 'LOGIN',
          action: 'OFF_HOURS_AUTH',
          resource: 'Workstation-Win11',
          ipAddress: targetUser.ipAddress || '10.14.88.102',
          severity: 'MEDIUM',
          details: { login_hour_utc: 3, baseline_shift: '09:00 - 18:00', anomaly: 'Unusual Shift Window' },
        });
        siemEngine.recalculateRisk(targetUser.id);
        siemEngine.correlateAlertsForUser(targetUser.id);
        recalculateAllRisk();
      },
    },
    {
      id: 'UNUSUAL_LOCATION',
      threatType: 'Unusual Location',
      ruleId: 'RULE 004',
      description: 'Authentication session originating from an IP geolocation outside the defined corporate geofence boundary.',
      riskLevel: 'HIGH',
      affectedEmployee: targetEmployeeDisplay,
      execute: () => {
        siemEngine.ingestLog({
          timestamp: new Date().toISOString(),
          userId: targetUser.id,
          username: targetUser.username,
          source: 'auth-service',
          eventType: 'LOGIN',
          action: 'AUTH_SUCCESS_UNUSUAL_GEO',
          resource: 'Cloud-VPN-Gateway',
          ipAddress: '198.51.100.42',
          severity: 'HIGH',
          details: { geo_location: 'Kyiv, Ukraine', corporate_geofence: false, anomaly: 'Unusual Geographical Origin' },
        });
        siemEngine.recalculateRisk(targetUser.id);
        siemEngine.correlateAlertsForUser(targetUser.id);
        recalculateAllRisk();
      },
    },
    {
      id: 'SENSITIVE_FILES',
      threatType: 'Sensitive File Access',
      ruleId: 'RULE 005',
      description: 'Unauthorized read access to restricted executive repository: /vault/finance/M&A_Confidential_Brief.pdf.',
      riskLevel: 'CRITICAL',
      affectedEmployee: targetEmployeeDisplay,
      execute: () => {
        siemEngine.ingestLog({
          timestamp: new Date().toISOString(),
          userId: targetUser.id,
          username: targetUser.username,
          source: 'endpoint-agent',
          eventType: 'SENSITIVE_FILE_ACCESS',
          action: 'FILE_READ_RESTRICTED',
          resource: '/vault/finance/M&A_Confidential_Brief.pdf',
          ipAddress: targetUser.ipAddress || '10.14.88.102',
          severity: 'HIGH',
          details: { classification: 'HIGHLY_CONFIDENTIAL', file_size_mb: 34.5, sizeMb: 34.5 },
        });
        siemEngine.recalculateRisk(targetUser.id);
        siemEngine.correlateAlertsForUser(targetUser.id);
        recalculateAllRisk();
      },
    },
    {
      id: 'DATA_TRANSFER',
      threatType: 'Abnormal Data Transfer',
      ruleId: 'RULE 006',
      description: 'Massive archive egress transfer: 840 MB corporate backup downloaded in a single session.',
      riskLevel: 'HIGH',
      affectedEmployee: targetEmployeeDisplay,
      execute: () => {
        injectScenario('MASS_DOWNLOAD');
      },
    },
    {
      id: 'DEVICE_ACTIVITY',
      threatType: 'Unauthorized Device Activity',
      ruleId: 'RULE 007',
      description: 'Unregistered USB storage attached with policy violation and attempted 664.5 MB egress transfer.',
      riskLevel: 'CRITICAL',
      affectedEmployee: targetEmployeeDisplay,
      execute: () => {
        injectScenario('DISGRUNTLED_EXFIL');
      },
    },
  ];

  const handleRun = (scenario: typeof scenarios[0]) => {
    setRunningScenario(scenario.id);
    scenario.execute();
    setTimeout(() => {
      setRunningScenario(null);
      setLastExecuted(scenario.threatType);
    }, 600);
  };

  return (
    <div className="p-6 space-y-6 max-w-[1600px] mx-auto text-slate-200">
      {/* Top Section: Threat Simulation Lab */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-white tracking-tight">
            Threat Simulation Lab
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Deterministic attack scenarios to test detection rules, sliding windows, and alert correlation.
          </p>
        </div>

        {lastExecuted && (
          <button
            onClick={() => setActiveTab('alerts')}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#20C997]/15 border border-[#20C997]/30 text-[#20C997] text-xs font-semibold hover:bg-[#20C997]/25 cursor-pointer"
          >
            <CheckCircle2 className="w-3.5 h-3.5" />
            <span>Simulated: {lastExecuted} &rarr; View Alert</span>
          </button>
        )}
      </div>

      {/* Seven Clean Scenario Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {scenarios.map((sc) => {
          const isRunning = runningScenario === sc.id;

          const sevBadge =
            sc.riskLevel === 'CRITICAL'
              ? 'bg-[#FF5C6C]/10 text-[#FF5C6C] border-[#FF5C6C]/30'
              : sc.riskLevel === 'HIGH'
              ? 'bg-[#FFB020]/10 text-[#FFB020] border-[#FFB020]/30'
              : 'bg-[#5B8CFF]/10 text-[#5B8CFF] border-[#5B8CFF]/30';

          return (
            <div
              key={sc.id}
              className="soc-card p-5 flex flex-col justify-between space-y-4 hover:border-[#314366] transition-colors"
            >
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono font-bold text-[#5B8CFF]">
                    {sc.ruleId}
                  </span>
                  <span className={`text-[10px] px-2 py-0.5 rounded-full border font-medium ${sevBadge}`}>
                    {sc.riskLevel}
                  </span>
                </div>

                <div>
                  <h3 className="text-sm font-semibold text-white">
                    {sc.threatType}
                  </h3>
                  <p className="text-xs text-slate-300 mt-1 leading-relaxed">
                    {sc.description}
                  </p>
                </div>

                <div className="p-2.5 bg-[#0D1424] border border-[#22304A] rounded-lg text-xs space-y-1">
                  <span className="text-[10px] text-slate-400 block uppercase">
                    Affected Employee
                  </span>
                  <span className="text-slate-200 font-medium truncate block">
                    {sc.affectedEmployee}
                  </span>
                </div>
              </div>

              <div className="pt-3 border-t border-[#22304A] flex items-center justify-between">
                <span className="text-[11px] text-slate-400">
                  Target: SIEM Rule Pipeline
                </span>

                <button
                  onClick={() => handleRun(sc)}
                  disabled={isRunning}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#5B8CFF] hover:bg-[#4a7cee] text-white text-xs font-semibold transition-colors cursor-pointer disabled:opacity-50"
                >
                  <PlayCircle className={`w-3.5 h-3.5 ${isRunning ? 'animate-spin' : ''}`} />
                  <span>{isRunning ? 'Simulating...' : 'Run Simulation'}</span>
                </button>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
