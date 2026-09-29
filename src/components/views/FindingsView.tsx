import React, { useState } from 'react';
import { useSIEM } from '../../context/SIEMContext';
import {
  FileText,
  Download,
  ShieldAlert,
  Terminal,
  Activity,
  Users,
  CheckCircle2,
  Scale,
  Calendar,
  Layers,
  PieChart,
} from 'lucide-react';

export const FindingsView: React.FC = () => {
  const { summary, alerts, events, riskScores, users, rules, findings } = useSIEM();
  const [reportPeriod, setReportPeriod] = useState<'24h' | '7d' | '30d'>('24h');

  // Risk Distribution Buckets
  const critRisk = riskScores.filter((r) => r.finalScore >= 75).length;
  const highRisk = riskScores.filter((r) => r.finalScore >= 50 && r.finalScore < 75).length;
  const medRisk = riskScores.filter((r) => r.finalScore >= 25 && r.finalScore < 50).length;
  const lowRisk = riskScores.filter((r) => r.finalScore < 25).length;
  const totalScored = riskScores.length || 1;

  // Rule Trigger Stats
  const ruleStats = rules.map((r) => {
    const count = findings.filter(
      (f) => f.ruleCode === r.ruleCode || f.ruleId === r.id
    ).length;
    return {
      code: r.ruleCode,
      name: r.name,
      severity: r.severity,
      count,
    };
  });

  // Top Risk Users
  const topUsers = [...riskScores]
    .sort((a, b) => b.finalScore - a.finalScore)
    .slice(0, 5)
    .map((r) => {
      const u = users.find((usr) => usr.id === r.userId);
      return {
        name: u?.fullName || `User #${r.userId}`,
        empId: u?.employeeId || `EMP-${r.userId}`,
        department: u?.department || 'Operations',
        score: r.finalScore,
        level: r.riskLevel,
      };
    });

  const handleDownloadReport = () => {
    const reportData = {
      generatedAt: new Date().toISOString(),
      reportPeriod,
      threatSummary: {
        totalEvents: summary.totalEvents,
        openAlerts: summary.openAlerts,
        criticalAlerts: summary.criticalAlerts,
        highRiskUsers: summary.highRiskUsers,
        avgRiskScore: summary.avgRiskScore,
      },
      severityBreakdown: {
        critical: alerts.filter((a) => a.severity === 'CRITICAL').length,
        high: alerts.filter((a) => a.severity === 'HIGH').length,
        medium: alerts.filter((a) => a.severity === 'MEDIUM').length,
        low: alerts.filter((a) => a.severity === 'LOW').length,
      },
      riskDistribution: {
        criticalUsers: critRisk,
        highRiskUsers: highRisk,
        mediumRiskUsers: medRisk,
        lowRiskUsers: lowRisk,
      },
      topRiskPersonnel: topUsers,
      ruleTriggerStatistics: ruleStats,
    };

    const dataStr =
      'data:text/json;charset=utf-8,' +
      encodeURIComponent(JSON.stringify(reportData, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute(
      'download',
      `siem_soc_threat_report_${reportPeriod}_${new Date().toISOString().split('T')[0]}.json`
    );
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.removeChild(downloadAnchor);
  };

  return (
    <div className="p-6 space-y-6 max-w-[1600px] mx-auto text-slate-200">
      {/* Top Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-white tracking-tight">
            Security Intelligence & Reports
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Consolidated threat posture, risk distribution analytics, and rule trigger intelligence.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className="flex items-center bg-[#0D1424] border border-[#22304A] rounded-lg p-0.5 text-xs">
            <button
              onClick={() => setReportPeriod('24h')}
              className={`px-3 py-1 rounded-md transition-colors cursor-pointer ${
                reportPeriod === '24h'
                  ? 'bg-[#111A2C] text-white font-semibold shadow-sm'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              24h
            </button>
            <button
              onClick={() => setReportPeriod('7d')}
              className={`px-3 py-1 rounded-md transition-colors cursor-pointer ${
                reportPeriod === '7d'
                  ? 'bg-[#111A2C] text-white font-semibold shadow-sm'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              7d
            </button>
            <button
              onClick={() => setReportPeriod('30d')}
              className={`px-3 py-1 rounded-md transition-colors cursor-pointer ${
                reportPeriod === '30d'
                  ? 'bg-[#111A2C] text-white font-semibold shadow-sm'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              30d
            </button>
          </div>

          <button
            onClick={handleDownloadReport}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#5B8CFF] hover:bg-[#4a7cee] text-white text-xs font-semibold cursor-pointer"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Download Report</span>
          </button>
        </div>
      </div>

      {/* 1. Threat Summary & Security Events KPI Grid */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="soc-card p-4">
          <div className="text-xs font-semibold uppercase tracking-wider text-slate-400">
            THREAT SUMMARY
          </div>
          <div className="text-2xl font-bold font-mono text-white mt-2">
            {summary.openAlerts} Open
          </div>
          <div className="text-[11px] text-slate-400 mt-1">
            {summary.criticalAlerts} Critical Incidents
          </div>
        </div>

        <div className="soc-card p-4">
          <div className="text-xs font-semibold uppercase tracking-wider text-slate-400">
            SECURITY EVENTS
          </div>
          <div className="text-2xl font-bold font-mono text-[#5B8CFF] mt-2">
            {summary.totalEvents.toLocaleString()}
          </div>
          <div className="text-[11px] text-slate-400 mt-1">
            {events.length} Normalized records
          </div>
        </div>

        <div className="soc-card p-4">
          <div className="text-xs font-semibold uppercase tracking-wider text-slate-400">
            AVERAGE RISK
          </div>
          <div className="text-2xl font-bold font-mono text-[#FFB020] mt-2">
            {summary.avgRiskScore} / 100
          </div>
          <div className="text-[11px] text-slate-400 mt-1">
            Decayed baseline score
          </div>
        </div>

        <div className="soc-card p-4">
          <div className="text-xs font-semibold uppercase tracking-wider text-slate-400">
            HIGH-RISK PERSONNEL
          </div>
          <div className="text-2xl font-bold font-mono text-[#FF5C6C] mt-2">
            {summary.highRiskUsers}
          </div>
          <div className="text-[11px] text-slate-400 mt-1">
            Score &gt;= 50 threshold
          </div>
        </div>
      </div>

      {/* 2. Risk Distribution & Alert Summary */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Risk Distribution Card */}
        <div className="soc-card p-5 space-y-4">
          <div>
            <h2 className="text-sm font-semibold text-white tracking-tight">
              Risk Score Distribution
            </h2>
            <p className="text-xs text-slate-400">
              Employee risk classification across all evaluated principals
            </p>
          </div>

          <div className="space-y-3">
            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="text-slate-300 font-medium">Critical Risk (75 - 100)</span>
                <span className="font-mono text-[#FF5C6C] font-bold">{critRisk} users</span>
              </div>
              <div className="w-full bg-[#0D1424] rounded-full h-2 border border-[#22304A]">
                <div
                  className="bg-[#FF5C6C] h-full rounded-full"
                  style={{ width: `${(critRisk / totalScored) * 100}%` }}
                />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="text-slate-300 font-medium">High Risk (50 - 74)</span>
                <span className="font-mono text-[#FFB020] font-bold">{highRisk} users</span>
              </div>
              <div className="w-full bg-[#0D1424] rounded-full h-2 border border-[#22304A]">
                <div
                  className="bg-[#FFB020] h-full rounded-full"
                  style={{ width: `${(highRisk / totalScored) * 100}%` }}
                />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="text-slate-300 font-medium">Medium Risk (25 - 49)</span>
                <span className="font-mono text-[#5B8CFF] font-bold">{medRisk} users</span>
              </div>
              <div className="w-full bg-[#0D1424] rounded-full h-2 border border-[#22304A]">
                <div
                  className="bg-[#5B8CFF] h-full rounded-full"
                  style={{ width: `${(medRisk / totalScored) * 100}%` }}
                />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="text-slate-300 font-medium">Low / Baseline (&lt; 25)</span>
                <span className="font-mono text-[#20C997] font-bold">{lowRisk} users</span>
              </div>
              <div className="w-full bg-[#0D1424] rounded-full h-2 border border-[#22304A]">
                <div
                  className="bg-[#20C997] h-full rounded-full"
                  style={{ width: `${(lowRisk / totalScored) * 100}%` }}
                />
              </div>
            </div>
          </div>
        </div>

        {/* Alert Summary Card */}
        <div className="soc-card p-5 space-y-4">
          <div>
            <h2 className="text-sm font-semibold text-white tracking-tight">
              Alert Summary
            </h2>
            <p className="text-xs text-slate-400">
              Severity distribution and incident lifecycle status
            </p>
          </div>

          <div className="grid grid-cols-2 gap-3 text-xs">
            <div className="p-3 bg-[#0D1424] border border-[#22304A] rounded-lg">
              <span className="text-slate-400 block text-[10px] uppercase">Critical Alerts</span>
              <span className="text-xl font-bold font-mono text-[#FF5C6C]">
                {alerts.filter((a) => a.severity === 'CRITICAL').length}
              </span>
            </div>
            <div className="p-3 bg-[#0D1424] border border-[#22304A] rounded-lg">
              <span className="text-slate-400 block text-[10px] uppercase">High Alerts</span>
              <span className="text-xl font-bold font-mono text-[#FFB020]">
                {alerts.filter((a) => a.severity === 'HIGH').length}
              </span>
            </div>
            <div className="p-3 bg-[#0D1424] border border-[#22304A] rounded-lg">
              <span className="text-slate-400 block text-[10px] uppercase">Medium Alerts</span>
              <span className="text-xl font-bold font-mono text-[#5B8CFF]">
                {alerts.filter((a) => a.severity === 'MEDIUM').length}
              </span>
            </div>
            <div className="p-3 bg-[#0D1424] border border-[#22304A] rounded-lg">
              <span className="text-slate-400 block text-[10px] uppercase">Resolved / Closed</span>
              <span className="text-xl font-bold font-mono text-[#20C997]">
                {alerts.filter((a) => a.status === 'RESOLVED').length}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* 3. Rule Trigger Statistics & Top Risk Users */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Rule Trigger Statistics */}
        <div className="soc-card p-5 space-y-4">
          <div>
            <h2 className="text-sm font-semibold text-white tracking-tight">
              Rule Trigger Statistics
            </h2>
            <p className="text-xs text-slate-400">
              Detection frequency per correlation rule module
            </p>
          </div>

          <div className="space-y-2.5">
            {ruleStats.map((r, i) => (
              <div
                key={i}
                className="p-2.5 bg-[#0D1424] border border-[#22304A] rounded-lg flex items-center justify-between text-xs"
              >
                <div>
                  <div className="font-semibold text-white">{r.name}</div>
                  <div className="text-[10px] text-slate-400 font-mono">{r.code}</div>
                </div>

                <div className="text-right">
                  <span className="font-mono font-bold text-[#5B8CFF]">
                    {r.count} triggers
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Top Risk Users */}
        <div className="soc-card p-5 space-y-4">
          <div>
            <h2 className="text-sm font-semibold text-white tracking-tight">
              Top Risk Users
            </h2>
            <p className="text-xs text-slate-400">
              Personnel exhibiting highest risk deviation
            </p>
          </div>

          <div className="space-y-2.5">
            {topUsers.map((u, i) => (
              <div
                key={i}
                className="p-2.5 bg-[#0D1424] border border-[#22304A] rounded-lg flex items-center justify-between text-xs"
              >
                <div>
                  <div className="font-semibold text-white">{u.name}</div>
                  <div className="text-[10px] text-slate-400">{u.empId} · {u.department}</div>
                </div>

                <div className="text-right">
                  <span className="font-mono font-bold text-[#FF5C6C]">
                    {u.score} / 100
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
