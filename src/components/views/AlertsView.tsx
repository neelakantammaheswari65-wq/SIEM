import React, { useState } from 'react';
import { useSIEM } from '../../context/SIEMContext';
import { Alert, AlertStatus, Severity } from '../../types/siem';
import { api } from '../../services/apiClient';
import {
  ShieldAlert,
  Search,
  Filter,
  CheckCircle2,
  AlertTriangle,
  Clock,
  User,
  Activity,
  FileText,
  X,
  Eye,
  Check,
  Ban,
  Sparkles,
  ExternalLink,
  ChevronRight,
  Shield,
} from 'lucide-react';

export const AlertsView: React.FC = () => {
  const {
    alerts,
    selectedAlert,
    setSelectedAlert,
    acknowledgeAlert,
    resolveAlert,
    markFalsePositive,
    users,
  } = useSIEM();

  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');

  // AI narrative state
  const [aiLoading, setAiLoading] = useState(false);
  const [aiNarrative, setAiNarrative] = useState<{
    alertId: string;
    narrative: string;
    source: string;
    fallback: boolean;
  } | null>(null);
  const [aiNotice, setAiNotice] = useState<string | null>(null);

  // Five top metrics: Critical, High, Medium, Low, Open
  const critAlerts = alerts.filter((a) => a.severity === 'CRITICAL');
  const highAlerts = alerts.filter((a) => a.severity === 'HIGH');
  const medAlerts = alerts.filter((a) => a.severity === 'MEDIUM');
  const lowAlerts = alerts.filter((a) => a.severity === 'LOW');
  const openAlerts = alerts.filter((a) => a.status === 'OPEN');

  const handleRequestAiAnalysis = async (alertId: string) => {
    setAiLoading(true);
    setAiNotice(null);
    try {
      const res = await api.soc.getAlertNarrative(alertId);
      if (res && res.narrative) {
        setAiNarrative({
          alertId,
          narrative: res.narrative,
          source: res.source,
          fallback: !!res.fallback,
        });
        if (res.fallback) {
          setAiNotice('AI analysis temporarily unavailable — using local detection.');
        }
      }
    } catch (err: any) {
      setAiNotice('AI analysis temporarily unavailable — using local detection.');
      if (selectedAlert) {
        setAiNarrative({
          alertId,
          narrative: `[Local SOC Rule Engine] Incident ${alertId} involves anomalous high-severity behavior by user @${selectedAlert.username}. Multi-dimensional telemetry detected correlated policy violations across ${selectedAlert.evidence.length} evidence indicators. Calculated Risk Score: ${selectedAlert.riskScore}/100. Immediate containment action: verify user credentials, restrict credential tokens, and evaluate device authorization status.`,
          source: 'local_engine',
          fallback: true,
        });
      }
    } finally {
      setAiLoading(false);
    }
  };

  const filteredAlerts = alerts.filter((alert) => {
    if (!alert) return false;
    const matchesSearch =
      (alert.title || '').toLowerCase().includes(search.toLowerCase()) ||
      (alert.username || '').toLowerCase().includes(search.toLowerCase()) ||
      (alert.alertId || '').toLowerCase().includes(search.toLowerCase()) ||
      (alert.description || '').toLowerCase().includes(search.toLowerCase());

    const matchesSeverity = severityFilter === 'ALL' || alert.severity === severityFilter;
    const matchesStatus = statusFilter === 'ALL' || alert.status === statusFilter;

    return matchesSearch && matchesSeverity && matchesStatus;
  });

  return (
    <div className="p-6 space-y-6 max-w-[1600px] mx-auto text-slate-200">
      {/* Header Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-white tracking-tight">
            Alert Center
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Investigate, triage, and respond to correlated insider threat incidents.
          </p>
        </div>

        <div className="text-xs font-mono text-slate-400 bg-[#111A2C] px-3 py-1.5 rounded-lg border border-[#22304A]">
          Total Alerts: <strong className="text-white">{alerts.length}</strong>
        </div>
      </div>

      {/* Top 5 Metrics: Critical, High, Medium, Low, Open */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3.5">
        {/* Critical */}
        <div className="soc-card p-3.5 flex flex-col justify-between">
          <div className="flex items-center justify-between text-xs text-slate-400 font-medium">
            <span>Critical</span>
            <span className="w-2 h-2 rounded-full bg-[#FF5C6C]" />
          </div>
          <div className="mt-2">
            <span className="text-2xl font-bold font-mono text-[#FF5C6C]">
              {critAlerts.length}
            </span>
            <span className="text-[11px] text-slate-400 block mt-0.5">SLA &lt;15m</span>
          </div>
        </div>

        {/* High */}
        <div className="soc-card p-3.5 flex flex-col justify-between">
          <div className="flex items-center justify-between text-xs text-slate-400 font-medium">
            <span>High</span>
            <span className="w-2 h-2 rounded-full bg-[#FFB020]" />
          </div>
          <div className="mt-2">
            <span className="text-2xl font-bold font-mono text-[#FFB020]">
              {highAlerts.length}
            </span>
            <span className="text-[11px] text-slate-400 block mt-0.5">SLA &lt;1h</span>
          </div>
        </div>

        {/* Medium */}
        <div className="soc-card p-3.5 flex flex-col justify-between">
          <div className="flex items-center justify-between text-xs text-slate-400 font-medium">
            <span>Medium</span>
            <span className="w-2 h-2 rounded-full bg-[#5B8CFF]" />
          </div>
          <div className="mt-2">
            <span className="text-2xl font-bold font-mono text-[#5B8CFF]">
              {medAlerts.length}
            </span>
            <span className="text-[11px] text-slate-400 block mt-0.5">SLA &lt;4h</span>
          </div>
        </div>

        {/* Low */}
        <div className="soc-card p-3.5 flex flex-col justify-between">
          <div className="flex items-center justify-between text-xs text-slate-400 font-medium">
            <span>Low</span>
            <span className="w-2 h-2 rounded-full bg-[#20C997]" />
          </div>
          <div className="mt-2">
            <span className="text-2xl font-bold font-mono text-[#20C997]">
              {lowAlerts.length}
            </span>
            <span className="text-[11px] text-slate-400 block mt-0.5">Standard</span>
          </div>
        </div>

        {/* Open */}
        <div className="soc-card p-3.5 flex flex-col justify-between">
          <div className="flex items-center justify-between text-xs text-slate-400 font-medium">
            <span>Open (Action Req.)</span>
            <span className="w-2 h-2 rounded-full bg-[#8B7CFF] animate-pulse" />
          </div>
          <div className="mt-2">
            <span className="text-2xl font-bold font-mono text-[#8B7CFF]">
              {openAlerts.length}
            </span>
            <span className="text-[11px] text-slate-400 block mt-0.5">Active triage</span>
          </div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="soc-card p-4 grid grid-cols-1 sm:grid-cols-3 gap-3">
        <div className="relative">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search alert ID, employee, title..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full bg-[#0D1424] border border-[#22304A] rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-400 focus:outline-none focus:border-[#5B8CFF]"
          />
        </div>

        <div>
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="w-full bg-[#0D1424] border border-[#22304A] rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-[#5B8CFF]"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
        </div>

        <div>
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="w-full bg-[#0D1424] border border-[#22304A] rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-[#5B8CFF]"
          >
            <option value="ALL">All Statuses</option>
            <option value="OPEN">Open</option>
            <option value="ACKNOWLEDGED">Acknowledged</option>
            <option value="RESOLVED">Resolved</option>
            <option value="FALSE_POSITIVE">False Positive</option>
          </select>
        </div>
      </div>

      {/* Alert List Cards */}
      <div className="space-y-3">
        {filteredAlerts.length === 0 ? (
          <div className="soc-card p-8 text-center text-xs text-slate-400">
            No alerts match the selected criteria.
          </div>
        ) : (
          filteredAlerts.map((alt) => {
            const userObj = users.find((u) => u.id === alt.userId);
            const empCode = userObj ? `${userObj.fullName} (@${alt.username})` : `@${alt.username}`;

            const sevBadge =
              alt.severity === 'CRITICAL'
                ? 'bg-[#FF5C6C]/10 text-[#FF5C6C] border-[#FF5C6C]/30'
                : alt.severity === 'HIGH'
                ? 'bg-[#FFB020]/10 text-[#FFB020] border-[#FFB020]/30'
                : alt.severity === 'MEDIUM'
                ? 'bg-[#5B8CFF]/10 text-[#5B8CFF] border-[#5B8CFF]/30'
                : 'bg-[#20C997]/10 text-[#20C997] border-[#20C997]/30';

            const statusBadge =
              alt.status === 'OPEN'
                ? 'bg-[#FF5C6C]/10 text-[#FF5C6C] border-[#FF5C6C]/30'
                : alt.status === 'ACKNOWLEDGED'
                ? 'bg-[#FFB020]/10 text-[#FFB020] border-[#FFB020]/30'
                : alt.status === 'RESOLVED'
                ? 'bg-[#20C997]/10 text-[#20C997] border-[#20C997]/30'
                : 'bg-slate-800 text-slate-400 border-slate-700';

            return (
              <div
                key={alt.id}
                onClick={() => setSelectedAlert(alt)}
                className="soc-card p-4 space-y-3 hover:border-[#314366] transition-colors cursor-pointer"
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono font-bold text-[#5B8CFF]">
                      {alt.alertId}
                    </span>
                    <span className={`text-[10px] px-2 py-0.5 rounded-full border font-medium ${sevBadge}`}>
                      {alt.severity}
                    </span>
                    <span className={`text-[10px] px-2 py-0.5 rounded-full border font-medium ${statusBadge}`}>
                      {alt.status}
                    </span>
                  </div>

                  <div className="text-xs font-mono text-slate-400">
                    {new Date(alt.lastSeen).toLocaleString()}
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-12 gap-3 items-center">
                  <div className="md:col-span-8">
                    <h3 className="text-sm font-semibold text-white">
                      {alt.title}
                    </h3>
                    <p className="text-xs text-slate-300 mt-1">
                      {alt.description}
                    </p>
                    <div className="text-xs text-slate-400 mt-1.5 flex items-center gap-2">
                      <span>Employee: <strong className="text-white">{empCode}</strong></span>
                      <span>·</span>
                      <span>Evidence: {alt.evidence.length} indicators</span>
                    </div>
                  </div>

                  <div className="md:col-span-4 flex items-center justify-end gap-3">
                    <div className="text-right">
                      <span className="text-[10px] text-slate-400 block uppercase">Risk Score</span>
                      <span className="text-lg font-bold font-mono text-white">
                        {alt.riskScore} <span className="text-xs text-slate-500">/ 100</span>
                      </span>
                    </div>

                    <div className="flex items-center gap-1.5">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedAlert(alt);
                        }}
                        className="px-2.5 py-1.5 rounded-lg bg-[#0D1424] hover:bg-[#1E2B42] text-xs text-[#5B8CFF] border border-[#22304A] cursor-pointer"
                      >
                        Investigate
                      </button>

                      {alt.status === 'OPEN' && (
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            acknowledgeAlert(alt.id);
                          }}
                          className="px-2.5 py-1.5 rounded-lg bg-[#FFB020]/15 hover:bg-[#FFB020]/25 text-xs text-[#FFB020] border border-[#FFB020]/30 cursor-pointer"
                        >
                          Ack
                        </button>
                      )}

                      {alt.status !== 'RESOLVED' && (
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            resolveAlert(alt.id);
                          }}
                          className="px-2.5 py-1.5 rounded-lg bg-[#20C997]/15 hover:bg-[#20C997]/25 text-xs text-[#20C997] border border-[#20C997]/30 cursor-pointer"
                        >
                          Resolve
                        </button>
                      )}
                    </div>
                  </div>
                </div>
              </div>
            );
          })
        )}
      </div>

      {/* Selected Incident Drawer */}
      {selectedAlert && (
        <div className="fixed inset-0 z-50 bg-black/60 flex items-center justify-end">
          <div className="bg-[#111A2C] border-l border-[#22304A] w-full max-w-xl h-full p-6 space-y-5 overflow-y-auto animate-in slide-in-from-right duration-200 shadow-2xl">
            <div className="flex items-center justify-between border-b border-[#22304A] pb-4">
              <div>
                <span className="text-xs font-mono text-[#5B8CFF] font-bold">
                  {selectedAlert.alertId}
                </span>
                <h2 className="text-base font-bold text-white mt-1">
                  {selectedAlert.title}
                </h2>
              </div>
              <button
                onClick={() => setSelectedAlert(null)}
                className="text-slate-400 hover:text-white text-xs cursor-pointer p-1"
              >
                ✕ Close
              </button>
            </div>

            {/* Quick Status / Actions */}
            <div className="p-3 bg-[#0D1424] border border-[#22304A] rounded-lg flex items-center justify-between text-xs">
              <div>
                <span className="text-slate-400 text-[10px] block">STATUS</span>
                <span className="font-semibold text-white">{selectedAlert.status}</span>
              </div>
              <div className="space-x-1.5">
                {selectedAlert.status === 'OPEN' && (
                  <button
                    onClick={() => acknowledgeAlert(selectedAlert.id)}
                    className="px-3 py-1 rounded-lg bg-[#FFB020]/15 text-[#FFB020] text-xs font-semibold border border-[#FFB020]/30 cursor-pointer"
                  >
                    Acknowledge
                  </button>
                )}
                <button
                  onClick={() => resolveAlert(selectedAlert.id)}
                  className="px-3 py-1 rounded-lg bg-[#20C997]/15 text-[#20C997] text-xs font-semibold border border-[#20C997]/30 cursor-pointer"
                >
                  Resolve Incident
                </button>
                <button
                  onClick={() => markFalsePositive(selectedAlert.id)}
                  className="px-3 py-1 rounded-lg bg-[#111A2C] text-slate-300 text-xs border border-[#22304A] cursor-pointer"
                >
                  False Positive
                </button>
              </div>
            </div>

            {/* Details */}
            <div className="space-y-2">
              <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                Target Employee & Impact
              </h3>
              <div className="bg-[#0D1424] border border-[#22304A] rounded-lg p-3 text-xs space-y-1.5">
                <div className="flex justify-between">
                  <span className="text-slate-400">Employee:</span>
                  <span className="text-white font-medium">@{selectedAlert.username}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Risk Score:</span>
                  <span className="text-[#FF5C6C] font-bold font-mono">{selectedAlert.riskScore} / 100</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">First Observation:</span>
                  <span className="text-slate-300">{new Date(selectedAlert.firstSeen).toLocaleTimeString()}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Last Observation:</span>
                  <span className="text-slate-300">{new Date(selectedAlert.lastSeen).toLocaleTimeString()}</span>
                </div>
              </div>
            </div>

            {/* Contributing Factors */}
            <div className="space-y-2">
              <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                Contributing Evidence ({selectedAlert.evidence.length} Indicators)
              </h3>
              <div className="space-y-1.5 max-h-48 overflow-y-auto">
                {selectedAlert.evidence.map((ev, i) => (
                  <div key={i} className="p-2.5 bg-[#0D1424] border border-[#22304A] rounded-lg text-xs">
                    <div className="flex justify-between text-slate-200 font-medium">
                      <span>{ev.findingSummary}</span>
                      <span className="text-[#FFB020] font-mono">+{ev.weight} Risk</span>
                    </div>
                    <div className="text-[10px] text-slate-400 mt-0.5">
                      Rule: {ev.ruleCode} · Ref: {ev.logId}
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* On-Demand AI Incident Narrative */}
            <div className="pt-2 border-t border-[#22304A] space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-slate-400 uppercase">
                  AI Incident Narrative
                </span>
                <button
                  onClick={() => handleRequestAiAnalysis(selectedAlert.alertId)}
                  disabled={aiLoading}
                  className="flex items-center gap-1.5 px-3 py-1 rounded-lg bg-[#5B8CFF]/15 hover:bg-[#5B8CFF]/25 text-[#5B8CFF] text-xs font-medium border border-[#5B8CFF]/30 cursor-pointer"
                >
                  <Sparkles className="w-3.5 h-3.5" />
                  <span>{aiLoading ? 'Analyzing...' : 'Generate Narrative'}</span>
                </button>
              </div>

              {aiNotice && (
                <div className="text-xs text-[#FFB020] bg-[#FFB020]/10 p-2.5 rounded-lg border border-[#FFB020]/20">
                  {aiNotice}
                </div>
              )}

              {aiNarrative && aiNarrative.alertId === selectedAlert.alertId && (
                <div className="p-3 bg-[#0D1424] border border-[#22304A] rounded-lg text-xs text-slate-200 leading-relaxed">
                  {aiNarrative.narrative}
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
