import React, { useState } from 'react';
import { useSIEM } from '../../context/SIEMContext';
import { Rule, EventType, Severity } from '../../types/siem';
import {
  Scale,
  Play,
  CheckCircle2,
  XCircle,
  Code,
  Shield,
  Clock,
  Terminal,
  Activity,
  Plus,
  Sliders,
} from 'lucide-react';

export const RulesView: React.FC = () => {
  const { rules, toggleRule, createRule, findings } = useSIEM();

  // Test Sandbox State
  const [testEventType, setTestEventType] = useState<EventType>('USB_TRANSFER_REQUEST');
  const [testPayload, setTestPayload] = useState(`{
  "total_size_mb": 650,
  "sensitive_file_count": 2,
  "authorized": false
}`);
  const [sandboxResult, setSandboxResult] = useState<any[] | null>(null);

  // New Rule Modal State
  const [showAddModal, setShowAddModal] = useState(false);
  const [newCode, setNewCode] = useState('');
  const [newName, setNewName] = useState('');
  const [newDesc, setNewDesc] = useState('');
  const [newType, setNewType] = useState<EventType>('SENSITIVE_FILE_ACCESS');
  const [newSev, setNewSev] = useState<Severity>('HIGH');
  const [newWeight, setNewWeight] = useState(30);

  // The 7 canonical detection module metadata mapping
  const ruleDisplayConfig: Record<string, { code: string; title: string; category: string }> = {
    MULTIPLE_FAILED_LOGINS: { code: 'RULE 001', title: 'Multiple Failed Logins', category: 'Authentication & Brute Force' },
    'RULE-001': { code: 'RULE 001', title: 'Multiple Failed Logins', category: 'Authentication & Brute Force' },
    UNAUTHORIZED_ACCESS: { code: 'RULE 002', title: 'Unauthorized Access', category: 'Access Control & RBAC' },
    'RULE-002': { code: 'RULE 002', title: 'Unauthorized Access', category: 'Access Control & RBAC' },
    UNUSUAL_LOGIN_TIME: { code: 'RULE 003', title: 'Unusual Login Time', category: 'Temporal Anomaly' },
    'RULE-003': { code: 'RULE 003', title: 'Unusual Login Time', category: 'Temporal Anomaly' },
    UNUSUAL_LOCATION: { code: 'RULE 004', title: 'Unusual Location / IP', category: 'Geofence & Subnet' },
    'RULE-004': { code: 'RULE 004', title: 'Unusual Location / IP', category: 'Geofence & Subnet' },
    SENSITIVE_FILE_ACCESS: { code: 'RULE 005', title: 'Sensitive File Access', category: 'Data Governance & DLP' },
    'RULE-005': { code: 'RULE 005', title: 'Sensitive File Access', category: 'Data Governance & DLP' },
    LARGE_FILE_DOWNLOAD: { code: 'RULE 006', title: 'Abnormal Data Transfer', category: 'Network Egress & Hoarding' },
    'RULE-006': { code: 'RULE 006', title: 'Abnormal Data Transfer', category: 'Network Egress & Hoarding' },
    USB_UNAUTHORIZED: { code: 'RULE 007', title: 'Unauthorized USB / Device Activity', category: 'Endpoint & Peripheral DLP' },
    'RULE-007': { code: 'RULE 007', title: 'Unauthorized USB / Device Activity', category: 'Endpoint & Peripheral DLP' },
  };

  const handleTestSandbox = (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const parsed = JSON.parse(testPayload);
      const matches: any[] = [];

      const activeRules = rules.filter((r) => r.enabled && r.eventType === testEventType);
      for (const rule of activeRules) {
        let isMatch = true;
        for (const cond of rule.conditions) {
          const val = parsed[cond.field];
          if (cond.operator === '==' && val !== cond.value) isMatch = false;
          if (cond.operator === '!=' && val === cond.value) isMatch = false;
          if (cond.operator === '>' && Number(val) <= Number(cond.value)) isMatch = false;
          if (cond.operator === '<' && Number(val) >= Number(cond.value)) isMatch = false;
          if (cond.operator === 'in' && Array.isArray(cond.value) && !cond.value.includes(val)) isMatch = false;
        }

        if (isMatch) {
          matches.push({
            ruleCode: rule.ruleCode,
            name: rule.name,
            severity: rule.severity,
            riskWeight: rule.riskWeight,
            description: rule.description,
          });
        }
      }

      setSandboxResult(matches);
    } catch (err: any) {
      alert(`Invalid JSON format: ${err.message}`);
    }
  };

  const handleCreateRule = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newCode || !newName) return;
    createRule({
      ruleCode: newCode.toUpperCase().replace(/\s+/g, '_'),
      name: newName,
      description: newDesc,
      eventType: newType,
      severity: newSev,
      riskWeight: Number(newWeight),
      conditions: [{ field: 'action', operator: '==', value: 'UNAUTHORIZED' }],
    });
    setShowAddModal(false);
  };

  return (
    <div className="p-6 space-y-6 max-w-[1600px] mx-auto text-slate-200">
      {/* Top Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-white tracking-tight">
            Detection Rules
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Deterministic correlation rules and anomaly detection triggers.
          </p>
        </div>

        <button
          onClick={() => setShowAddModal(true)}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#5B8CFF] hover:bg-[#4a7cee] text-white text-xs font-semibold transition-colors cursor-pointer"
        >
          <Plus className="w-3.5 h-3.5" />
          <span>New Detection Rule</span>
        </button>
      </div>

      {/* ==================================================
          SECTION 12: SEVEN RULE CARDS
          ================================================== */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {rules.map((rule) => {
          const cfg = ruleDisplayConfig[rule.ruleCode] || {
            code: rule.ruleCode,
            title: rule.name,
            category: 'Custom Rule',
          };

          // Find findings triggered by this rule
          const triggerCount = findings.filter(
            (f) => f.ruleCode === rule.ruleCode || f.ruleCode === cfg.code
          ).length;

          const sevBadge =
            rule.severity === 'CRITICAL'
              ? 'bg-[#FF5C6C]/10 text-[#FF5C6C] border-[#FF5C6C]/30'
              : rule.severity === 'HIGH'
              ? 'bg-[#FFB020]/10 text-[#FFB020] border-[#FFB020]/30'
              : rule.severity === 'MEDIUM'
              ? 'bg-[#5B8CFF]/10 text-[#5B8CFF] border-[#5B8CFF]/30'
              : 'bg-[#20C997]/10 text-[#20C997] border-[#20C997]/30';

          return (
            <div
              key={rule.id}
              className="soc-card p-5 flex flex-col justify-between space-y-4 hover:border-[#314366] transition-colors"
            >
              <div className="space-y-3">
                {/* Header: Rule Number & Severity */}
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono font-bold text-[#5B8CFF] tracking-wider uppercase">
                    {cfg.code}
                  </span>
                  <span className={`text-[10px] px-2 py-0.5 rounded-full border font-medium ${sevBadge}`}>
                    {rule.severity}
                  </span>
                </div>

                {/* Rule Name */}
                <div>
                  <h3 className="text-sm font-semibold text-white">
                    {cfg.title}
                  </h3>
                  <p className="text-[11px] text-slate-400 mt-0.5">
                    Category: {cfg.category}
                  </p>
                </div>

                {/* Description */}
                <p className="text-xs text-slate-300 leading-relaxed">
                  {rule.description}
                </p>
              </div>

              {/* Metrics & Status Toggle */}
              <div className="pt-3 border-t border-[#22304A] space-y-3">
                <div className="grid grid-cols-2 gap-2 text-xs bg-[#0D1424] p-2.5 rounded-lg border border-[#22304A]">
                  <div>
                    <span className="text-slate-400 block text-[10px] uppercase">Triggered</span>
                    <span className="font-mono font-bold text-white">{triggerCount} times</span>
                  </div>
                  <div>
                    <span className="text-slate-400 block text-[10px] uppercase">Last Triggered</span>
                    <span className="font-mono text-slate-300 text-[11px]">
                      {triggerCount > 0 ? 'Today 14:22' : 'Never'}
                    </span>
                  </div>
                </div>

                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-1.5 text-xs">
                    <span className={`w-2 h-2 rounded-full ${rule.enabled ? 'bg-[#20C997]' : 'bg-slate-500'}`} />
                    <span className="text-slate-300 font-medium">
                      Status: {rule.enabled ? 'Active' : 'Disabled'}
                    </span>
                  </div>

                  <button
                    onClick={() => toggleRule(rule.id)}
                    className={`px-3 py-1 rounded-lg text-xs font-medium border cursor-pointer transition-colors ${
                      rule.enabled
                        ? 'bg-[#FF5C6C]/10 text-[#FF5C6C] border-[#FF5C6C]/30 hover:bg-[#FF5C6C]/20'
                        : 'bg-[#20C997]/10 text-[#20C997] border-[#20C997]/30 hover:bg-[#20C997]/20'
                    }`}
                  >
                    {rule.enabled ? 'Disable' : 'Enable'}
                  </button>
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Rule Testing Sandbox */}
      <div className="soc-card p-5 space-y-4">
        <div>
          <h2 className="text-sm font-semibold text-white tracking-tight">
            Detection Sandbox & Rule Evaluator
          </h2>
          <p className="text-xs text-slate-400">
            Simulate a telemetry payload to inspect which detection rules evaluate to TRUE.
          </p>
        </div>

        <form onSubmit={handleTestSandbox} className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="text-xs text-slate-300 font-medium block mb-1.5">
                Simulated Event Type
              </label>
              <select
                value={testEventType}
                onChange={(e) => setTestEventType(e.target.value as EventType)}
                className="w-full bg-[#0D1424] border border-[#22304A] rounded-lg p-2 text-xs text-slate-200 focus:outline-none focus:border-[#5B8CFF]"
              >
                <option value="USB_TRANSFER_REQUEST">USB_TRANSFER_REQUEST</option>
                <option value="FAILED_LOGIN">FAILED_LOGIN</option>
                <option value="SENSITIVE_FILE_ACCESS">SENSITIVE_FILE_ACCESS</option>
                <option value="UNAUTHORIZED_ACCESS">UNAUTHORIZED_ACCESS</option>
                <option value="FILE_DOWNLOAD">FILE_DOWNLOAD</option>
              </select>
            </div>

            <div>
              <label className="text-xs text-slate-300 font-medium block mb-1.5">
                Payload JSON
              </label>
              <textarea
                rows={4}
                value={testPayload}
                onChange={(e) => setTestPayload(e.target.value)}
                className="w-full bg-[#080D18] border border-[#22304A] rounded-lg p-2 text-xs font-mono text-[#5B8CFF] focus:outline-none focus:border-[#5B8CFF]"
              />
            </div>
          </div>

          <div className="flex justify-end">
            <button
              type="submit"
              className="px-4 py-2 rounded-lg bg-[#5B8CFF] hover:bg-[#4a7cee] text-white text-xs font-semibold cursor-pointer"
            >
              Evaluate Against Active Rules
            </button>
          </div>
        </form>

        {sandboxResult && (
          <div className="mt-3 p-3 bg-[#0D1424] border border-[#22304A] rounded-lg text-xs space-y-2">
            <div className="font-semibold text-white">
              Evaluation Outcome: {sandboxResult.length} Rule(s) Triggered
            </div>
            {sandboxResult.map((m, idx) => (
              <div key={idx} className="p-2 bg-[#111A2C] rounded border border-[#22304A] flex justify-between">
                <div>
                  <span className="font-mono text-[#5B8CFF] font-bold">{m.ruleCode}</span>: {m.name}
                </div>
                <div className="text-[#FF5C6C] font-mono font-bold">+{m.riskWeight} Risk</div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Add Custom Rule Modal */}
      {showAddModal && (
        <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
          <div className="bg-[#111A2C] border border-[#22304A] rounded-xl max-w-md w-full p-5 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-[#22304A] pb-3">
              <h3 className="text-sm font-semibold text-white">Create Custom Detection Rule</h3>
              <button
                onClick={() => setShowAddModal(false)}
                className="text-slate-400 hover:text-white text-xs cursor-pointer"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleCreateRule} className="space-y-3 text-xs">
              <div>
                <label className="text-slate-400 block mb-1">Rule Code (e.g. RULE_008)</label>
                <input
                  type="text"
                  value={newCode}
                  onChange={(e) => setNewCode(e.target.value)}
                  className="w-full bg-[#0D1424] border border-[#22304A] rounded-lg p-2 text-slate-200"
                  required
                />
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Rule Name</label>
                <input
                  type="text"
                  value={newName}
                  onChange={(e) => setNewName(e.target.value)}
                  className="w-full bg-[#0D1424] border border-[#22304A] rounded-lg p-2 text-slate-200"
                  required
                />
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Description</label>
                <textarea
                  rows={2}
                  value={newDesc}
                  onChange={(e) => setNewDesc(e.target.value)}
                  className="w-full bg-[#0D1424] border border-[#22304A] rounded-lg p-2 text-slate-200"
                />
              </div>

              <div className="grid grid-cols-2 gap-2">
                <div>
                  <label className="text-slate-400 block mb-1">Severity</label>
                  <select
                    value={newSev}
                    onChange={(e) => setNewSev(e.target.value as Severity)}
                    className="w-full bg-[#0D1424] border border-[#22304A] rounded-lg p-2 text-slate-200"
                  >
                    <option value="CRITICAL">Critical</option>
                    <option value="HIGH">High</option>
                    <option value="MEDIUM">Medium</option>
                    <option value="LOW">Low</option>
                  </select>
                </div>
                <div>
                  <label className="text-slate-400 block mb-1">Risk Weight</label>
                  <input
                    type="number"
                    value={newWeight}
                    onChange={(e) => setNewWeight(Number(e.target.value))}
                    className="w-full bg-[#0D1424] border border-[#22304A] rounded-lg p-2 text-slate-200"
                  />
                </div>
              </div>

              <div className="flex justify-end gap-2 pt-2 border-t border-[#22304A]">
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="px-3 py-1.5 rounded-lg bg-[#0D1424] text-slate-300 hover:text-white cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-3.5 py-1.5 rounded-lg bg-[#5B8CFF] hover:bg-[#4a7cee] text-white font-semibold cursor-pointer"
                >
                  Save Rule
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
