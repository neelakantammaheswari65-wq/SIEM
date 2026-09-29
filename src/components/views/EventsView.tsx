import React, { useState } from 'react';
import { useSIEM } from '../../context/SIEMContext';
import { EventType, Severity } from '../../types/siem';
import { siemEngine } from '../../services/siemEngine';
import {
  Terminal,
  Search,
  Filter,
  X,
  Copy,
  Check,
  Calendar,
  Shield,
  Activity,
  Layers,
  ChevronRight,
  PlusCircle,
  Clock,
  ExternalLink,
} from 'lucide-react';

export const EventsView: React.FC = () => {
  const { events, users, riskScores, currentUser } = useSIEM();

  // Filters
  const [search, setSearch] = useState('');
  const [dateFilter, setDateFilter] = useState<'1h' | '24h' | '7d' | 'ALL'>('24h');
  const [employeeFilter, setEmployeeFilter] = useState<string>('ALL');
  const [ruleFilter, setRuleFilter] = useState<string>('ALL');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');

  // Selected event for right-side detail drawer
  const [selectedEvent, setSelectedEvent] = useState<any | null>(null);
  const [copied, setCopied] = useState(false);
  const [showInjectModal, setShowInjectModal] = useState(false);

  // Pagination
  const [currentPage, setCurrentPage] = useState(1);
  const pageSize = 40;

  // Ingestion Modal State
  const [newEventUser, setNewEventUser] = useState<number>(101);
  const [newEventType, setNewEventType] = useState<EventType>('SENSITIVE_FILE_ACCESS');
  const [newEventAction, setNewEventAction] = useState('READ_CONFIDENTIAL');
  const [newEventResource, setNewEventResource] = useState('/vault/finance/M&A_Strategy.pdf');
  const [newEventSeverity, setNewEventSeverity] = useState<Severity>('HIGH');
  const [newEventDetails, setNewEventDetails] = useState('{\n  "classification": "TOP_SECRET",\n  "file_size_mb": 42.0\n}');

  const handleManualIngest = (e: React.FormEvent) => {
    e.preventDefault();
    try {
      let parsedDetails = {};
      try {
        parsedDetails = JSON.parse(newEventDetails);
      } catch {
        parsedDetails = { raw_input: newEventDetails };
      }

      const u = users.find((usr) => usr.id === Number(newEventUser)) || users[0];
      siemEngine.ingestLog({
        timestamp: new Date().toISOString(),
        userId: u.id,
        username: u.username,
        source: 'manual-ingest-console',
        eventType: newEventType,
        action: newEventAction,
        resource: newEventResource,
        ipAddress: u.ipAddress || '10.14.88.100',
        severity: newEventSeverity,
        details: parsedDetails,
      });

      setShowInjectModal(false);
    } catch (err) {
      console.warn('Manual log ingest failed:', err);
    }
  };

  const handleCopyJson = (obj: any) => {
    try {
      if (typeof navigator !== 'undefined' && navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(JSON.stringify(obj, null, 2)).catch(() => {});
      }
    } catch {}
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // Filter evaluation
  const filteredEvents = events.filter((ev) => {
    if (!ev) return false;

    // Search filter
    const searchLower = search.toLowerCase();
    const matchesSearch =
      !search.trim() ||
      (ev.eventType || '').toLowerCase().includes(searchLower) ||
      (ev.username && ev.username.toLowerCase().includes(searchLower)) ||
      (ev.normalizedData?.resource && ev.normalizedData.resource.toLowerCase().includes(searchLower)) ||
      (ev.normalizedData?.action && ev.normalizedData.action.toLowerCase().includes(searchLower)) ||
      (ev.normalizedData?.ipAddress && ev.normalizedData.ipAddress.toLowerCase().includes(searchLower));

    // Employee filter
    const matchesEmployee = employeeFilter === 'ALL' || String(ev.userId) === employeeFilter;

    // Severity filter
    const matchesSeverity = severityFilter === 'ALL' || ev.normalizedData?.severity === severityFilter;

    // Rule filter
    const evRule = ev.normalizedData?.ruleId || (ev.eventType === 'FAILED_LOGIN' ? 'RULE-001' : ev.eventType === 'UNAUTHORIZED_ACCESS' ? 'RULE-002' : ev.eventType === 'SENSITIVE_FILE_ACCESS' ? 'RULE-005' : 'NORMAL');
    const matchesRule = ruleFilter === 'ALL' || evRule === ruleFilter;

    // Status filter
    const evStatus = ev.processed ? 'PROCESSED' : 'PENDING';
    const matchesStatus = statusFilter === 'ALL' || evStatus === statusFilter;

    return matchesSearch && matchesEmployee && matchesSeverity && matchesRule && matchesStatus;
  });

  const totalPages = Math.max(1, Math.ceil(filteredEvents.length / pageSize));
  const pagedEvents = filteredEvents.slice((currentPage - 1) * pageSize, currentPage * pageSize);

  return (
    <div className="p-6 space-y-6 max-w-[1600px] mx-auto text-slate-200">
      {/* Top Header: Security Events */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-white tracking-tight">
            Security Events
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Monitor and investigate activity across the organization.
          </p>
        </div>

        <div className="flex items-center gap-3">
          {currentUser.role === 'ADMIN' && (
            <button
              onClick={() => setShowInjectModal(true)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#5B8CFF] hover:bg-[#4a7cee] text-white text-xs font-semibold transition-colors cursor-pointer"
            >
              <PlusCircle className="w-3.5 h-3.5" />
              <span>Inject Event</span>
            </button>
          )}

          <div className="text-xs font-mono text-slate-400 bg-[#111A2C] px-3 py-1.5 rounded-lg border border-[#22304A]">
            Total Ingested: <strong className="text-white">{events.length.toLocaleString()}</strong>
          </div>
        </div>
      </div>

      {/* Filter Bar: Search, Date filter, Employee filter, Rule filter, Severity filter, Status filter */}
      <div className="soc-card p-4 space-y-3">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {/* Search */}
          <div className="relative">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search event, IP, user, resource..."
              value={search}
              onChange={(e) => {
                setSearch(e.target.value);
                setCurrentPage(1);
              }}
              className="w-full bg-[#0D1424] border border-[#22304A] rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-400 focus:outline-none focus:border-[#5B8CFF]"
            />
          </div>

          {/* Date Filter */}
          <div>
            <select
              value={dateFilter}
              onChange={(e) => setDateFilter(e.target.value as any)}
              className="w-full bg-[#0D1424] border border-[#22304A] rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-[#5B8CFF]"
            >
              <option value="1h">Date Range: Past 1 Hour</option>
              <option value="24h">Date Range: Past 24 Hours</option>
              <option value="7d">Date Range: Past 7 Days</option>
              <option value="ALL">Date Range: All Records</option>
            </select>
          </div>

          {/* Employee Filter */}
          <div>
            <select
              value={employeeFilter}
              onChange={(e) => {
                setEmployeeFilter(e.target.value);
                setCurrentPage(1);
              }}
              className="w-full bg-[#0D1424] border border-[#22304A] rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-[#5B8CFF]"
            >
              <option value="ALL">All Employees</option>
              {users.slice(0, 30).map((u) => (
                <option key={u.id} value={String(u.id)}>
                  {u.fullName} (@{u.username})
                </option>
              ))}
            </select>
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-2 border-t border-[#1E2B42]">
          {/* Rule Filter */}
          <div>
            <select
              value={ruleFilter}
              onChange={(e) => {
                setRuleFilter(e.target.value);
                setCurrentPage(1);
              }}
              className="w-full bg-[#0D1424] border border-[#22304A] rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-[#5B8CFF]"
            >
              <option value="ALL">All Rules</option>
              <option value="RULE-001">RULE-001: Multiple Failed Logins</option>
              <option value="RULE-002">RULE-002: Unauthorized Access</option>
              <option value="RULE-003">RULE-003: Unusual Login Time</option>
              <option value="RULE-004">RULE-004: Unusual Location / IP</option>
              <option value="RULE-005">RULE-005: Sensitive File Access</option>
              <option value="RULE-006">RULE-006: Abnormal Data Transfer</option>
              <option value="RULE-007">RULE-007: Device Activity</option>
              <option value="NORMAL">NORMAL: Standard Event</option>
            </select>
          </div>

          {/* Severity Filter */}
          <div>
            <select
              value={severityFilter}
              onChange={(e) => {
                setSeverityFilter(e.target.value);
                setCurrentPage(1);
              }}
              className="w-full bg-[#0D1424] border border-[#22304A] rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-[#5B8CFF]"
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>
          </div>

          {/* Status Filter */}
          <div>
            <select
              value={statusFilter}
              onChange={(e) => {
                setStatusFilter(e.target.value);
                setCurrentPage(1);
              }}
              className="w-full bg-[#0D1424] border border-[#22304A] rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-[#5B8CFF]"
            >
              <option value="ALL">All Statuses</option>
              <option value="PROCESSED">Processed</option>
              <option value="PENDING">Pending</option>
            </select>
          </div>
        </div>
      </div>

      {/* Modern Event Table */}
      <div className="soc-card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-[#22304A] bg-[#0D1424] text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                <th className="py-3 px-4">Time</th>
                <th className="py-3 px-4">Employee</th>
                <th className="py-3 px-4">Event</th>
                <th className="py-3 px-4">Rule</th>
                <th className="py-3 px-4">Source</th>
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">Risk</th>
                <th className="py-3 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#22304A]">
              {pagedEvents.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-slate-400">
                    No security events matched the selected filters.
                  </td>
                </tr>
              ) : (
                pagedEvents.map((ev) => {
                  const userObj = users.find((u) => u.id === ev.userId);
                  const empName = userObj ? userObj.fullName : `@${ev.username || 'unknown'}`;
                  const empId = userObj?.employeeId || `EMP-${ev.userId || '0042'}`;
                  const sev = ev.normalizedData?.severity || 'LOW';
                  const ruleCode = ev.normalizedData?.ruleId || (ev.eventType === 'FAILED_LOGIN' ? 'RULE-001' : ev.eventType === 'UNAUTHORIZED_ACCESS' ? 'RULE-002' : ev.eventType === 'SENSITIVE_FILE_ACCESS' ? 'RULE-005' : 'NORMAL');
                  const userRisk = riskScores.find((r) => r.userId === ev.userId)?.finalScore || (sev === 'CRITICAL' ? 85 : sev === 'HIGH' ? 62 : 12);

                  const sevBadge =
                    sev === 'CRITICAL'
                      ? 'bg-[#FF5C6C]/10 text-[#FF5C6C] border-[#FF5C6C]/30'
                      : sev === 'HIGH'
                      ? 'bg-[#FFB020]/10 text-[#FFB020] border-[#FFB020]/30'
                      : sev === 'MEDIUM'
                      ? 'bg-[#5B8CFF]/10 text-[#5B8CFF] border-[#5B8CFF]/30'
                      : 'bg-[#20C997]/10 text-[#20C997] border-[#20C997]/30';

                  return (
                    <tr
                      key={ev.id}
                      onClick={() => setSelectedEvent(ev)}
                      className="hover:bg-[#0D1424] transition-colors cursor-pointer"
                    >
                      <td className="py-3 px-4 font-mono text-slate-400 text-[11px] whitespace-nowrap">
                        {new Date(ev.timestamp).toLocaleTimeString()}
                      </td>

                      <td className="py-3 px-4">
                        <div className="font-medium text-white">{empName}</div>
                        <div className="text-[10px] text-slate-400 font-mono">{empId}</div>
                      </td>

                      <td className="py-3 px-4 max-w-xs truncate">
                        <div className="text-slate-200 font-medium truncate">
                          {ev.normalizedData?.action || ev.eventType}
                        </div>
                        <div className="text-[10px] text-slate-400 truncate font-mono">
                          {ev.normalizedData?.resource || 'system'}
                        </div>
                      </td>

                      <td className="py-3 px-4 font-mono text-[11px] text-slate-300">
                        {ruleCode}
                      </td>

                      <td className="py-3 px-4 text-slate-400 text-[11px] truncate max-w-[120px]">
                        {ev.normalizedData?.source || 'endpoint-agent'}
                      </td>

                      <td className="py-3 px-4">
                        <span className={`text-[10px] px-2 py-0.5 rounded-full border font-medium ${sevBadge}`}>
                          {sev}
                        </span>
                      </td>

                      <td className="py-3 px-4 font-mono font-semibold text-white">
                        {userRisk}
                      </td>

                      <td className="py-3 px-4 text-right">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelectedEvent(ev);
                          }}
                          className="px-2.5 py-1 rounded bg-[#0D1424] hover:bg-[#1E2B42] text-[11px] text-[#5B8CFF] border border-[#22304A] cursor-pointer"
                        >
                          Details
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Bar */}
        <div className="p-3.5 bg-[#0D1424] border-t border-[#22304A] flex flex-col sm:flex-row items-center justify-between gap-3 text-xs text-slate-400">
          <span>
            Showing {Math.min(filteredEvents.length, (currentPage - 1) * pageSize + 1)}-{Math.min(filteredEvents.length, currentPage * pageSize)} of {filteredEvents.length} events
          </span>

          <div className="flex items-center gap-2">
            <span>Page {currentPage} of {totalPages}</span>
            <button
              onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
              disabled={currentPage <= 1}
              className="px-2.5 py-1 rounded bg-[#111A2C] hover:bg-[#1E2B42] disabled:opacity-40 text-slate-200 border border-[#22304A] cursor-pointer"
            >
              Prev
            </button>
            <button
              onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
              disabled={currentPage >= totalPages}
              className="px-2.5 py-1 rounded bg-[#111A2C] hover:bg-[#1E2B42] disabled:opacity-40 text-slate-200 border border-[#22304A] cursor-pointer"
            >
              Next
            </button>
          </div>
        </div>
      </div>

      {/* Right-Side Detail Drawer (Slide-in from right when an event is selected) */}
      {selectedEvent && (
        <div className="fixed inset-0 z-50 bg-black/60 flex items-center justify-end">
          <div className="bg-[#111A2C] border-l border-[#22304A] w-full max-w-lg h-full p-6 space-y-5 overflow-y-auto animate-in slide-in-from-right duration-200 shadow-2xl">
            <div className="flex items-center justify-between border-b border-[#22304A] pb-4">
              <div>
                <span className="text-[11px] font-mono text-[#5B8CFF] uppercase">
                  Event Telemetry Inspector
                </span>
                <h2 className="text-base font-bold text-white mt-0.5">
                  Event #{selectedEvent.id}
                </h2>
              </div>
              <button
                onClick={() => setSelectedEvent(null)}
                className="text-slate-400 hover:text-white text-xs cursor-pointer p-1"
              >
                ✕ Close
              </button>
            </div>

            <div className="space-y-3">
              <div className="bg-[#0D1424] border border-[#22304A] rounded-lg p-3 text-xs space-y-2">
                <div className="flex justify-between">
                  <span className="text-slate-400">Event Type:</span>
                  <span className="font-semibold text-white">{selectedEvent.eventType}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Actor:</span>
                  <span className="text-[#5B8CFF] font-medium">@{selectedEvent.username} (ID: {selectedEvent.userId})</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Action:</span>
                  <span className="text-slate-200">{selectedEvent.normalizedData?.action || selectedEvent.action}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Target Resource:</span>
                  <span className="text-slate-200 truncate max-w-[200px]">{selectedEvent.normalizedData?.resource || 'N/A'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">IP Origin:</span>
                  <span className="font-mono text-slate-300">{selectedEvent.normalizedData?.ipAddress || selectedEvent.ipAddress || '10.14.88.102'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Timestamp:</span>
                  <span className="text-slate-300">{selectedEvent.timestamp}</span>
                </div>
              </div>

              <div>
                <div className="flex items-center justify-between text-xs text-slate-400 uppercase tracking-wider mb-2">
                  <span>Raw Telemetry JSON</span>
                  <button
                    onClick={() => handleCopyJson(selectedEvent)}
                    className="flex items-center gap-1 text-[#5B8CFF] hover:underline cursor-pointer"
                  >
                    {copied ? <Check className="w-3.5 h-3.5 text-[#20C997]" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copied ? 'Copied' : 'Copy JSON'}</span>
                  </button>
                </div>
                <pre className="text-xs bg-[#080D18] p-3 rounded-lg border border-[#22304A] overflow-x-auto text-[#5B8CFF] max-h-64 font-mono">
                  {JSON.stringify(selectedEvent, null, 2)}
                </pre>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Manual Inject Modal */}
      {showInjectModal && (
        <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
          <div className="bg-[#111A2C] border border-[#22304A] rounded-xl max-w-md w-full p-5 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-[#22304A] pb-3">
              <h3 className="text-sm font-semibold text-white">Manual Telemetry Ingest</h3>
              <button
                onClick={() => setShowInjectModal(false)}
                className="text-slate-400 hover:text-white text-xs cursor-pointer"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleManualIngest} className="space-y-3 text-xs">
              <div>
                <label className="text-slate-400 block mb-1">Target Employee</label>
                <select
                  value={newEventUser}
                  onChange={(e) => setNewEventUser(Number(e.target.value))}
                  className="w-full bg-[#0D1424] border border-[#22304A] rounded-lg p-2 text-slate-200"
                >
                  {users.slice(0, 15).map((u) => (
                    <option key={u.id} value={u.id}>
                      {u.fullName} (@{u.username})
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Event Type</label>
                <select
                  value={newEventType}
                  onChange={(e) => setNewEventType(e.target.value as EventType)}
                  className="w-full bg-[#0D1424] border border-[#22304A] rounded-lg p-2 text-slate-200"
                >
                  <option value="SENSITIVE_FILE_ACCESS">SENSITIVE_FILE_ACCESS</option>
                  <option value="FAILED_LOGIN">FAILED_LOGIN</option>
                  <option value="UNAUTHORIZED_ACCESS">UNAUTHORIZED_ACCESS</option>
                  <option value="FILE_DOWNLOAD">FILE_DOWNLOAD</option>
                </select>
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Action</label>
                <input
                  type="text"
                  value={newEventAction}
                  onChange={(e) => setNewEventAction(e.target.value)}
                  className="w-full bg-[#0D1424] border border-[#22304A] rounded-lg p-2 text-slate-200"
                />
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Severity</label>
                <select
                  value={newEventSeverity}
                  onChange={(e) => setNewEventSeverity(e.target.value as Severity)}
                  className="w-full bg-[#0D1424] border border-[#22304A] rounded-lg p-2 text-slate-200"
                >
                  <option value="CRITICAL">Critical</option>
                  <option value="HIGH">High</option>
                  <option value="MEDIUM">Medium</option>
                  <option value="LOW">Low</option>
                </select>
              </div>

              <div className="flex justify-end gap-2 pt-2 border-t border-[#22304A]">
                <button
                  type="button"
                  onClick={() => setShowInjectModal(false)}
                  className="px-3 py-1.5 rounded-lg bg-[#0D1424] text-slate-300 hover:text-white cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-3 py-1.5 rounded-lg bg-[#5B8CFF] hover:bg-[#4a7cee] text-white font-semibold cursor-pointer"
                >
                  Ingest Event
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
