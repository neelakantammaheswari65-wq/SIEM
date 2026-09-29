import React, { useState } from 'react';
import { useSIEM } from '../../context/SIEMContext';
import {
  FileCheck2,
  Search,
  Download,
  ShieldCheck,
  CheckCircle2,
  Filter,
} from 'lucide-react';

export const AuditLogsView: React.FC = () => {
  const { auditLogs } = useSIEM();
  const [search, setSearch] = useState('');
  const [actionFilter, setActionFilter] = useState('ALL');
  const [resultFilter, setResultFilter] = useState('ALL');

  // Filter logs
  const filteredLogs = auditLogs.filter((log) => {
    if (!log) return false;
    const matchesSearch =
      (log.actor || '').toLowerCase().includes(search.toLowerCase()) ||
      (log.action || '').toLowerCase().includes(search.toLowerCase()) ||
      (log.resource || '').toLowerCase().includes(search.toLowerCase()) ||
      (log.details || '').toLowerCase().includes(search.toLowerCase());

    const isBlocked =
      log.action.includes('FAIL') ||
      log.action.includes('DENIED') ||
      log.action.includes('BLOCK');
    const resultText = log.status || (isBlocked ? 'BLOCKED' : 'SUCCESS');

    const matchesResult = resultFilter === 'ALL' || resultText === resultFilter;
    const matchesAction = actionFilter === 'ALL' || log.action.includes(actionFilter);

    return matchesSearch && matchesResult && matchesAction;
  });

  const handleExportCSV = () => {
    const headers = ['Timestamp', 'Actor', 'Action', 'Resource', 'Result', 'IP Address', 'Severity'];
    const rows = filteredLogs.map((log) => {
      const isBlocked = log.action.includes('FAIL') || log.action.includes('DENIED') || log.action.includes('BLOCK');
      const resultText = log.status || (isBlocked ? 'BLOCKED' : 'SUCCESS');
      const sev = isBlocked ? 'HIGH' : 'LOW';

      return [
        log.timestamp,
        log.actor,
        log.action,
        log.resource || 'SYSTEM',
        resultText,
        log.ipAddress || '10.14.88.102',
        sev,
      ];
    });

    const csvContent =
      'data:text/csv;charset=utf-8,' +
      [headers.join(','), ...rows.map((e) => e.map((val) => `"${val}"`).join(','))].join('\n');

    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', `soc_audit_log_${new Date().toISOString().split('T')[0]}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const handleExportJSON = () => {
    const dataStr =
      'data:text/json;charset=utf-8,' +
      encodeURIComponent(JSON.stringify(filteredLogs, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `soc_audit_log_${new Date().toISOString().split('T')[0]}.json`);
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
            Security Audit Trail
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Immutable log recording administrative access, authentication attempts, and DLP decisions.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleExportCSV}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#111A2C] hover:bg-[#1E2B42] text-xs text-slate-200 border border-[#22304A] cursor-pointer"
          >
            <Download className="w-3.5 h-3.5 text-[#5B8CFF]" />
            <span>Export CSV</span>
          </button>
          <button
            onClick={handleExportJSON}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#111A2C] hover:bg-[#1E2B42] text-xs text-slate-200 border border-[#22304A] cursor-pointer"
          >
            <Download className="w-3.5 h-3.5 text-[#5B8CFF]" />
            <span>Export JSON</span>
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="soc-card p-4 grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
        <div className="relative">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search actor, action, resource, details..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full bg-[#0D1424] border border-[#22304A] rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-400 focus:outline-none focus:border-[#5B8CFF]"
          />
        </div>

        <div>
          <select
            value={actionFilter}
            onChange={(e) => setActionFilter(e.target.value)}
            className="w-full bg-[#0D1424] border border-[#22304A] rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-[#5B8CFF]"
          >
            <option value="ALL">All Actions</option>
            <option value="AUTH">Authentication / Logins</option>
            <option value="ACCESS">Resource Access</option>
            <option value="ALERT">Alert Management</option>
            <option value="USER">User / Employee</option>
          </select>
        </div>

        <div>
          <select
            value={resultFilter}
            onChange={(e) => setResultFilter(e.target.value)}
            className="w-full bg-[#0D1424] border border-[#22304A] rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-[#5B8CFF]"
          >
            <option value="ALL">All Results</option>
            <option value="SUCCESS">SUCCESS</option>
            <option value="BLOCKED">BLOCKED</option>
          </select>
        </div>
      </div>

      {/* Professional Audit Table
          Columns: Timestamp, Actor, Action, Resource, Result, IP Address, Severity */}
      <div className="soc-card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-[#22304A] bg-[#0D1424] text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                <th className="py-3 px-4">Timestamp</th>
                <th className="py-3 px-4">Actor</th>
                <th className="py-3 px-4">Action</th>
                <th className="py-3 px-4">Resource</th>
                <th className="py-3 px-4">Result</th>
                <th className="py-3 px-4">IP Address</th>
                <th className="py-3 px-4 text-right">Severity</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#22304A]">
              {filteredLogs.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-slate-400">
                    No audit records match the filter criteria.
                  </td>
                </tr>
              ) : (
                filteredLogs.map((log) => {
                  const isBlocked =
                    log.action.includes('FAIL') ||
                    log.action.includes('DENIED') ||
                    log.action.includes('BLOCK');
                  const resultText = log.status || (isBlocked ? 'BLOCKED' : 'SUCCESS');
                  const sev = isBlocked ? 'HIGH' : 'LOW';

                  return (
                    <tr key={log.id} className="hover:bg-[#0D1424] transition-colors">
                      {/* Timestamp */}
                      <td className="py-3 px-4 font-mono text-[11px] text-slate-400 whitespace-nowrap">
                        {new Date(log.timestamp).toLocaleString()}
                      </td>

                      {/* Actor */}
                      <td className="py-3 px-4 font-semibold text-white">
                        @{log.actor}
                      </td>

                      {/* Action */}
                      <td className="py-3 px-4">
                        <div className="font-medium text-slate-200">{log.action}</div>
                        {log.details && (
                          <div className="text-[11px] text-slate-400 truncate max-w-xs mt-0.5">
                            {log.details}
                          </div>
                        )}
                      </td>

                      {/* Resource */}
                      <td className="py-3 px-4 text-slate-300 font-mono text-[11px] truncate max-w-[180px]">
                        {log.resource || 'SYSTEM'}
                      </td>

                      {/* Result */}
                      <td className="py-3 px-4">
                        <span
                          className={`text-[10px] px-2 py-0.5 rounded-full border font-medium ${
                            resultText === 'SUCCESS'
                              ? 'bg-[#20C997]/10 text-[#20C997] border-[#20C997]/30'
                              : 'bg-[#FF5C6C]/10 text-[#FF5C6C] border-[#FF5C6C]/30'
                          }`}
                        >
                          {resultText}
                        </span>
                      </td>

                      {/* IP Address */}
                      <td className="py-3 px-4 font-mono text-[11px] text-slate-400">
                        {log.ipAddress || '10.14.88.102'}
                      </td>

                      {/* Severity */}
                      <td className="py-3 px-4 text-right">
                        <span
                          className={`text-[10px] font-mono font-bold ${
                            sev === 'HIGH' ? 'text-[#FFB020]' : 'text-slate-400'
                          }`}
                        >
                          {sev}
                        </span>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
