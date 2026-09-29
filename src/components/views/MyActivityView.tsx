import React from 'react';
import { useSIEM } from '../../context/SIEMContext';
import {
  Clock,
  CheckCircle2,
} from 'lucide-react';

export const MyActivityView: React.FC = () => {
  const { currentUser, userFileActivities } = useSIEM();

  const myActivities = userFileActivities.filter((a) => a.userId === currentUser.id);

  return (
    <div className="p-6 space-y-6 max-w-[1600px] mx-auto text-slate-200">
      {/* Header */}
      <div className="soc-card p-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-[#5B8CFF]/15 border border-[#5B8CFF]/30 flex items-center justify-center text-[#5B8CFF]">
            <Clock className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white tracking-tight">My Activity History</h1>
            <p className="text-xs text-slate-400 mt-0.5">
              Personal timestamped log of your workspace sessions, document views, and file downloads.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <div className="text-xs bg-[#0D1424] px-3 py-1.5 rounded-lg border border-[#22304A] text-slate-300 font-mono">
            User: <span className="text-white font-bold">{currentUser.username}</span> ({currentUser.department})
          </div>
        </div>
      </div>

      {/* Activity Table */}
      <div className="soc-card overflow-hidden">
        <div className="p-4 border-b border-[#22304A] flex items-center justify-between bg-[#0D1424]">
          <h3 className="font-semibold text-xs text-white">Activity Log ({myActivities.length} Records)</h3>
          <span className="text-[11px] text-slate-400 font-mono">Retention: 90 Days Enterprise Audit</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="bg-[#0D1424] border-b border-[#22304A] text-slate-400 uppercase tracking-wider text-[10px] font-semibold font-mono">
                <th className="py-3 px-4">Timestamp</th>
                <th className="py-3 px-4">Action</th>
                <th className="py-3 px-4">Document Name</th>
                <th className="py-3 px-4">Classification</th>
                <th className="py-3 px-4">Size</th>
                <th className="py-3 px-4 text-right">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#22304A] font-mono">
              {myActivities.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-slate-500 font-sans text-xs">
                    <Clock className="w-7 h-7 text-slate-600 mx-auto mb-2 opacity-50" />
                    No recent activity recorded yet.
                  </td>
                </tr>
              ) : (
                myActivities.map((act) => (
                  <tr key={act.id} className="hover:bg-[#0D1424]/60 transition-colors">
                    <td className="py-3 px-4 text-slate-400 text-xs">
                      {new Date(act.timestamp).toLocaleString()}
                    </td>
                    <td className="py-3 px-4">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          act.action === 'DOWNLOAD'
                            ? 'bg-[#5B8CFF]/15 text-[#5B8CFF] border border-[#5B8CFF]/30'
                            : 'bg-[#0D1424] text-slate-300 border border-[#22304A]'
                        }`}
                      >
                        {act.action}
                      </span>
                    </td>
                    <td className="py-3 px-4 font-sans font-semibold text-white">
                      {act.fileName}
                    </td>
                    <td className="py-3 px-4 text-xs text-slate-400 font-sans">
                      {act.classification}
                    </td>
                    <td className="py-3 px-4 text-slate-300">{act.sizeMb} MB</td>
                    <td className="py-3 px-4 text-right">
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold bg-[#20C997]/15 text-[#20C997] border border-[#20C997]/30 font-sans">
                        <CheckCircle2 className="w-3 h-3" />
                        {act.status}
                      </span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
