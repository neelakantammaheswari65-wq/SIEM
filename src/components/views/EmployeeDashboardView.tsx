import React from 'react';
import { useSIEM } from '../../context/SIEMContext';
import {
  FolderLock,
  FileText,
  Download,
  Eye,
  Clock,
  ShieldCheck,
  Briefcase,
  HelpCircle,
  ArrowRight,
  CheckCircle2,
} from 'lucide-react';
import { DemoFile } from '../../types/siem';

export const EmployeeDashboardView: React.FC = () => {
  const { currentUser, files, userFileActivities, accessFile, setActiveTab } = useSIEM();

  const handleDownload = (file: DemoFile) => {
    accessFile(file.id, 'DOWNLOAD');
  };

  const handleOpen = (file: DemoFile) => {
    accessFile(file.id, 'OPEN');
  };

  const myActivities = userFileActivities.filter((a) => a.userId === currentUser.id);
  const recommendedFiles = files.slice(0, 4);

  return (
    <div className="p-6 space-y-6 max-w-[1600px] mx-auto text-slate-200">
      {/* Welcome Banner */}
      <div className="soc-card p-6 flex flex-col md:flex-row md:items-center justify-between gap-6">
        <div className="space-y-2">
          <div className="inline-flex items-center gap-2 px-2.5 py-0.5 rounded-full bg-[#0D1424] border border-[#22304A] text-[#5B8CFF] text-xs font-semibold">
            <ShieldCheck className="w-3.5 h-3.5 text-[#5B8CFF]" />
            <span>Enterprise Workspace</span>
          </div>
          <h1 className="text-xl md:text-2xl font-bold text-white tracking-tight">
            Welcome back, <span className="text-[#5B8CFF]">{currentUser.fullName}</span>
          </h1>
          <p className="text-xs text-slate-400 max-w-xl leading-relaxed">
            Access your department's shared documents, collaborate on team deliverables, and review internal compliance documentation.
          </p>
        </div>

        {/* Quick User Identity Card */}
        <div className="flex items-center gap-3.5 bg-[#0D1424] border border-[#22304A] rounded-xl p-3.5 shrink-0">
          <div className="w-11 h-11 rounded-lg bg-[#5B8CFF]/15 border border-[#5B8CFF]/30 text-[#5B8CFF] flex items-center justify-center font-bold text-base">
            {currentUser.fullName.charAt(0)}
          </div>
          <div className="space-y-0.5">
            <p className="text-xs font-bold text-white">{currentUser.fullName}</p>
            <p className="text-[11px] text-slate-400 flex items-center gap-1">
              <Briefcase className="w-3 h-3 text-slate-500" /> {currentUser.department}
            </p>
            <p className="text-[10px] font-mono text-[#5B8CFF]">
              Workstation: {currentUser.ipAddress || '10.14.88.102'}
            </p>
          </div>
        </div>
      </div>

      {/* 3 Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Card 1 */}
        <div className="soc-card p-5 flex flex-col justify-between space-y-4">
          <div className="space-y-2">
            <div className="w-9 h-9 rounded-lg bg-[#5B8CFF]/15 border border-[#5B8CFF]/30 text-[#5B8CFF] flex items-center justify-center">
              <FolderLock className="w-4 h-4" />
            </div>
            <h3 className="font-semibold text-white text-sm">Corporate File Repository</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Browse {files.length} managed resources across Engineering, Finance, Operations, and HR.
            </p>
          </div>
          <button
            id="btn-goto-files"
            onClick={() => setActiveTab('files')}
            className="w-full py-2 px-3 rounded-lg bg-[#5B8CFF] hover:bg-[#4a7cee] text-white font-semibold text-xs flex items-center justify-center gap-2 transition-colors cursor-pointer"
          >
            <span>Browse All Files</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>

        {/* Card 2 */}
        <div className="soc-card p-5 flex flex-col justify-between space-y-4">
          <div className="space-y-2">
            <div className="w-9 h-9 rounded-lg bg-[#20C997]/15 border border-[#20C997]/30 text-[#20C997] flex items-center justify-center">
              <ShieldCheck className="w-4 h-4" />
            </div>
            <h3 className="font-semibold text-white text-sm">Enterprise DLP & Safety</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              All employee access to confidential documents is logged for enterprise compliance & security verification.
            </p>
          </div>
          <div className="flex items-center gap-2 text-[11px] text-[#20C997] font-semibold bg-[#20C997]/10 border border-[#20C997]/30 p-2.5 rounded-lg">
            <CheckCircle2 className="w-4 h-4 shrink-0" />
            <span>Endpoint Protection Active & Verified</span>
          </div>
        </div>

        {/* Card 3 */}
        <div className="soc-card p-5 flex flex-col justify-between space-y-4">
          <div className="space-y-2">
            <div className="w-9 h-9 rounded-lg bg-[#8B7CFF]/15 border border-[#8B7CFF]/30 text-[#8B7CFF] flex items-center justify-center">
              <HelpCircle className="w-4 h-4" />
            </div>
            <h3 className="font-semibold text-white text-sm">IT Service Desk</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Need access clearance to restricted archives or encrypted datasets? Submit a ticket to IT Operations.
            </p>
          </div>
          <div className="text-[11px] text-slate-400 font-mono bg-[#0D1424] p-2.5 rounded-lg border border-[#22304A] text-center">
            Helpdesk Ext: <span className="text-white font-bold">#4040</span> (24/7 Support)
          </div>
        </div>
      </div>

      {/* Two Columns: Recommended Documents & My Recent Activity */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recommended Files */}
        <div className="soc-card p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-[#22304A] pb-3">
            <div>
              <h3 className="font-semibold text-white text-sm">Recommended Documents</h3>
              <p className="text-xs text-slate-400">Frequently accessed departmental files</p>
            </div>
            <button
              onClick={() => setActiveTab('files')}
              className="text-xs text-[#5B8CFF] hover:underline font-semibold flex items-center gap-1 cursor-pointer"
            >
              View All →
            </button>
          </div>

          <div className="space-y-2.5">
            {recommendedFiles.map((file) => (
              <div
                key={file.id}
                className="flex items-center justify-between p-3 rounded-lg bg-[#0D1424] border border-[#22304A] hover:border-[#314366] transition-colors"
              >
                <div className="flex items-center gap-2.5 min-w-0">
                  <div className="p-1.5 rounded-md bg-[#111A2C] border border-[#22304A] text-[#5B8CFF] shrink-0">
                    <FileText className="w-4 h-4" />
                  </div>
                  <div className="min-w-0">
                    <p className="text-xs font-semibold text-white truncate">
                      {file.name}
                    </p>
                    <p className="text-[10px] text-slate-400 flex items-center gap-1 mt-0.5">
                      <span>{file.department}</span>
                      <span>•</span>
                      <span>{file.sizeMb} MB</span>
                      <span>•</span>
                      <span className="font-mono text-[#5B8CFF]">{file.classification}</span>
                    </p>
                  </div>
                </div>

                <div className="flex items-center gap-1 shrink-0 ml-3">
                  <button
                    onClick={() => handleOpen(file)}
                    className="p-1.5 text-slate-400 hover:text-white rounded-md hover:bg-[#22304A] transition-colors cursor-pointer"
                    title="Preview Document"
                  >
                    <Eye className="w-3.5 h-3.5" />
                  </button>
                  <button
                    onClick={() => handleDownload(file)}
                    className="p-1.5 text-[#5B8CFF] hover:text-white rounded-md hover:bg-[#5B8CFF]/20 transition-colors cursor-pointer"
                    title="Download File"
                  >
                    <Download className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* My Activity History */}
        <div className="soc-card p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-[#22304A] pb-3">
            <div>
              <h3 className="font-semibold text-white text-sm">My File Activity Log</h3>
              <p className="text-xs text-slate-400">Your recent actions and document views</p>
            </div>
            <button
              onClick={() => setActiveTab('my_activity')}
              className="text-xs text-[#5B8CFF] hover:underline font-semibold flex items-center gap-1 cursor-pointer"
            >
              Full Log →
            </button>
          </div>

          <div className="space-y-2.5">
            {myActivities.length === 0 ? (
              <div className="py-10 text-center text-slate-500 text-xs">
                <Clock className="w-7 h-7 text-slate-600 mx-auto mb-2 opacity-50" />
                <p>No recent activity recorded yet today.</p>
                <p className="text-[11px] text-slate-600 mt-1">
                  Open or download files in the repository to view history.
                </p>
              </div>
            ) : (
              myActivities.slice(0, 5).map((act) => (
                <div
                  key={act.id}
                  className="flex items-center justify-between p-2.5 rounded-lg bg-[#0D1424] border border-[#22304A] text-xs"
                >
                  <div className="flex items-center gap-2.5 min-w-0">
                    <div
                      className={`p-1.5 rounded-md shrink-0 ${
                        act.action === 'DOWNLOAD'
                          ? 'bg-[#5B8CFF]/15 text-[#5B8CFF] border border-[#5B8CFF]/30'
                          : 'bg-[#111A2C] text-slate-400 border border-[#22304A]'
                      }`}
                    >
                      {act.action === 'DOWNLOAD' ? (
                        <Download className="w-3.5 h-3.5" />
                      ) : (
                        <Eye className="w-3.5 h-3.5" />
                      )}
                    </div>
                    <div className="min-w-0">
                      <p className="font-semibold text-white truncate">{act.fileName}</p>
                      <p className="text-[10px] text-slate-400 font-mono mt-0.5">
                        {act.action} • {act.sizeMb} MB • {new Date(act.timestamp).toLocaleTimeString()}
                      </p>
                    </div>
                  </div>

                  <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-[#20C997]/15 text-[#20C997] border border-[#20C997]/30 shrink-0 ml-2">
                    {act.status}
                  </span>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
