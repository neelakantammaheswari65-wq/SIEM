import React, { useState, useMemo } from 'react';
import { useSIEM } from '../../context/SIEMContext';
import { DemoFile, FileClassification } from '../../types/siem';
import {
  FolderLock,
  FileText,
  Download,
  Eye,
  Search,
  Filter,
  Building,
  KeyRound,
  FileSpreadsheet,
  FileArchive,
  FileCode,
  CheckCircle2,
  X,
  Radio,
} from 'lucide-react';

export const FileRepositoryView: React.FC = () => {
  const { files, accessFile, currentUser } = useSIEM();
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedDept, setSelectedDept] = useState('ALL');
  const [selectedClassification, setSelectedClassification] = useState('ALL');
  const [previewFile, setPreviewFile] = useState<DemoFile | null>(null);
  const [activeDownloadingId, setActiveDownloadingId] = useState<string | null>(null);
  const [downloadProgress, setDownloadProgress] = useState(0);

  const isSOCRole = currentUser.role === 'ADMIN' || currentUser.role === 'SECURITY_ANALYST';

  const departments = useMemo(() => {
    const depts = new Set(files.map((f) => f.department));
    return ['ALL', ...Array.from(depts)];
  }, [files]);

  const classifications = useMemo(() => {
    return ['ALL', 'PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'RESTRICTED', 'SENSITIVE', 'HIGHLY_CONFIDENTIAL'];
  }, []);

  const filteredFiles = useMemo(() => {
    return files.filter((file) => {
      const matchesSearch =
        file.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
        file.department.toLowerCase().includes(searchQuery.toLowerCase()) ||
        file.description.toLowerCase().includes(searchQuery.toLowerCase());
      const matchesDept = selectedDept === 'ALL' || file.department === selectedDept;
      const matchesClass =
        selectedClassification === 'ALL' || file.classification === selectedClassification;
      return matchesSearch && matchesDept && matchesClass;
    });
  }, [files, searchQuery, selectedDept, selectedClassification]);

  const handleDownload = (file: DemoFile) => {
    setActiveDownloadingId(file.id);
    setDownloadProgress(0);

    const interval = setInterval(() => {
      setDownloadProgress((prev) => {
        if (prev >= 100) {
          clearInterval(interval);
          setActiveDownloadingId(null);
          accessFile(file.id, 'DOWNLOAD');
          return 100;
        }
        return prev + 25;
      });
    }, 150);
  };

  const handleOpenPreview = (file: DemoFile) => {
    setPreviewFile(file);
    accessFile(file.id, 'OPEN');
  };

  const getFileIcon = (file: DemoFile) => {
    if (file.name.endsWith('.pdf')) {
      return <FileText className="w-4 h-4 text-[#FF5C6C]" />;
    }
    if (file.name.endsWith('.docx')) {
      return <FileText className="w-4 h-4 text-[#5B8CFF]" />;
    }
    if (file.name.endsWith('.xlsx') || file.name.endsWith('.csv')) {
      return <FileSpreadsheet className="w-4 h-4 text-[#20C997]" />;
    }
    if (file.name.endsWith('.zip') || file.name.endsWith('.tar.gz')) {
      return <FileArchive className="w-4 h-4 text-[#FFB020]" />;
    }
    return <FileCode className="w-4 h-4 text-[#8B7CFF]" />;
  };

  const getClassificationBadge = (classification: FileClassification) => {
    switch (classification) {
      case 'PUBLIC':
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-[#0D1424] text-slate-300 border border-[#22304A]">
            PUBLIC
          </span>
        );
      case 'INTERNAL':
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-[#5B8CFF]/15 text-[#5B8CFF] border border-[#5B8CFF]/30">
            INTERNAL
          </span>
        );
      case 'CONFIDENTIAL':
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-[#FFB020]/15 text-[#FFB020] border border-[#FFB020]/30">
            CONFIDENTIAL
          </span>
        );
      case 'SENSITIVE':
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-[#FFB020]/20 text-[#FFB020] border border-[#FFB020]/40">
            SENSITIVE PII
          </span>
        );
      case 'RESTRICTED':
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-[#FF5C6C]/15 text-[#FF5C6C] border border-[#FF5C6C]/30">
            RESTRICTED R&D
          </span>
        );
      case 'HIGHLY_CONFIDENTIAL':
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-[#8B7CFF]/15 text-[#8B7CFF] border border-[#8B7CFF]/30">
            HIGHLY CONFIDENTIAL
          </span>
        );
      default:
        return null;
    }
  };

  return (
    <div className="p-6 space-y-6 max-w-[1600px] mx-auto text-slate-200">
      {/* Top Banner */}
      <div className="soc-card p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-[#5B8CFF]/15 border border-[#5B8CFF]/30 flex items-center justify-center text-[#5B8CFF]">
            <FolderLock className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-xl font-bold text-white tracking-tight">
                Corporate Document Repository
              </h1>
              <span className="text-xs px-2 py-0.5 rounded bg-[#0D1424] text-slate-300 font-mono border border-[#22304A]">
                {files.length} Managed Files
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Secure departmental storage and internal resource distribution.
            </p>
          </div>
        </div>

        {/* SOC Telemetry Context Tag */}
        {isSOCRole && (
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-[#0D1424] border border-[#22304A] text-slate-300 text-xs font-mono">
            <Radio className="w-3.5 h-3.5 text-[#5B8CFF] animate-pulse" />
            <span>SOC Telemetry Active</span>
          </div>
        )}
      </div>

      {/* Filters & Search Toolbar */}
      <div className="soc-card p-4 flex flex-col md:flex-row gap-4 items-center justify-between">
        {/* Search */}
        <div className="relative w-full md:w-80">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            id="input-file-search"
            type="text"
            placeholder="Search by file name or department..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-[#0D1424] border border-[#22304A] text-slate-200 text-xs rounded-lg pl-9 pr-3 py-2 focus:outline-none focus:border-[#5B8CFF] transition-colors"
          />
        </div>

        {/* Department Filter */}
        <div className="flex flex-wrap items-center gap-2 w-full md:w-auto">
          <span className="text-xs font-semibold text-slate-400 flex items-center gap-1 mr-1">
            <Filter className="w-3.5 h-3.5" /> Dept:
          </span>
          <select
            id="select-dept-filter"
            value={selectedDept}
            onChange={(e) => setSelectedDept(e.target.value)}
            className="bg-[#0D1424] border border-[#22304A] text-slate-200 text-xs rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-[#5B8CFF] cursor-pointer"
          >
            {departments.map((dept) => (
              <option key={dept} value={dept}>
                {dept === 'ALL' ? 'All Departments' : dept}
              </option>
            ))}
          </select>

          <span className="text-xs font-semibold text-slate-400 flex items-center gap-1 ml-2 mr-1">
            Classification:
          </span>
          <select
            id="select-class-filter"
            value={selectedClassification}
            onChange={(e) => setSelectedClassification(e.target.value)}
            className="bg-[#0D1424] border border-[#22304A] text-slate-200 text-xs rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-[#5B8CFF] cursor-pointer"
          >
            {classifications.map((cls) => (
              <option key={cls} value={cls}>
                {cls === 'ALL' ? 'All Classifications' : cls}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Files Table */}
      <div className="soc-card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="bg-[#0D1424] border-b border-[#22304A] text-slate-400 uppercase tracking-wider text-[10px] font-semibold font-mono">
                <th className="py-3 px-4">File Name & Type</th>
                <th className="py-3 px-4">Department</th>
                <th className="py-3 px-4">Classification</th>
                <th className="py-3 px-4">File Size</th>
                <th className="py-3 px-4">Permission State</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#22304A]">
              {filteredFiles.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-slate-500 text-xs">
                    No files found matching your criteria.
                  </td>
                </tr>
              ) : (
                filteredFiles.map((file) => {
                  const isDownloading = activeDownloadingId === file.id;

                  return (
                    <tr
                      key={file.id}
                      id={`file-row-${file.id}`}
                      className="hover:bg-[#0D1424]/60 transition-colors"
                    >
                      {/* Name & Description */}
                      <td className="py-3 px-4">
                        <div className="flex items-center gap-3">
                          <div className="p-2 rounded-lg bg-[#0D1424] border border-[#22304A] shrink-0">
                            {getFileIcon(file)}
                          </div>
                          <div>
                            <span className="font-semibold text-white block text-xs">
                              {file.name}
                            </span>
                            <span className="text-[11px] text-slate-400 line-clamp-1">
                              {file.description}
                            </span>
                          </div>
                        </div>
                      </td>

                      {/* Department */}
                      <td className="py-3 px-4 text-slate-300">
                        <div className="flex items-center gap-1.5">
                          <Building className="w-3.5 h-3.5 text-slate-500" />
                          <span>{file.department}</span>
                        </div>
                      </td>

                      {/* Classification Badge */}
                      <td className="py-3 px-4">{getClassificationBadge(file.classification)}</td>

                      {/* File Size */}
                      <td className="py-3 px-4 font-mono text-slate-300">
                        {file.sizeMb >= 500 ? (
                          <span className="text-[#FFB020] font-bold">{file.sizeMb} MB</span>
                        ) : (
                          <span>{file.sizeMb} MB</span>
                        )}
                      </td>

                      {/* Permission State */}
                      <td className="py-3 px-4">
                        <div className="flex items-center gap-1.5 text-[11px]">
                          {file.accessPermission === 'GRANTED' ? (
                            <span className="text-[#20C997] flex items-center gap-1 font-semibold">
                              <CheckCircle2 className="w-3.5 h-3.5" /> Granted
                            </span>
                          ) : (
                            <span className="text-slate-400 flex items-center gap-1">
                              <KeyRound className="w-3.5 h-3.5 text-slate-500" /> Clearance Required
                            </span>
                          )}
                        </div>
                      </td>

                      {/* Action Buttons */}
                      <td className="py-3 px-4 text-right">
                        <div className="flex items-center justify-end gap-2">
                          <button
                            id={`btn-open-${file.id}`}
                            onClick={() => handleOpenPreview(file)}
                            className="px-2.5 py-1.5 rounded-lg bg-[#0D1424] hover:bg-[#111A2C] text-slate-300 hover:text-white transition-all text-xs font-semibold flex items-center gap-1 cursor-pointer border border-[#22304A]"
                            title="Open Document in Preview"
                          >
                            <Eye className="w-3.5 h-3.5 text-[#5B8CFF]" />
                            <span>Open</span>
                          </button>

                          <button
                            id={`btn-download-${file.id}`}
                            onClick={() => handleDownload(file)}
                            disabled={isDownloading}
                            className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-all cursor-pointer ${
                              isDownloading
                                ? 'bg-[#5B8CFF]/20 border border-[#5B8CFF] text-[#5B8CFF]'
                                : 'bg-[#5B8CFF] hover:bg-[#4a7cee] text-white'
                            }`}
                            title="Download file to workstation"
                          >
                            <Download className={`w-3.5 h-3.5 ${isDownloading ? 'animate-bounce' : ''}`} />
                            <span>{isDownloading ? `${downloadProgress}%` : 'Download'}</span>
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Document Viewer Modal */}
      {previewFile && (
        <div className="fixed inset-0 bg-[#080D18]/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-[#111A2C] border border-[#22304A] rounded-xl w-full max-w-2xl overflow-hidden shadow-2xl">
            {/* Modal Header */}
            <div className="p-4 border-b border-[#22304A] flex items-center justify-between bg-[#0D1424]">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-[#111A2C] border border-[#22304A]">
                  {getFileIcon(previewFile)}
                </div>
                <div>
                  <h3 className="font-bold text-white text-sm">{previewFile.name}</h3>
                  <div className="flex items-center gap-2 text-xs text-slate-400 mt-0.5">
                    <span>{previewFile.department}</span>
                    <span>•</span>
                    <span>{previewFile.sizeMb} MB</span>
                    <span>•</span>
                    {getClassificationBadge(previewFile.classification)}
                  </div>
                </div>
              </div>
              <button
                onClick={() => setPreviewFile(null)}
                className="p-1.5 text-slate-400 hover:text-white rounded-lg hover:bg-[#22304A] transition-colors cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Document Body */}
            <div className="p-5 space-y-4 max-h-96 overflow-y-auto bg-[#080D18] font-mono text-xs text-slate-300">
              <div className="p-4 rounded-lg bg-[#0D1424] border border-[#22304A] space-y-2">
                <div className="flex items-center justify-between text-[10px] text-slate-500 border-b border-[#22304A] pb-2">
                  <span>DOCUMENT PREVIEW ENGINE // v3.4</span>
                  <span>USER: {currentUser.username.toUpperCase()}</span>
                </div>
                <p className="text-slate-300 leading-relaxed font-sans text-xs pt-2">
                  {previewFile.description}
                </p>
                <div className="pt-3 text-[11px] font-mono text-slate-400 space-y-1">
                  <p>Classification Level: <span className="text-[#5B8CFF] font-semibold">{previewFile.classification}</span></p>
                  <p>Department: <span className="text-white">{previewFile.department}</span></p>
                  <p>Egress Policy: <span className="text-[#FFB020]">Monitored by SIEM DLP Agent</span></p>
                </div>
              </div>
            </div>

            {/* Modal Footer */}
            <div className="p-3 bg-[#0D1424] border-t border-[#22304A] flex items-center justify-between">
              <span className="text-xs text-slate-400">
                Viewing as <span className="text-white font-semibold">{currentUser.fullName}</span>
              </span>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => setPreviewFile(null)}
                  className="px-3 py-1.5 rounded-lg text-xs text-slate-300 hover:text-white hover:bg-[#22304A] transition-colors cursor-pointer font-medium"
                >
                  Close Viewer
                </button>
                <button
                  onClick={() => {
                    handleDownload(previewFile);
                    setPreviewFile(null);
                  }}
                  className="px-3.5 py-1.5 rounded-lg text-xs bg-[#5B8CFF] hover:bg-[#4a7cee] text-white font-semibold transition-colors cursor-pointer flex items-center gap-1.5"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>Download Copy ({previewFile.sizeMb} MB)</span>
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
