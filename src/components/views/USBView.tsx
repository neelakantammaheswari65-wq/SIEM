import React, { useState } from 'react';
import { useSIEM } from '../../context/SIEMContext';
import {
  Usb,
  ShieldCheck,
  Lock,
  Plus,
  Trash2,
  FileText,
  KeyRound,
  CheckCircle2,
  XCircle,
  ArrowRight,
  HardDrive,
  Settings,
} from 'lucide-react';
import { USB_TRANSFER_THRESHOLD_MB } from '../../services/siemEngine';

export const USBView: React.FC = () => {
  const {
    usbDevices,
    usbTransfers,
    users,
    toggleUSBAuth,
    simulateUSBInsert,
    simulateUSBRemove,
    simulateTransfer,
  } = useSIEM();

  // New Transfer Simulation Builder
  const [selectedDevice, setSelectedDevice] = useState<string>(usbDevices[0]?.deviceId || 'USB-APEX-092');
  const [selectedUser, setSelectedUser] = useState<number>(101);
  const [fileList, setFileList] = useState<
    { name: string; sizeMb: number; sensitive: boolean; type: string }[]
  >([
    { name: 'financial_projections_2026.xlsx', sizeMb: 24.5, sensitive: true, type: 'application/vnd.ms-excel' },
    { name: 'product_launch_deck.pdf', sizeMb: 12.0, sensitive: false, type: 'application/pdf' },
  ]);

  const [newFileName, setNewFileName] = useState('');
  const [newFileSize, setNewFileSize] = useState('150');
  const [newFileSensitive, setNewFileSensitive] = useState(false);
  const [newFileType, setNewFileType] = useState('application/zip');

  const [lastTransferResult, setLastTransferResult] = useState<any | null>(null);

  // Quick Device Insert Modal / State
  const [newDevId, setNewDevId] = useState('USB-ROGUE-999');
  const [newDevName, setNewDevName] = useState('Kingston DataTraveler 64GB');
  const [newDevCap, setNewDevCap] = useState(64);
  const [newDevAuth, setNewDevAuth] = useState(false);

  const handleAddFile = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newFileName.trim()) return;
    setFileList([
      ...fileList,
      {
        name: newFileName.trim(),
        sizeMb: Number(newFileSize) || 10,
        sensitive: newFileSensitive,
        type: newFileType,
      },
    ]);
    setNewFileName('');
  };

  const handleRemoveFile = (index: number) => {
    setFileList(fileList.filter((_, i) => i !== index));
  };

  const handleInsertDevice = (e: React.FormEvent) => {
    e.preventDefault();
    simulateUSBInsert({
      deviceId: newDevId.trim(),
      deviceName: newDevName.trim(),
      vendor: 'Generic USB Hardware',
      capacityGb: newDevCap,
      authorized: newDevAuth,
    });
    setNewDevId(`USB-TEST-${Math.floor(Math.random() * 899 + 100)}`);
  };

  const handleExecuteTransfer = (e: React.FormEvent) => {
    e.preventDefault();
    if (fileList.length === 0) return;
    const res = simulateTransfer(selectedUser, selectedDevice, fileList);
    setLastTransferResult(res);
  };

  const totalPayloadSize = fileList.reduce((acc, f) => acc + f.sizeMb, 0);

  return (
    <div className="p-6 space-y-6 max-w-[1600px] mx-auto text-slate-200">
      {/* Top Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-white tracking-tight">
            System & Endpoint DLP Settings
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Pre-flight peripheral inspection enforcing authorization whitelists and safe cryptographic protection.
          </p>
        </div>

        <div className="text-xs font-mono text-slate-300 bg-[#111A2C] px-3 py-1.5 rounded-lg border border-[#22304A]">
          DLP Threshold: <strong className="text-white">{USB_TRANSFER_THRESHOLD_MB} MB</strong>
        </div>
      </div>

      {/* Grid: Device Registry & Interactive Transfer Simulator */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Device Registry (5 cols) */}
        <div className="lg:col-span-5 space-y-6">
          <div className="soc-card p-5 space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-semibold text-white flex items-center gap-2">
                <HardDrive className="w-4 h-4 text-[#5B8CFF]" />
                Endpoint USB Device Registry
              </h2>
              <span className="text-xs text-slate-400 font-mono">{usbDevices.length} devices</span>
            </div>

            <div className="space-y-3">
              {usbDevices.map((dev) => {
                const isBlocked = dev.status === 'BLOCKED' || !dev.authorized;

                return (
                  <div
                    key={dev.deviceId}
                    className={`p-3.5 rounded-lg border transition-all ${
                      isBlocked
                        ? 'bg-[#FF5C6C]/5 border-[#FF5C6C]/30'
                        : 'bg-[#0D1424] border-[#22304A]'
                    }`}
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="text-xs font-bold text-white font-mono">{dev.deviceId}</span>
                          <span
                            className={`text-[10px] px-2 py-0.5 rounded-full font-medium ${
                              dev.authorized
                                ? 'bg-[#20C997]/15 text-[#20C997] border border-[#20C997]/30'
                                : 'bg-[#FF5C6C]/15 text-[#FF5C6C] border border-[#FF5C6C]/30'
                            }`}
                          >
                            {dev.authorized ? 'AUTHORIZED' : 'UNAUTHORIZED'}
                          </span>
                        </div>
                        <p className="text-xs font-medium text-slate-200 mt-1">{dev.deviceName}</p>
                        <p className="text-[11px] text-slate-400 font-mono">
                          {dev.vendor} · {dev.capacityGb} GB
                        </p>
                      </div>

                      <div className="text-right">
                        <span
                          className={`text-[10px] px-2 py-0.5 rounded-full font-medium ${
                            dev.status === 'CONNECTED'
                              ? 'bg-[#20C997]/15 text-[#20C997] border border-[#20C997]/30'
                              : dev.status === 'BLOCKED'
                              ? 'bg-[#FF5C6C]/15 text-[#FF5C6C] border border-[#FF5C6C]/30'
                              : 'bg-slate-800 text-slate-400'
                          }`}
                        >
                          {dev.status}
                        </span>
                      </div>
                    </div>

                    <div className="mt-3 pt-2.5 border-t border-[#22304A] flex items-center justify-between text-xs">
                      <span className="text-[11px] text-slate-400">
                        Assigned: <strong className="text-white">@{dev.username || 'System'}</strong>
                      </span>

                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => toggleUSBAuth(dev.deviceId, !dev.authorized)}
                          className={`px-2.5 py-1 rounded-lg text-xs font-medium border transition-colors cursor-pointer ${
                            dev.authorized
                              ? 'bg-[#FF5C6C]/15 hover:bg-[#FF5C6C]/25 text-[#FF5C6C] border-[#FF5C6C]/30'
                              : 'bg-[#20C997]/15 hover:bg-[#20C997]/25 text-[#20C997] border-[#20C997]/30'
                          }`}
                        >
                          {dev.authorized ? 'Revoke Auth' : 'Authorize'}
                        </button>

                        {dev.status === 'CONNECTED' && (
                          <button
                            onClick={() => simulateUSBRemove(dev.deviceId)}
                            className="px-2.5 py-1 rounded-lg bg-[#111A2C] hover:bg-[#1E2B42] text-slate-300 border border-[#22304A] text-xs cursor-pointer"
                          >
                            Eject
                          </button>
                        )}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Quick Hardware Simulator */}
          <div className="soc-card p-5 space-y-4">
            <h2 className="text-sm font-semibold text-white flex items-center gap-2">
              <Usb className="w-4 h-4 text-[#8B7CFF]" />
              Simulate Physical USB Connection
            </h2>

            <form onSubmit={handleInsertDevice} className="space-y-3 text-xs">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 mb-1">Device ID</label>
                  <input
                    type="text"
                    value={newDevId}
                    onChange={(e) => setNewDevId(e.target.value)}
                    className="w-full bg-[#0D1424] border border-[#22304A] rounded-lg p-2 text-slate-200 font-mono focus:outline-none focus:border-[#5B8CFF]"
                    required
                  />
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">Capacity (GB)</label>
                  <input
                    type="number"
                    value={newDevCap}
                    onChange={(e) => setNewDevCap(Number(e.target.value))}
                    className="w-full bg-[#0D1424] border border-[#22304A] rounded-lg p-2 text-slate-200 font-mono focus:outline-none focus:border-[#5B8CFF]"
                    required
                  />
                </div>
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Device Model / Label</label>
                <input
                  type="text"
                  value={newDevName}
                  onChange={(e) => setNewDevName(e.target.value)}
                  className="w-full bg-[#0D1424] border border-[#22304A] rounded-lg p-2 text-slate-200 focus:outline-none focus:border-[#5B8CFF]"
                  required
                />
              </div>

              <div className="flex items-center gap-2 pt-1">
                <input
                  type="checkbox"
                  id="chk-auth-dev"
                  checked={newDevAuth}
                  onChange={(e) => setNewDevAuth(e.target.checked)}
                  className="w-3.5 h-3.5 rounded bg-[#0D1424] border-[#22304A] cursor-pointer"
                />
                <label htmlFor="chk-auth-dev" className="text-slate-300 cursor-pointer">
                  Pre-approve on Corporate Whitelist
                </label>
              </div>

              <button
                type="submit"
                className="w-full py-2 bg-[#5B8CFF] hover:bg-[#4a7cee] text-white font-semibold rounded-lg transition-colors flex items-center justify-center gap-2 cursor-pointer mt-2"
              >
                <Plus className="w-3.5 h-3.5" />
                <span>Simulate Device Plug-In</span>
              </button>
            </form>
          </div>
        </div>

        {/* Interactive Transfer Policy Simulator (7 cols) */}
        <div className="lg:col-span-7 space-y-6">
          <div className="soc-card p-5 space-y-4">
            <div>
              <h2 className="text-sm font-semibold text-white flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-[#20C997]" />
                Pre-Transfer DLP Policy Evaluation Simulator
              </h2>
              <p className="text-xs text-slate-400 mt-1">
                Construct payload files and test the <span className="text-[#5B8CFF] font-mono">BLOCK &gt; PROTECT &gt; ALLOW</span> decision hierarchy.
              </p>
            </div>

            <form onSubmit={handleExecuteTransfer} className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs text-slate-400 mb-1">User Identity</label>
                  <select
                    value={selectedUser}
                    onChange={(e) => setSelectedUser(Number(e.target.value))}
                    className="w-full bg-[#0D1424] border border-[#22304A] rounded-lg p-2 text-xs text-slate-200 focus:outline-none focus:border-[#5B8CFF]"
                  >
                    {users.map((u) => (
                      <option key={u.id} value={u.id}>
                        {u.fullName} (@{u.username})
                      </option>
                    ))}
                  </select>
                </div>

                <div>
                  <label className="block text-xs text-slate-400 mb-1">Target USB Device</label>
                  <select
                    value={selectedDevice}
                    onChange={(e) => setSelectedDevice(e.target.value)}
                    className="w-full bg-[#0D1424] border border-[#22304A] rounded-lg p-2 text-xs text-slate-200 font-mono focus:outline-none focus:border-[#5B8CFF]"
                  >
                    {usbDevices.map((d) => (
                      <option key={d.deviceId} value={d.deviceId}>
                        {d.deviceId} - {d.deviceName} ({d.authorized ? 'AUTH' : 'UNAUTH'})
                      </option>
                    ))}
                  </select>
                </div>
              </div>

              {/* Staged Payload Files */}
              <div className="space-y-2">
                <div className="flex items-center justify-between text-xs text-slate-300">
                  <span className="font-semibold">Staged Payload Files ({fileList.length})</span>
                  <span className="font-mono text-[#5B8CFF]">
                    Total: {totalPayloadSize.toFixed(1)} MB {totalPayloadSize > 500 && '(>500MB Limit)'}
                  </span>
                </div>

                <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
                  {fileList.map((f, idx) => (
                    <div
                      key={idx}
                      className={`p-2.5 rounded-lg border flex items-center justify-between text-xs font-mono ${
                        f.sensitive
                          ? 'bg-[#FFB020]/10 border-[#FFB020]/30 text-amber-200'
                          : 'bg-[#0D1424] border-[#22304A] text-slate-300'
                      }`}
                    >
                      <div className="flex items-center gap-2 min-w-0">
                        <FileText className="w-3.5 h-3.5 shrink-0 text-slate-400" />
                        <span className="truncate font-sans">{f.name}</span>
                        {f.sensitive && (
                          <span className="px-1.5 py-0.2 bg-[#FF5C6C]/20 text-[#FF5C6C] border border-[#FF5C6C]/40 rounded text-[9px] font-bold">
                            RESTRICTED
                          </span>
                        )}
                      </div>

                      <div className="flex items-center gap-3 shrink-0">
                        <span className="text-slate-400">{f.sizeMb} MB</span>
                        <button
                          type="button"
                          onClick={() => handleRemoveFile(idx)}
                          className="text-slate-500 hover:text-[#FF5C6C] cursor-pointer"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Add Custom File to Staging */}
              <div className="p-3 rounded-lg bg-[#0D1424] border border-[#22304A] space-y-2">
                <span className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider block">Stage New File</span>
                <div className="grid grid-cols-1 sm:grid-cols-12 gap-2 text-xs">
                  <div className="sm:col-span-6">
                    <input
                      type="text"
                      placeholder="File Name (e.g. salaries.xlsx)"
                      value={newFileName}
                      onChange={(e) => setNewFileName(e.target.value)}
                      className="w-full bg-[#111A2C] border border-[#22304A] rounded-lg px-2.5 py-1.5 text-slate-200 focus:outline-none focus:border-[#5B8CFF]"
                    />
                  </div>
                  <div className="sm:col-span-3">
                    <input
                      type="number"
                      placeholder="Size MB"
                      value={newFileSize}
                      onChange={(e) => setNewFileSize(e.target.value)}
                      className="w-full bg-[#111A2C] border border-[#22304A] rounded-lg px-2.5 py-1.5 text-slate-200 font-mono focus:outline-none focus:border-[#5B8CFF]"
                    />
                  </div>
                  <div className="sm:col-span-3 flex items-center justify-between gap-2">
                    <label className="flex items-center gap-1 text-slate-300 text-[11px] cursor-pointer">
                      <input
                        type="checkbox"
                        checked={newFileSensitive}
                        onChange={(e) => setNewFileSensitive(e.target.checked)}
                        className="w-3 h-3 rounded bg-[#111A2C] border-[#22304A]"
                      />
                      <span>Sensitive</span>
                    </label>
                    <button
                      type="button"
                      onClick={handleAddFile}
                      className="px-3 py-1.5 bg-[#111A2C] hover:bg-[#1E2B42] text-[#5B8CFF] rounded-lg font-semibold cursor-pointer text-xs border border-[#22304A]"
                    >
                      Add
                    </button>
                  </div>
                </div>
              </div>

              <button
                type="submit"
                className="w-full py-2.5 bg-[#5B8CFF] hover:bg-[#4a7cee] text-white font-semibold rounded-lg transition-colors flex items-center justify-center gap-2 cursor-pointer text-xs"
              >
                <span>Evaluate & Intercept Transfer Request</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </form>

            {/* Live Evaluation Result Card */}
            {lastTransferResult && (
              <div
                className={`p-4 rounded-lg border transition-all space-y-2.5 ${
                  lastTransferResult.decision === 'BLOCK'
                    ? 'bg-[#FF5C6C]/10 border-[#FF5C6C]/40 text-red-200'
                    : lastTransferResult.decision === 'PROTECT'
                    ? 'bg-[#FFB020]/10 border-[#FFB020]/40 text-amber-200'
                    : 'bg-[#20C997]/10 border-[#20C997]/40 text-emerald-200'
                }`}
              >
                <div className="flex items-center justify-between border-b border-[#22304A] pb-2">
                  <div className="flex items-center gap-2">
                    {lastTransferResult.decision === 'BLOCK' ? (
                      <XCircle className="w-5 h-5 text-[#FF5C6C]" />
                    ) : lastTransferResult.decision === 'PROTECT' ? (
                      <Lock className="w-5 h-5 text-[#FFB020]" />
                    ) : (
                      <CheckCircle2 className="w-5 h-5 text-[#20C997]" />
                    )}
                    <div>
                      <h4 className="text-sm font-bold text-white">
                        DECISION: {lastTransferResult.decision}
                      </h4>
                      <p className="text-[11px] opacity-80 font-mono">
                        Ref: {lastTransferResult.transferId}
                      </p>
                    </div>
                  </div>

                  <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-[#111A2C] border border-[#22304A] text-white">
                    {lastTransferResult.totalSizeMb.toFixed(1)} MB / {lastTransferResult.fileCount} File(s)
                  </span>
                </div>

                <div className="space-y-1 text-xs">
                  <p className="font-semibold text-white">Policy Justifications:</p>
                  {lastTransferResult.reasons.map((r: string, i: number) => (
                    <p key={i} className="opacity-80">
                      • {r}
                    </p>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
