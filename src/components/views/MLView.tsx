import React, { useState } from 'react';
import { useSIEM } from '../../context/SIEMContext';
import {
  BrainCircuit,
  Cpu,
  RefreshCw,
  CheckCircle2,
  AlertTriangle,
  Layers,
  Sparkles,
} from 'lucide-react';

export const MLView: React.FC = () => {
  const { anomalies, trainMLModel, recalculateAllRisk } = useSIEM();
  const [isTraining, setIsTraining] = useState(false);
  const [contamination] = useState(0.1);

  const handleTrain = () => {
    setIsTraining(true);
    trainMLModel();
    recalculateAllRisk();
    setTimeout(() => setIsTraining(false), 800);
  };

  return (
    <div className="p-6 space-y-6 max-w-[1600px] mx-auto text-slate-200">
      {/* Top Header Card */}
      <div className="soc-card p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
            <BrainCircuit className="w-5 h-5 text-[#8B7CFF]" />
            Machine Learning Anomaly Engine (Isolation Forest)
          </h1>
          <p className="text-xs text-slate-400 mt-1 max-w-2xl">
            Unsupervised tree-based anomaly partitioning on 7 behavioral feature vectors without requiring historical threat labels.
          </p>
        </div>

        <button
          id="btn-retrain-ml"
          onClick={handleTrain}
          disabled={isTraining}
          className="flex items-center gap-2 px-4 py-2 rounded-lg bg-[#5B8CFF] hover:bg-[#4a7cee] text-white text-xs font-semibold shadow-md transition-all cursor-pointer disabled:opacity-50"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isTraining ? 'animate-spin' : ''}`} />
          <span>{isTraining ? 'Fitting Estimators...' : 'Retrain Isolation Forest'}</span>
        </button>
      </div>

      {/* Model Spec & Parameters Grid Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 font-mono text-xs">
        <div className="soc-card p-4">
          <p className="text-[10px] text-slate-400 font-semibold uppercase tracking-wider">MODEL STATUS</p>
          <p className="text-sm font-bold text-[#20C997] mt-1 flex items-center gap-1.5 font-sans">
            <CheckCircle2 className="w-4 h-4 text-[#20C997]" />
            ONLINE (READY)
          </p>
          <p className="text-[10px] text-slate-400 mt-1 font-mono">Version: iforest-v1.4</p>
        </div>

        <div className="soc-card p-4">
          <p className="text-[10px] text-slate-400 font-semibold uppercase tracking-wider">ESTIMATORS & DEPTH</p>
          <p className="text-sm font-bold text-white mt-1 font-mono">100 Trees / iTrees</p>
          <p className="text-[10px] text-slate-400 mt-1 font-mono">Subsample: 256 samples</p>
        </div>

        <div className="soc-card p-4">
          <p className="text-[10px] text-slate-400 font-semibold uppercase tracking-wider">CONTAMINATION PARAM</p>
          <p className="text-sm font-bold text-[#5B8CFF] mt-1 font-mono">{contamination} (10%)</p>
          <p className="text-[10px] text-slate-400 mt-1 font-mono">Outlier expectation threshold</p>
        </div>

        <div className="soc-card p-4">
          <p className="text-[10px] text-slate-400 font-semibold uppercase tracking-wider">SCORING RANGE</p>
          <p className="text-sm font-bold text-[#8B7CFF] mt-1 font-mono">0 – 100 Normalized</p>
          <p className="text-[10px] text-slate-400 mt-1 font-mono">100 = Max Behavioral Deviation</p>
        </div>
      </div>

      {/* Feature Extraction Vector Matrix Table */}
      <div className="soc-card p-5 space-y-4">
        <div>
          <h3 className="text-sm font-semibold text-white flex items-center gap-2">
            <Layers className="w-4 h-4 text-[#5B8CFF]" />
            24-Hour Behavioral Feature Extraction Matrix
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Aggregated numerical telemetry dimensions transformed into tabular arrays for tree partitioning.
          </p>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse font-mono text-xs">
            <thead>
              <tr className="border-b border-[#22304A] bg-[#0D1424] text-[10px] text-slate-400 uppercase tracking-wider">
                <th className="py-3 px-4">User</th>
                <th className="py-3 px-4 text-center">Logins</th>
                <th className="py-3 px-4 text-center">Failed Logins</th>
                <th className="py-3 px-4 text-center">USB Inserts</th>
                <th className="py-3 px-4 text-center">USB Transfers</th>
                <th className="py-3 px-4 text-center">USB Vol (MB)</th>
                <th className="py-3 px-4 text-center">Sensitive Files</th>
                <th className="py-3 px-4 text-center">Rule Findings</th>
                <th className="py-3 px-4 text-right">Anomaly Score</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#22304A]">
              {anomalies.map((anom) => {
                const isHigh = anom.anomalyScore >= 75;
                const isMed = anom.anomalyScore >= 50 && anom.anomalyScore < 75;

                return (
                  <tr key={anom.userId} className="hover:bg-[#0D1424]/60 transition-colors">
                    <td className="py-3 px-4 font-sans font-semibold text-white">@{anom.username}</td>
                    <td className="py-3 px-4 text-center text-slate-300">{anom.featureSnapshot.login_count}</td>
                    <td className="py-3 px-4 text-center font-bold text-[#FFB020]">
                      {anom.featureSnapshot.failed_login_count}
                    </td>
                    <td className="py-3 px-4 text-center text-slate-300">{anom.featureSnapshot.usb_insert_count}</td>
                    <td className="py-3 px-4 text-center text-slate-300">{anom.featureSnapshot.usb_transfer_count}</td>
                    <td className="py-3 px-4 text-center font-bold text-[#8B7CFF]">
                      {anom.featureSnapshot.total_usb_mb.toFixed(1)} MB
                    </td>
                    <td className="py-3 px-4 text-center font-bold text-[#FF5C6C]">
                      {anom.featureSnapshot.sensitive_access_count}
                    </td>
                    <td className="py-3 px-4 text-center font-bold text-[#FFB020]">
                      {anom.featureSnapshot.finding_count}
                    </td>
                    <td className="py-3 px-4 text-right">
                      <div className="flex items-center justify-end gap-2">
                        <span
                          className={`text-xs font-bold font-mono ${
                            isHigh ? 'text-[#FF5C6C]' : isMed ? 'text-[#FFB020]' : 'text-[#20C997]'
                          }`}
                        >
                          {anom.anomalyScore}
                        </span>
                        <span
                          className={`text-[9px] px-2 py-0.5 rounded-full font-semibold ${
                            isHigh
                              ? 'bg-[#FF5C6C]/15 text-[#FF5C6C] border border-[#FF5C6C]/30'
                              : isMed
                              ? 'bg-[#FFB020]/15 text-[#FFB020] border border-[#FFB020]/30'
                              : 'bg-[#20C997]/15 text-[#20C997] border border-[#20C997]/30'
                          }`}
                        >
                          {anom.anomalyLevel}
                        </span>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Behavioral Deviation Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {anomalies.map((anom) => (
          <div key={anom.userId} className="soc-card p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-[#22304A] pb-3">
              <div className="flex items-center gap-3">
                <div className="w-9 h-9 rounded-lg bg-[#8B7CFF]/15 border border-[#8B7CFF]/30 text-[#8B7CFF] flex items-center justify-center font-bold text-sm">
                  {anom.username.charAt(0).toUpperCase()}
                </div>
                <div>
                  <h4 className="text-xs font-bold text-white">@{anom.username}</h4>
                  <span className="text-[10px] text-slate-400 font-mono">UID: {anom.userId}</span>
                </div>
              </div>

              <div className="text-right font-mono">
                <span className="text-base font-bold text-[#8B7CFF]">{anom.anomalyScore}/100</span>
                <p className="text-[10px] text-slate-400">Anomaly Index</p>
              </div>
            </div>

            <div>
              <p className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                <Sparkles className="w-3.5 h-3.5 text-[#8B7CFF]" />
                Behavioral Deviation Indicators
              </p>
              <div className="space-y-1.5 text-xs">
                {anom.indicators.map((ind, i) => (
                  <p key={i} className="p-2.5 rounded-lg bg-[#0D1424] border border-[#22304A] text-slate-300 text-[11px] leading-relaxed">
                    › {ind}
                  </p>
                ))}
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
