import React, { useState } from 'react';
import { useSIEM } from '../../context/SIEMContext';
import { Activity, Clock, RefreshCw, Shield, PieChart as PieIcon, AlertTriangle } from 'lucide-react';

export const RiskView: React.FC = () => {
  const { users, riskScores, recalculateAllRisk, setSelectedUser, selectedUser } = useSIEM();
  const [activeUserTab, setActiveUserTab] = useState<number>(selectedUser?.id || (users[0]?.id ?? 101));

  const activeUser = users.find((u) => u.id === activeUserTab) || users[0] || {
    id: 101,
    fullName: 'Alex Mercer',
    username: 'amercer',
    email: 'amercer@enterprise.com',
    department: 'R&D Engineering',
    role: 'EMPLOYEE',
  };

  const activeRisk = riskScores.find((r) => r.userId === activeUser.id) || {
    finalScore: 12,
    ruleScore: 12,
    mlScore: 5,
    riskLevel: 'LOW',
    contributingFindingsCount: 0,
    scoreBreakdown: {},
  };

  const breakdownData = Object.entries(activeRisk.scoreBreakdown || {}).map(([ruleCode, value]) => ({
    ruleCode,
    value: Number(value),
  }));

  const decaySchedule = [
    { range: '< 1 hour', decay: '100% (1.00x)', desc: 'Immediate Incident Window' },
    { range: '1 - 6 hours', decay: '75% (0.75x)', desc: 'Active Incident Window' },
    { range: '6 - 12 hours', decay: '50% (0.50x)', desc: 'Moderate Threat Dissipation' },
    { range: '12 - 24 hours', decay: '25% (0.25x)', desc: 'Residual Baseline Impact' },
    { range: '> 24 hours', decay: '0% (0.00x)', desc: 'Excluded from Active Score' },
  ];

  return (
    <div className="p-6 space-y-6 max-w-[1600px] mx-auto text-slate-200">
      {/* Top Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-white tracking-tight">
            Threat Detection & Behavioral Risk Engine
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Deterministic risk scoring: Raw Risk = Sum(Finding.RiskWeight × TimeDecayFactor), capped at min(Raw, 100).
          </p>
        </div>

        <button
          onClick={recalculateAllRisk}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#5B8CFF] hover:bg-[#4a7cee] text-white text-xs font-semibold cursor-pointer"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          <span>Recalculate All Scores</span>
        </button>
      </div>

      {/* User Selector Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
        {users.slice(0, 10).map((u) => {
          const userScore = riskScores.find((r) => r.userId === u.id)?.finalScore || 0;
          const isCrit = userScore >= 75;
          const isHigh = userScore >= 50 && userScore < 75;
          const isMed = userScore >= 25 && userScore < 50;
          const isSelected = activeUserTab === u.id;

          const scoreColor = isCrit
            ? 'text-[#FF5C6C]'
            : isHigh
            ? 'text-[#FFB020]'
            : isMed
            ? 'text-[#5B8CFF]'
            : 'text-[#20C997]';

          return (
            <button
              key={u.id}
              onClick={() => {
                setActiveUserTab(u.id);
                setSelectedUser(u);
              }}
              className={`p-3 rounded-lg border text-left transition-all cursor-pointer ${
                isSelected
                  ? 'bg-[#111A2C] border-[#5B8CFF] shadow-md'
                  : 'bg-[#0D1424] border-[#22304A] hover:border-[#314366]'
              }`}
            >
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-white truncate">{u.fullName}</span>
                <span className={`text-xs font-mono font-bold ${scoreColor}`}>
                  {userScore}
                </span>
              </div>
              <p className="text-[11px] text-slate-400 mt-1 truncate">{u.department}</p>
            </button>
          );
        })}
      </div>

      {/* Active User Risk Deep Dive Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Gauge & Profile Card (4 cols) */}
        <div className="lg:col-span-4 soc-card p-5 flex flex-col justify-between space-y-6">
          <div>
            <div className="flex items-center gap-3 border-b border-[#22304A] pb-4">
              <div className="w-11 h-11 rounded-lg bg-[#5B8CFF]/15 border border-[#5B8CFF]/30 text-[#5B8CFF] flex items-center justify-center font-bold text-base">
                {activeUser.fullName.charAt(0)}
              </div>
              <div>
                <h2 className="text-sm font-semibold text-white">{activeUser.fullName}</h2>
                <p className="text-xs text-slate-400 font-mono">@{activeUser.username}</p>
                <span className="inline-block mt-1 text-[10px] px-2 py-0.5 bg-[#0D1424] text-slate-300 rounded font-medium border border-[#22304A]">
                  {activeUser.department}
                </span>
              </div>
            </div>

            {/* Circular Gauge Visual */}
            <div className="my-6 flex flex-col items-center justify-center">
              <div className="relative flex items-center justify-center w-36 h-36 rounded-full border-4 border-[#22304A] bg-[#0D1424]">
                <div
                  className={`absolute inset-0 rounded-full border-4 border-t-transparent ${
                    activeRisk.finalScore >= 75
                      ? 'border-[#FF5C6C] animate-pulse'
                      : activeRisk.finalScore >= 50
                      ? 'border-[#FFB020]'
                      : activeRisk.finalScore >= 25
                      ? 'border-[#5B8CFF]'
                      : 'border-[#20C997]'
                  }`}
                  style={{ transform: `rotate(${activeRisk.finalScore * 3.6}deg)` }}
                />
                <div className="text-center z-10">
                  <span className="text-3xl font-extrabold font-mono text-white">
                    {activeRisk.finalScore}
                  </span>
                  <p className="text-[10px] font-mono text-slate-400 uppercase tracking-widest mt-0.5">/ 100</p>
                </div>
              </div>

              <div className="mt-4 text-center">
                <span
                  className={`px-3 py-1 rounded-full text-xs font-semibold font-mono ${
                    activeRisk.finalScore >= 75
                      ? 'bg-[#FF5C6C]/15 text-[#FF5C6C] border border-[#FF5C6C]/30'
                      : activeRisk.finalScore >= 50
                      ? 'bg-[#FFB020]/15 text-[#FFB020] border border-[#FFB020]/30'
                      : activeRisk.finalScore >= 25
                      ? 'bg-[#5B8CFF]/15 text-[#5B8CFF] border border-[#5B8CFF]/30'
                      : 'bg-[#20C997]/15 text-[#20C997] border border-[#20C997]/30'
                  }`}
                >
                  RISK TIER: {activeRisk.riskLevel}
                </span>
              </div>
            </div>
          </div>

          <div className="p-3 bg-[#0D1424] rounded-lg border border-[#22304A] text-xs space-y-1.5 font-mono">
            <div className="flex justify-between text-slate-400">
              <span>Rule Engine Component:</span>
              <span className="text-[#FFB020] font-bold">{activeRisk.ruleScore}</span>
            </div>
            <div className="flex justify-between text-slate-400">
              <span>ML Isolation Forest Score:</span>
              <span className="text-[#5B8CFF] font-bold">{activeRisk.mlScore}</span>
            </div>
            <div className="flex justify-between text-slate-400">
              <span>Contributing Findings:</span>
              <span className="text-white font-bold">{activeRisk.contributingFindingsCount}</span>
            </div>
          </div>
        </div>

        {/* Explainability Breakdown & Decay Curve (8 cols) */}
        <div className="lg:col-span-8 space-y-6">
          {/* Breakdown Card */}
          <div className="soc-card p-5 space-y-4">
            <div>
              <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                <PieIcon className="w-4 h-4 text-[#5B8CFF]" />
                Explainable Risk Contribution Breakdown
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Weighted rule violations after applying deterministic time decay.
              </p>
            </div>

            {breakdownData.length === 0 ? (
              <div className="p-8 text-center bg-[#0D1424] rounded-lg border border-[#22304A] text-xs text-slate-400">
                No active rule findings recorded in the calculation window. Baseline score is normal.
              </div>
            ) : (
              <div className="space-y-3">
                {breakdownData.map((item) => (
                  <div key={item.ruleCode} className="space-y-1">
                    <div className="flex justify-between text-xs font-mono">
                      <span className="text-[#5B8CFF] font-semibold">{item.ruleCode}</span>
                      <span className="text-[#FFB020] font-bold">+{item.value.toFixed(1)} pts</span>
                    </div>
                    <div className="w-full bg-[#0D1424] rounded-full h-2 overflow-hidden border border-[#22304A]">
                      <div
                        className="bg-gradient-to-r from-[#FFB020] to-[#FF5C6C] h-full rounded-full"
                        style={{ width: `${Math.min((item.value / 100) * 100, 100)}%` }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Mathematical 24h Decay Table Card */}
          <div className="soc-card p-5 space-y-4">
            <div>
              <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                <Clock className="w-4 h-4 text-[#FFB020]" />
                Time-Decayed Behavioral Scoring Matrix
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Older findings decay progressively to prioritize recent insider threat activity.
              </p>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3 font-mono">
              {decaySchedule.map((s) => (
                <div key={s.range} className="p-3 bg-[#0D1424] rounded-lg border border-[#22304A] text-center">
                  <p className="text-[11px] text-slate-400">{s.range}</p>
                  <p className="text-sm font-bold text-[#5B8CFF] my-1">{s.decay}</p>
                  <p className="text-[10px] text-slate-400 font-sans">{s.desc}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
