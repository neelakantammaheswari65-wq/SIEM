import React, { useState } from 'react';
import { useSIEM } from '../../context/SIEMContext';
import {
  ShieldAlert,
  AlertTriangle,
  Activity,
  Terminal,
  Users,
  CheckCircle2,
  TrendingUp,
  Eye,
  ExternalLink,
  ChevronRight,
  Shield,
  ArrowUpRight,
  Calendar,
  Clock,
  Layers,
  Filter,
} from 'lucide-react';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  PieChart,
  Pie,
  Cell,
} from 'recharts';

export const DashboardView: React.FC = () => {
  const {
    summary,
    alerts,
    events,
    riskScores,
    users,
    setActiveTab,
    setSelectedAlert,
    setSelectedUser,
    acknowledgeAlert,
    resolveAlert,
  } = useSIEM();

  const [timeframe, setTimeframe] = useState<'24h' | '7d' | '30d'>('24h');
  const [selectedEventModal, setSelectedEventModal] = useState<any | null>(null);

  // Active Threats (Open & Acknowledged Alerts)
  const activeThreatsList = alerts.filter((a) => a.status === 'OPEN' || a.status === 'ACKNOWLEDGED');

  // Severity Distribution Data
  const critCount = alerts.filter((a) => a.severity === 'CRITICAL').length;
  const highCount = alerts.filter((a) => a.severity === 'HIGH').length;
  const medCount = alerts.filter((a) => a.severity === 'MEDIUM').length;
  const lowCount = alerts.filter((a) => a.severity === 'LOW').length;
  const totalSeverityCount = critCount + highCount + medCount + lowCount || 1;

  const severityDonutData = [
    { name: 'Critical', value: critCount, color: '#FF5C6C' },
    { name: 'High', value: highCount, color: '#FFB020' },
    { name: 'Medium', value: medCount, color: '#5B8CFF' },
    { name: 'Low', value: lowCount, color: '#20C997' },
  ];

  // Threat Activity Data Based on Timeframe
  const getActivityData = () => {
    if (timeframe === '24h') {
      return [
        { label: '00:00', events: 140, threats: 1, alerts: 1 },
        { label: '03:00', events: 90, threats: 0, alerts: 0 },
        { label: '06:00', events: 210, threats: 1, alerts: 1 },
        { label: '09:00', events: 950, threats: 4, alerts: 2 },
        { label: '12:00', events: 1480, threats: 8, alerts: 4 },
        { label: '15:00', events: 1620, threats: 11, alerts: 6 },
        { label: '18:00', events: 720, threats: 5, alerts: 3 },
        { label: '21:00', events: 340, threats: 2, alerts: 1 },
      ];
    }
    if (timeframe === '7d') {
      return [
        { label: 'Mon', events: 6400, threats: 18, alerts: 9 },
        { label: 'Tue', events: 8200, threats: 24, alerts: 14 },
        { label: 'Wed', events: 7900, threats: 21, alerts: 11 },
        { label: 'Thu', events: 9100, threats: 32, alerts: 16 },
        { label: 'Fri', events: 8700, threats: 29, alerts: 13 },
        { label: 'Sat', events: 2400, threats: 6, alerts: 2 },
        { label: 'Sun', events: 1900, threats: 4, alerts: 1 },
      ];
    }
    return [
      { label: 'Week 1', events: 38000, threats: 85, alerts: 42 },
      { label: 'Week 2', events: 44000, threats: 110, alerts: 54 },
      { label: 'Week 3', events: 41000, threats: 94, alerts: 48 },
      { label: 'Week 4', events: 49000, threats: 122, alerts: 61 },
    ];
  };

  // Top Risk Users
  const topRiskUsers = [...riskScores]
    .sort((a, b) => b.finalScore - a.finalScore)
    .slice(0, 5)
    .map((r) => {
      const u = users.find((usr) => usr.id === r.userId);
      return {
        id: r.userId,
        name: u?.fullName || `User #${r.userId}`,
        employeeId: u?.employeeId || `EMP-${r.userId.toString().padStart(4, '0')}`,
        department: u?.department || 'Operations',
        score: r.finalScore,
        level: r.riskLevel,
        userObj: u,
      };
    });

  // Recent 6 Security Events
  const recentEvents = events.slice(0, 6);

  return (
    <div className="p-6 space-y-6 max-w-[1600px] mx-auto text-slate-200">
      {/* ==================================================
          SECTION 3: WELCOME HEADER & 4 COMPACT KPI CARDS
          ================================================== */}
      <div>
        <h1 className="text-xl font-bold text-white tracking-tight">
          Welcome to Security Operations Center
        </h1>
        <p className="text-xs text-slate-400 mt-1">
          Monitor insider activity, investigate threats and respond to security incidents.
        </p>
      </div>

      {/* 4 Clean Compact KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* 1. TOTAL EVENTS */}
        <div className="soc-card p-4 flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
              TOTAL EVENTS
            </span>
            <div className="w-8 h-8 rounded-lg bg-[#5B8CFF]/15 border border-[#5B8CFF]/30 flex items-center justify-center text-[#5B8CFF]">
              <Terminal className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3">
            <div className="text-2xl font-bold font-mono text-white">
              {summary.totalEvents.toLocaleString()}
            </div>
            <div className="flex items-center justify-between text-xs text-slate-400 mt-1">
              <span>Telemetry ingested</span>
              <span className="flex items-center text-[#20C997] font-medium text-[11px]">
                <TrendingUp className="w-3 h-3 mr-0.5" /> +14.2%
              </span>
            </div>
          </div>
        </div>

        {/* 2. ACTIVE THREATS */}
        <div className="soc-card p-4 flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
              ACTIVE THREATS
            </span>
            <div className="w-8 h-8 rounded-lg bg-[#FFB020]/15 border border-[#FFB020]/30 flex items-center justify-center text-[#FFB020]">
              <Activity className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3">
            <div className="text-2xl font-bold font-mono text-white">
              {activeThreatsList.length}
            </div>
            <div className="flex items-center justify-between text-xs text-slate-400 mt-1">
              <span>Requires investigation</span>
              <span className="text-[#FFB020] font-medium text-[11px]">
                {alerts.filter((a) => a.severity === 'CRITICAL' && a.status === 'OPEN').length} Critical
              </span>
            </div>
          </div>
        </div>

        {/* 3. HIGH-RISK USERS */}
        <div className="soc-card p-4 flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
              HIGH-RISK USERS
            </span>
            <div className="w-8 h-8 rounded-lg bg-[#FF5C6C]/15 border border-[#FF5C6C]/30 flex items-center justify-center text-[#FF5C6C]">
              <Users className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3">
            <div className="text-2xl font-bold font-mono text-white">
              {summary.highRiskUsers}
            </div>
            <div className="flex items-center justify-between text-xs text-slate-400 mt-1">
              <span>Score &gt;= 75 / 100</span>
              <span className="text-[#FF5C6C] font-medium text-[11px]">Immediate review</span>
            </div>
          </div>
        </div>

        {/* 4. OPEN ALERTS */}
        <div className="soc-card p-4 flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
              OPEN ALERTS
            </span>
            <div className="w-8 h-8 rounded-lg bg-[#8B7CFF]/15 border border-[#8B7CFF]/30 flex items-center justify-center text-[#8B7CFF]">
              <ShieldAlert className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3">
            <div className="text-2xl font-bold font-mono text-white">
              {summary.openAlerts}
            </div>
            <div className="flex items-center justify-between text-xs text-slate-400 mt-1">
              <span>Triage queue</span>
              <button
                onClick={() => setActiveTab('alerts')}
                className="text-[#5B8CFF] hover:underline font-medium text-[11px] cursor-pointer"
              >
                View all &rarr;
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* ==================================================
          SECTION 4 & 5: THREAT ACTIVITY CHART & SEVERITY DONUT
          ================================================== */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Threat Activity Chart Card (2 cols) */}
        <div className="lg:col-span-2 soc-card p-5 space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div>
              <h2 className="text-sm font-semibold text-white tracking-tight">
                Threat Activity
              </h2>
              <p className="text-xs text-slate-400">
                Security events, threat detections, and correlated alerts
              </p>
            </div>

            {/* Timeframe selector: 24h, 7d, 30d */}
            <div className="flex items-center bg-[#0D1424] border border-[#22304A] rounded-lg p-0.5 text-xs">
              <button
                onClick={() => setTimeframe('24h')}
                className={`px-3 py-1 rounded-md transition-colors cursor-pointer ${
                  timeframe === '24h'
                    ? 'bg-[#111A2C] text-white font-semibold shadow-sm'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                24 Hours
              </button>
              <button
                onClick={() => setTimeframe('7d')}
                className={`px-3 py-1 rounded-md transition-colors cursor-pointer ${
                  timeframe === '7d'
                    ? 'bg-[#111A2C] text-white font-semibold shadow-sm'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                7 Days
              </button>
              <button
                onClick={() => setTimeframe('30d')}
                className={`px-3 py-1 rounded-md transition-colors cursor-pointer ${
                  timeframe === '30d'
                    ? 'bg-[#111A2C] text-white font-semibold shadow-sm'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                30 Days
              </button>
            </div>
          </div>

          {/* Area Chart with smooth curves, subtle grid, and clean tooltips */}
          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={getActivityData()} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="gradientEvents" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#5B8CFF" stopOpacity={0.35} />
                    <stop offset="95%" stopColor="#5B8CFF" stopOpacity={0.0} />
                  </linearGradient>
                  <linearGradient id="gradientThreats" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#FFB020" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#FFB020" stopOpacity={0.0} />
                  </linearGradient>
                </defs>
                <XAxis
                  dataKey="label"
                  stroke="#475569"
                  fontSize={11}
                  tickLine={false}
                  axisLine={{ stroke: '#22304A' }}
                />
                <YAxis
                  stroke="#475569"
                  fontSize={11}
                  tickLine={false}
                  axisLine={{ stroke: '#22304A' }}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#111A2C',
                    borderColor: '#22304A',
                    borderRadius: '8px',
                    fontSize: '11px',
                    color: '#F1F5F9',
                  }}
                />
                <Area
                  type="monotone"
                  dataKey="events"
                  name="Events"
                  stroke="#5B8CFF"
                  strokeWidth={2}
                  fillOpacity={1}
                  fill="url(#gradientEvents)"
                />
                <Area
                  type="monotone"
                  dataKey="threats"
                  name="Threats"
                  stroke="#FFB020"
                  strokeWidth={2}
                  fillOpacity={1}
                  fill="url(#gradientThreats)"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Threat Severity Circular / Donut Chart Card (1 col) */}
        <div className="soc-card p-5 space-y-4 flex flex-col justify-between">
          <div>
            <h2 className="text-sm font-semibold text-white tracking-tight">
              Threat Severity
            </h2>
            <p className="text-xs text-slate-400">
              Severity distribution across all correlated alerts
            </p>
          </div>

          <div className="relative h-48 w-full flex items-center justify-center">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={severityDonutData}
                  cx="50%"
                  cy="50%"
                  innerRadius={55}
                  outerRadius={75}
                  paddingAngle={3}
                  dataKey="value"
                >
                  {severityDonutData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} stroke="#111A2C" strokeWidth={2} />
                  ))}
                </Pie>
              </PieChart>
            </ResponsiveContainer>

            {/* Total in Center */}
            <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
              <span className="text-2xl font-bold font-mono text-white">
                {alerts.length}
              </span>
              <span className="text-[10px] uppercase tracking-wider text-slate-400">
                Total Alerts
              </span>
            </div>
          </div>

          {/* Legend Items */}
          <div className="grid grid-cols-2 gap-2 pt-2 border-t border-[#22304A] text-xs">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-[#FF5C6C]" />
                <span className="text-slate-300">Critical</span>
              </div>
              <span className="font-mono font-semibold text-white">{critCount}</span>
            </div>

            <div className="flex items-center justify-between">
              <div className="flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-[#FFB020]" />
                <span className="text-slate-300">High</span>
              </div>
              <span className="font-mono font-semibold text-white">{highCount}</span>
            </div>

            <div className="flex items-center justify-between">
              <div className="flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-[#5B8CFF]" />
                <span className="text-slate-300">Medium</span>
              </div>
              <span className="font-mono font-semibold text-white">{medCount}</span>
            </div>

            <div className="flex items-center justify-between">
              <div className="flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-[#20C997]" />
                <span className="text-slate-300">Low</span>
              </div>
              <span className="font-mono font-semibold text-white">{lowCount}</span>
            </div>
          </div>
        </div>
      </div>

      {/* ==================================================
          SECTION 6 & 8: TOP RISK USERS & ACTIVE THREATS
          ================================================== */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Top Risk Users Panel */}
        <div className="soc-card p-5 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-sm font-semibold text-white tracking-tight">
                Top Risk Users
              </h2>
              <p className="text-xs text-slate-400">
                Personnel exhibiting highest behavioral risk deviation
              </p>
            </div>
            <button
              onClick={() => setActiveTab('risk')}
              className="text-xs text-[#5B8CFF] hover:underline cursor-pointer"
            >
              All Users &rarr;
            </button>
          </div>

          <div className="space-y-3">
            {topRiskUsers.map((u) => {
              const scoreColor =
                u.score >= 75
                  ? 'bg-[#FF5C6C]'
                  : u.score >= 50
                  ? 'bg-[#FFB020]'
                  : u.score >= 25
                  ? 'bg-[#5B8CFF]'
                  : 'bg-[#20C997]';

              return (
                <div
                  key={u.id}
                  onClick={() => {
                    if (u.userObj) setSelectedUser(u.userObj);
                    setActiveTab('risk');
                  }}
                  className="p-3 bg-[#0D1424] border border-[#22304A] hover:border-[#314366] rounded-lg flex items-center justify-between gap-4 transition-colors cursor-pointer"
                >
                  <div className="flex items-center gap-3 min-w-0">
                    <div className="w-9 h-9 rounded-full bg-[#5B8CFF]/15 border border-[#5B8CFF]/30 text-[#5B8CFF] flex items-center justify-center font-bold text-xs shrink-0">
                      {u.name.charAt(0)}
                    </div>
                    <div className="min-w-0">
                      <div className="text-xs font-semibold text-white truncate">
                        {u.name}
                      </div>
                      <div className="text-[11px] text-slate-400 flex items-center gap-2">
                        <span>{u.employeeId}</span>
                        <span>·</span>
                        <span>{u.department}</span>
                      </div>
                    </div>
                  </div>

                  <div className="w-36 text-right shrink-0">
                    <div className="flex items-center justify-end gap-1.5 text-xs font-mono font-bold">
                      <span className="text-slate-400 text-[10px]">Risk</span>
                      <span className="text-white">{u.score}</span>
                      <span className="text-slate-500 text-[10px]">/ 100</span>
                    </div>
                    <div className="w-full bg-[#111A2C] rounded-full h-1.5 mt-1 overflow-hidden border border-[#22304A]">
                      <div
                        className={`h-full rounded-full ${scoreColor}`}
                        style={{ width: `${Math.min(u.score, 100)}%` }}
                      />
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Active Threats Panel */}
        <div className="soc-card p-5 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-sm font-semibold text-white tracking-tight">
                Active Threats
              </h2>
              <p className="text-xs text-slate-400">
                Unresolved security incident detections
              </p>
            </div>
            <button
              onClick={() => setActiveTab('alerts')}
              className="text-xs text-[#5B8CFF] hover:underline cursor-pointer"
            >
              Alert Center &rarr;
            </button>
          </div>

          <div className="space-y-2.5">
            {activeThreatsList.length === 0 ? (
              <div className="p-8 text-center text-xs text-slate-400 bg-[#0D1424] rounded-lg border border-[#22304A]">
                No active threats detected. All systems nominal.
              </div>
            ) : (
              activeThreatsList.slice(0, 5).map((threat) => {
                const statusBadge =
                  threat.status === 'OPEN'
                    ? 'bg-[#FF5C6C]/10 text-[#FF5C6C] border-[#FF5C6C]/30'
                    : 'bg-[#FFB020]/10 text-[#FFB020] border-[#FFB020]/30';

                return (
                  <div
                    key={threat.id}
                    onClick={() => {
                      setSelectedAlert(threat);
                      setActiveTab('alerts');
                    }}
                    className="p-3 bg-[#0D1424] border border-[#22304A] hover:border-[#314366] rounded-lg flex items-center justify-between gap-3 transition-colors cursor-pointer"
                  >
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-semibold text-white truncate">
                          {threat.title}
                        </span>
                        <span className={`text-[10px] px-2 py-0.5 rounded-full border font-medium ${statusBadge}`}>
                          {threat.status === 'OPEN' ? 'Open' : 'Investigating'}
                        </span>
                      </div>
                      <div className="text-[11px] text-slate-400 mt-0.5 truncate">
                        Employee: <span className="text-slate-300">@{threat.username}</span> · Detected: {new Date(threat.lastSeen).toLocaleTimeString()}
                      </div>
                    </div>

                    <div className="text-right shrink-0">
                      <span className="text-xs font-mono font-bold text-[#FF5C6C]">
                        {threat.riskScore} Risk
                      </span>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>
      </div>

      {/* ==================================================
          SECTION 7: RECENT SECURITY EVENTS TABLE
          Columns: Time, Employee, Event, Rule, Severity, Risk, Status
          ================================================== */}
      <div className="soc-card overflow-hidden">
        <div className="p-4 border-b border-[#22304A] flex items-center justify-between">
          <div>
            <h2 className="text-sm font-semibold text-white tracking-tight">
              Recent Security Events
            </h2>
            <p className="text-xs text-slate-400">
              Real-time audit telemetry and rule triggering feed
            </p>
          </div>
          <button
            onClick={() => setActiveTab('events')}
            className="text-xs text-[#5B8CFF] hover:underline cursor-pointer"
          >
            View Event Explorer &rarr;
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-[#22304A] bg-[#0D1424] text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                <th className="py-3 px-4">Time</th>
                <th className="py-3 px-4">Employee</th>
                <th className="py-3 px-4">Event</th>
                <th className="py-3 px-4">Rule</th>
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">Risk</th>
                <th className="py-3 px-4 text-right">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#22304A]">
              {recentEvents.map((ev) => {
                const userObj = users.find((u) => u.id === ev.userId);
                const empDisplay = userObj ? userObj.fullName : `@${ev.username || 'unknown'}`;
                const sev = ev.normalizedData?.severity || 'LOW';
                const ruleCode = ev.normalizedData?.ruleId || (ev.eventType === 'FAILED_LOGIN' ? 'RULE-001' : ev.eventType === 'UNAUTHORIZED_ACCESS' ? 'RULE-002' : ev.eventType === 'SENSITIVE_FILE_ACCESS' ? 'RULE-005' : 'NORMAL');
                const userRisk = riskScores.find((r) => r.userId === ev.userId)?.finalScore || (sev === 'CRITICAL' ? 85 : sev === 'HIGH' ? 62 : 15);

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
                    onClick={() => setSelectedEventModal(ev)}
                    className="hover:bg-[#0D1424] transition-colors cursor-pointer"
                  >
                    <td className="py-3 px-4 font-mono text-slate-400 text-[11px] whitespace-nowrap">
                      {new Date(ev.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="py-3 px-4 font-medium text-white whitespace-nowrap">
                      {empDisplay}
                    </td>
                    <td className="py-3 px-4 text-slate-300 max-w-xs truncate">
                      {ev.normalizedData?.action || ev.eventType}
                    </td>
                    <td className="py-3 px-4 font-mono text-[11px] text-slate-400">
                      {ruleCode}
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
                      <span className="text-[10px] text-slate-400 font-mono">
                        {ev.processed ? 'Processed' : 'Ingested'}
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Selected Event Details Modal (Triggered by clicking event) */}
      {selectedEventModal && (
        <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
          <div className="bg-[#111A2C] border border-[#22304A] rounded-xl max-w-xl w-full p-5 space-y-4 shadow-2xl animate-in zoom-in-95 duration-150">
            <div className="flex items-center justify-between border-b border-[#22304A] pb-3">
              <h3 className="text-sm font-semibold text-white">
                Security Event Telemetry Details
              </h3>
              <button
                onClick={() => setSelectedEventModal(null)}
                className="text-slate-400 hover:text-white text-xs cursor-pointer"
              >
                ✕ Close
              </button>
            </div>

            <div className="grid grid-cols-2 gap-3 text-xs bg-[#0D1424] p-3 rounded-lg border border-[#22304A]">
              <div>
                <span className="text-slate-400 block text-[10px]">EVENT ID</span>
                <span className="font-mono text-white">#{selectedEventModal.id}</span>
              </div>
              <div>
                <span className="text-slate-400 block text-[10px]">TIMESTAMP</span>
                <span className="text-slate-300">{selectedEventModal.timestamp}</span>
              </div>
              <div>
                <span className="text-slate-400 block text-[10px]">EMPLOYEE / ACTOR</span>
                <span className="text-[#5B8CFF] font-medium">@{selectedEventModal.username}</span>
              </div>
              <div>
                <span className="text-slate-400 block text-[10px]">IP ORIGIN</span>
                <span className="font-mono text-slate-300">{selectedEventModal.ipAddress || '10.14.88.102'}</span>
              </div>
              <div className="col-span-2">
                <span className="text-slate-400 block text-[10px]">ACTION & TARGET</span>
                <span className="text-white font-medium">{selectedEventModal.action} &rarr; {selectedEventModal.resource || 'N/A'}</span>
              </div>
            </div>

            <div>
              <span className="text-[10px] text-slate-400 uppercase tracking-wider block mb-1">
                Normalized Telemetry JSON
              </span>
              <pre className="text-xs bg-[#080D18] p-3 rounded-lg border border-[#22304A] overflow-x-auto text-[#5B8CFF] max-h-48 font-mono">
                {JSON.stringify(selectedEventModal, null, 2)}
              </pre>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
