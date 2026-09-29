import React, { useState } from 'react';
import { useSIEM } from '../../context/SIEMContext';
import { useAuth } from '../../context/AuthContext';
import {
  Shield,
  Search,
  Bell,
  Sun,
  Moon,
  LogOut,
  ChevronDown,
  User,
  Radio,
  RefreshCw,
  Database,
  CheckCircle2,
  Sparkles,
} from 'lucide-react';
import { UserRole } from '../../types/siem';

export const Navbar: React.FC = () => {
  const {
    currentUser,
    switchRole,
    summary,
    isStreaming,
    setIsStreaming,
    activeTab,
    setActiveTab,
    recalculateAllRisk,
    seedDemoData,
    alerts,
  } = useSIEM();
  const { user: authUser, logout } = useAuth();

  const [userDropdownOpen, setUserDropdownOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [isDarkTheme, setIsDarkTheme] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);

  const isEmployee = currentUser.role === 'VIEWER' || currentUser.role === 'EMPLOYEE';
  const isAdmin = currentUser.role === 'ADMIN';
  const isSOC = currentUser.role === 'ADMIN' || currentUser.role === 'SECURITY_ANALYST';

  const handleRefresh = () => {
    setIsRefreshing(true);
    recalculateAllRisk();
    setTimeout(() => setIsRefreshing(false), 500);
  };

  const handleLogout = () => {
    setIsStreaming(false);
    logout();
  };

  const activeName = authUser?.fullName || currentUser.fullName;
  const activeRole = authUser?.role || currentUser.role;
  const activeUsername = authUser?.username || currentUser.username;

  // Active module title formatting
  const getModuleTitle = () => {
    switch (activeTab) {
      case 'dashboard':
        return isEmployee ? 'Employee Overview' : 'Overview';
      case 'events':
        return 'Security Events';
      case 'risk':
        return 'Threat Detection';
      case 'alerts':
        return 'Alerts';
      case 'employees':
      case 'users':
        return 'Employees';
      case 'rules':
        return 'Detection Rules';
      case 'scenarios':
        return 'Threat Simulation';
      case 'audit':
        return 'Audit Logs';
      case 'reports':
      case 'findings':
        return 'Reports';
      case 'settings':
      case 'usb':
        return 'Settings';
      case 'files':
        return 'Corporate Files';
      case 'my_activity':
        return 'My Activity';
      default:
        return 'Overview';
    }
  };

  const unreadAlertsCount = alerts.filter((a) => a.status === 'OPEN').length;

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!searchQuery.trim()) return;
    // Default search routing to events or employees
    setActiveTab('events');
  };

  return (
    <header className="h-16 bg-[#0D1424] border-b border-[#22304A] px-6 flex items-center justify-between z-30 sticky top-0 text-slate-200">
      {/* Left: Page Title and Small Breadcrumb */}
      <div className="flex flex-col justify-center min-w-0">
        <div className="flex items-center gap-1.5 text-[11px] text-slate-400">
          <span>SIEM</span>
          <span>/</span>
          <span className="text-[#5B8CFF] font-medium">{getModuleTitle()}</span>
        </div>
        <h1 className="text-base font-semibold text-white tracking-tight leading-none mt-1">
          {getModuleTitle()}
        </h1>
      </div>

      {/* Center/Right Section */}
      <div className="flex items-center gap-3">
        {/* Global Search Bar */}
        <form onSubmit={handleSearchSubmit} className="relative hidden md:block w-72 lg:w-96">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search employees, events, alerts..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-[#111A2C] border border-[#22304A] rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-400 focus:outline-none focus:border-[#5B8CFF] transition-colors"
          />
        </form>

        {/* Live Ingestion Indicator & Event Count (SOC Only) */}
        {isSOC && (
          <div className="hidden lg:flex items-center gap-2 pl-2 border-l border-[#22304A]">
            <button
              onClick={() => setIsStreaming(!isStreaming)}
              className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-mono transition-colors cursor-pointer border ${
                isStreaming
                  ? 'bg-[#20C997]/10 border-[#20C997]/30 text-[#20C997]'
                  : 'bg-[#111A2C] border-[#22304A] text-slate-400'
              }`}
              title="Toggle Live Event Stream"
            >
              <span className={`w-1.5 h-1.5 rounded-full ${isStreaming ? 'bg-[#20C997] animate-pulse' : 'bg-slate-500'}`} />
              <span className="font-semibold text-[11px]">
                {isStreaming ? 'LIVE' : 'PAUSED'}
              </span>
            </button>

            <button
              onClick={handleRefresh}
              disabled={isRefreshing}
              className="p-1.5 rounded-lg bg-[#111A2C] border border-[#22304A] text-slate-300 hover:text-white hover:border-[#314366] transition-colors cursor-pointer"
              title="Recalculate Risk Scores"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin text-[#5B8CFF]' : ''}`} />
            </button>
          </div>
        )}

        {/* Notifications Icon with Badge */}
        <button
          onClick={() => setActiveTab('alerts')}
          className="relative p-2 rounded-lg bg-[#111A2C] border border-[#22304A] text-slate-300 hover:text-white hover:border-[#314366] transition-colors cursor-pointer"
          title="Open Alerts"
        >
          <Bell className="w-4 h-4" />
          {unreadAlertsCount > 0 && (
            <span className="absolute -top-1 -right-1 w-4 h-4 rounded-full bg-[#FF5C6C] text-[10px] font-bold text-white flex items-center justify-center leading-none">
              {unreadAlertsCount}
            </span>
          )}
        </button>

        {/* Theme Toggle Button */}
        <button
          onClick={() => setIsDarkTheme(!isDarkTheme)}
          className="p-2 rounded-lg bg-[#111A2C] border border-[#22304A] text-slate-300 hover:text-white hover:border-[#314366] transition-colors cursor-pointer"
          title="Toggle Theme"
        >
          {isDarkTheme ? <Moon className="w-4 h-4 text-[#8B7CFF]" /> : <Sun className="w-4 h-4 text-[#FFB020]" />}
        </button>

        {/* Current User Profile & Dropdown */}
        <div className="relative">
          <button
            onClick={() => setUserDropdownOpen(!userDropdownOpen)}
            className="flex items-center gap-2.5 pl-2 pr-2.5 py-1.5 rounded-lg bg-[#111A2C] border border-[#22304A] hover:border-[#314366] transition-colors cursor-pointer"
          >
            <div className="w-7 h-7 rounded-full bg-[#5B8CFF]/20 border border-[#5B8CFF]/40 text-[#5B8CFF] flex items-center justify-center font-bold text-xs">
              {activeName.charAt(0)}
            </div>
            <div className="text-left hidden sm:block">
              <div className="text-xs font-semibold text-white leading-tight">
                {activeName}
              </div>
              <div className="text-[10px] text-slate-400 font-medium leading-none">
                {activeRole}
              </div>
            </div>
            <ChevronDown className="w-3.5 h-3.5 text-slate-400" />
          </button>

          {/* User Dropdown Menu */}
          {userDropdownOpen && (
            <div className="absolute right-0 mt-2 w-64 bg-[#111A2C] border border-[#22304A] rounded-xl shadow-xl p-2 z-50 animate-in fade-in zoom-in-95 duration-150">
              <div className="px-3 py-2 border-b border-[#22304A]">
                <div className="text-xs font-semibold text-white">{activeName}</div>
                <div className="text-[11px] text-slate-400">@{activeUsername}</div>
                <div className="mt-1 inline-block text-[10px] font-semibold px-2 py-0.5 rounded bg-[#5B8CFF]/15 text-[#5B8CFF] border border-[#5B8CFF]/30">
                  Role: {activeRole}
                </div>
              </div>

              {/* Quick Role Switcher for Presentation & Demonstration */}
              <div className="py-2 border-b border-[#22304A]">
                <div className="px-3 text-[10px] font-semibold uppercase tracking-wider text-slate-400 mb-1">
                  Switch Active Role
                </div>
                <div className="space-y-0.5">
                  <button
                    onClick={() => {
                      switchRole('ADMIN');
                      setUserDropdownOpen(false);
                    }}
                    className={`w-full text-left px-3 py-1.5 rounded-md text-xs transition-colors flex items-center justify-between cursor-pointer ${
                      activeRole === 'ADMIN' ? 'bg-[#5B8CFF]/15 text-[#5B8CFF] font-semibold' : 'text-slate-300 hover:bg-[#0D1424]'
                    }`}
                  >
                    <span>Security Administrator</span>
                    {activeRole === 'ADMIN' && <CheckCircle2 className="w-3.5 h-3.5 text-[#5B8CFF]" />}
                  </button>
                  <button
                    onClick={() => {
                      switchRole('SECURITY_ANALYST');
                      setUserDropdownOpen(false);
                    }}
                    className={`w-full text-left px-3 py-1.5 rounded-md text-xs transition-colors flex items-center justify-between cursor-pointer ${
                      activeRole === 'SECURITY_ANALYST' ? 'bg-[#5B8CFF]/15 text-[#5B8CFF] font-semibold' : 'text-slate-300 hover:bg-[#0D1424]'
                    }`}
                  >
                    <span>SOC Security Analyst</span>
                    {activeRole === 'SECURITY_ANALYST' && <CheckCircle2 className="w-3.5 h-3.5 text-[#5B8CFF]" />}
                  </button>
                  <button
                    onClick={() => {
                      switchRole('EMPLOYEE');
                      setUserDropdownOpen(false);
                    }}
                    className={`w-full text-left px-3 py-1.5 rounded-md text-xs transition-colors flex items-center justify-between cursor-pointer ${
                      activeRole === 'EMPLOYEE' || activeRole === 'VIEWER' ? 'bg-[#5B8CFF]/15 text-[#5B8CFF] font-semibold' : 'text-slate-300 hover:bg-[#0D1424]'
                    }`}
                  >
                    <span>Standard Employee</span>
                    {(activeRole === 'EMPLOYEE' || activeRole === 'VIEWER') && <CheckCircle2 className="w-3.5 h-3.5 text-[#5B8CFF]" />}
                  </button>
                </div>
              </div>

              {/* Seed Demo Data Option */}
              {isAdmin && (
                <div className="py-1 border-b border-[#22304A]">
                  <button
                    onClick={() => {
                      seedDemoData();
                      setUserDropdownOpen(false);
                    }}
                    className="w-full text-left px-3 py-1.5 rounded-md text-xs text-slate-300 hover:bg-[#0D1424] hover:text-white flex items-center gap-2 cursor-pointer"
                  >
                    <Database className="w-3.5 h-3.5 text-[#20C997]" />
                    <span>Reset / Seed 1,000 Demo Dataset</span>
                  </button>
                </div>
              )}

              {/* Logout Option */}
              <div className="pt-1">
                <button
                  onClick={() => {
                    setUserDropdownOpen(false);
                    handleLogout();
                  }}
                  className="w-full text-left px-3 py-1.5 rounded-md text-xs text-[#FF5C6C] hover:bg-[#FF5C6C]/10 flex items-center gap-2 cursor-pointer"
                >
                  <LogOut className="w-3.5 h-3.5" />
                  <span>Sign Out</span>
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </header>
  );
};
