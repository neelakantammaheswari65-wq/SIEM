import React from 'react';
import { useSIEM, ActiveTab } from '../../context/SIEMContext';
import {
  LayoutDashboard,
  ShieldAlert,
  Terminal,
  Activity,
  Users,
  Scale,
  PlayCircle,
  FileCheck2,
  FileText,
  Settings,
  FolderLock,
  Clock,
  Shield,
} from 'lucide-react';

interface NavItem {
  id: ActiveTab;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  badge?: number | string;
  badgeType?: 'danger' | 'warning' | 'neutral' | 'accent' | 'success';
  adminOnly?: boolean;
}

export const Sidebar: React.FC = () => {
  const { activeTab, setActiveTab, summary, currentUser, files, users } = useSIEM();

  const isEmployee = currentUser.role === 'VIEWER' || currentUser.role === 'EMPLOYEE';
  const isAdmin = currentUser.role === 'ADMIN';

  // Employee Navigation
  const employeeNavItems: NavItem[] = [
    {
      id: 'dashboard',
      label: 'Overview',
      icon: LayoutDashboard,
    },
    {
      id: 'files',
      label: 'Corporate Files',
      icon: FolderLock,
      badge: `${files.length}`,
      badgeType: 'neutral',
    },
    {
      id: 'my_activity',
      label: 'My Activity',
      icon: Clock,
    },
  ];

  // SOC Analyst / Admin Navigation (The 10 specified sections)
  const socNavItems: NavItem[] = [
    {
      id: 'dashboard',
      label: 'Overview',
      icon: LayoutDashboard,
    },
    {
      id: 'events',
      label: 'Security Events',
      icon: Terminal,
      badge: summary.totalEvents > 9999 ? '12.5k+' : summary.totalEvents,
      badgeType: 'neutral',
    },
    {
      id: 'risk',
      label: 'Threat Detection',
      icon: Activity,
      badge: summary.highRiskUsers > 0 ? `${summary.highRiskUsers}` : undefined,
      badgeType: 'warning',
    },
    {
      id: 'alerts',
      label: 'Alerts',
      icon: ShieldAlert,
      badge: summary.openAlerts > 0 ? summary.openAlerts : undefined,
      badgeType: 'danger',
    },
    {
      id: 'employees',
      label: 'Employees',
      icon: Users,
      badge: users.length > 0 ? `${users.length}` : undefined,
      badgeType: 'neutral',
    },
    {
      id: 'rules',
      label: 'Detection Rules',
      icon: Scale,
      badge: '7 Rules',
      badgeType: 'accent',
    },
    {
      id: 'scenarios',
      label: 'Threat Simulation',
      icon: PlayCircle,
    },
    {
      id: 'audit',
      label: 'Audit Logs',
      icon: FileCheck2,
      adminOnly: true,
    },
    {
      id: 'reports',
      label: 'Reports',
      icon: FileText,
    },
    {
      id: 'settings',
      label: 'Settings',
      icon: Settings,
      adminOnly: true,
    },
  ];

  const currentNavItems = isEmployee
    ? employeeNavItems
    : socNavItems.filter((item) => {
        if (item.adminOnly && !isAdmin) return false;
        return true;
      });

  return (
    <aside className="w-64 bg-[#0D1424] border-r border-[#22304A] flex flex-col shrink-0 select-none text-slate-300">
      {/* Top of Sidebar: SIEM INSIDER THREAT with simple professional shield icon */}
      <div className="h-16 px-5 border-b border-[#22304A] flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-[#111A2C] border border-[#22304A] flex items-center justify-center text-[#5B8CFF] shadow-sm">
            <Shield className="w-4 h-4 text-[#5B8CFF]" />
          </div>
          <div className="leading-tight">
            <div className="text-xs font-bold tracking-wider text-white uppercase">
              SIEM
            </div>
            <div className="text-[10px] font-medium text-slate-400 tracking-tight">
              INSIDER THREAT
            </div>
          </div>
        </div>

        <div className="flex items-center gap-1.5 font-mono text-[10px] text-slate-400 bg-[#111A2C] px-2 py-0.5 rounded border border-[#22304A]">
          <span className="w-1.5 h-1.5 rounded-full bg-[#20C997] animate-pulse"></span>
          <span>v2.8</span>
        </div>
      </div>

      {/* Navigation Links */}
      <div className="px-4 pt-4 pb-2 text-[10px] font-semibold uppercase tracking-wider text-slate-400">
        {isEmployee ? 'Employee Portal' : 'Navigation'}
      </div>

      <nav className="flex-1 px-3 space-y-1 overflow-y-auto">
        {currentNavItems.map((item) => {
          const isActive =
            activeTab === item.id ||
            (item.id === 'employees' && activeTab === 'users') ||
            (item.id === 'reports' && activeTab === 'findings') ||
            (item.id === 'settings' && activeTab === 'usb');
          const Icon = item.icon;

          return (
            <button
              key={item.id}
              id={`nav-item-${item.id}`}
              onClick={() => setActiveTab(item.id)}
              className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-xs font-medium transition-all cursor-pointer group ${
                isActive
                  ? 'bg-[#111A2C] text-white border-l-2 border-[#5B8CFF] font-semibold shadow-sm'
                  : 'text-slate-400 hover:text-slate-100 hover:bg-[#111A2C]/60'
              }`}
            >
              <div className="flex items-center gap-2.5 min-w-0">
                <Icon
                  className={`w-4 h-4 shrink-0 transition-colors ${
                    isActive ? 'text-[#5B8CFF]' : 'text-slate-400 group-hover:text-slate-200'
                  }`}
                />
                <span className="truncate">{item.label}</span>
              </div>

              {item.badge !== undefined && (
                <span
                  className={`text-[10px] font-mono px-2 py-0.5 rounded-md font-medium border ${
                    item.badgeType === 'danger'
                      ? 'bg-[#FF5C6C]/10 text-[#FF5C6C] border-[#FF5C6C]/30'
                      : item.badgeType === 'warning'
                      ? 'bg-[#FFB020]/10 text-[#FFB020] border-[#FFB020]/30'
                      : item.badgeType === 'accent'
                      ? 'bg-[#5B8CFF]/10 text-[#5B8CFF] border-[#5B8CFF]/30'
                      : item.badgeType === 'success'
                      ? 'bg-[#20C997]/10 text-[#20C997] border-[#20C997]/30'
                      : 'bg-[#111A2C] text-slate-400 border-[#22304A]'
                  }`}
                >
                  {item.badge}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      {/* Bottom of Sidebar: System Status (Explicit User Requirement) */}
      <div className="p-3.5 border-t border-[#22304A] bg-[#080D18]">
        <div className="text-[10px] font-semibold uppercase tracking-wider text-slate-400 mb-2 px-1">
          System Status
        </div>
        <div className="space-y-2 text-xs bg-[#0D1424] border border-[#22304A] rounded-lg p-2.5">
          <div className="flex items-center justify-between text-slate-300">
            <span className="flex items-center gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-[#20C997]"></span>
              <span>SIEM Engine</span>
            </span>
            <span className="text-[11px] font-medium text-[#20C997]">Online</span>
          </div>

          <div className="flex items-center justify-between text-slate-300">
            <span className="flex items-center gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-[#20C997]"></span>
              <span>Detection Engine</span>
            </span>
            <span className="text-[11px] font-medium text-[#20C997]">Active</span>
          </div>

          <div className="flex items-center justify-between text-slate-300">
            <span className="flex items-center gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-[#20C997]"></span>
              <span>Database</span>
            </span>
            <span className="text-[11px] font-medium text-[#20C997]">Connected</span>
          </div>
        </div>
      </div>
    </aside>
  );
};
