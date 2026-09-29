import React, { useState, useEffect } from 'react';
import { AuthProvider, useAuth } from './context/AuthContext';
import { SIEMProvider, useSIEM } from './context/SIEMContext';
import { Navbar } from './components/layout/Navbar';
import { Sidebar } from './components/layout/Sidebar';
import { ToastContainer } from './components/common/ToastContainer';
import { DashboardView } from './components/views/DashboardView';
import { AlertsView } from './components/views/AlertsView';
import { EventsView } from './components/views/EventsView';
import { FindingsView } from './components/views/FindingsView';
import { RiskView } from './components/views/RiskView';
import { MLView } from './components/views/MLView';
import { USBView } from './components/views/USBView';
import { RulesView } from './components/views/RulesView';
import { ScenariosView } from './components/views/ScenariosView';
import { UsersView } from './components/views/UsersView';
import { AuditLogsView } from './components/views/AuditLogsView';
import { FileRepositoryView } from './components/views/FileRepositoryView';
import { EmployeeDashboardView } from './components/views/EmployeeDashboardView';
import { MyActivityView } from './components/views/MyActivityView';
import { LoginPage } from './components/auth/LoginPage';
import { RegisterPage } from './components/auth/RegisterPage';
import { AuthGuard } from './components/auth/AuthGuard';

const MainLayout: React.FC = () => {
  const { activeTab, currentUser } = useSIEM();
  const isEmployee = currentUser.role === 'VIEWER' || currentUser.role === 'EMPLOYEE';

  return (
    <div className="min-h-screen bg-[#080D18] text-slate-100 flex flex-col font-sans selection:bg-[#5B8CFF] selection:text-white">
      <Navbar />
      <div className="flex-1 flex overflow-hidden">
        <Sidebar />
        <main className="flex-1 overflow-y-auto bg-[#080D18]">
          {/* Employee Routes */}
          {isEmployee && (
            <>
              {activeTab === 'dashboard' && <EmployeeDashboardView />}
              {activeTab === 'files' && <FileRepositoryView />}
              {activeTab === 'my_activity' && <MyActivityView />}
              {/* Guard against direct restricted tab states for employees */}
              {activeTab !== 'dashboard' && activeTab !== 'files' && activeTab !== 'my_activity' && (
                <EmployeeDashboardView />
              )}
            </>
          )}

          {/* SOC Admin & Analyst Routes */}
          {!isEmployee && (
            <>
              {activeTab === 'dashboard' && <DashboardView />}
              {activeTab === 'alerts' && <AlertsView />}
              {activeTab === 'events' && <EventsView />}
              {(activeTab === 'employees' || activeTab === 'users') && <UsersView />}
              {activeTab === 'files' && <FileRepositoryView />}
              {activeTab === 'audit' && <AuditLogsView />}
              {/* Background detection subsystems */}
              {(activeTab === 'findings' || activeTab === 'reports') && <FindingsView />}
              {activeTab === 'risk' && <RiskView />}
              {activeTab === 'ml' && <MLView />}
              {(activeTab === 'usb' || activeTab === 'settings') && <USBView />}
              {activeTab === 'rules' && <RulesView />}
              {activeTab === 'scenarios' && <ScenariosView />}
              {activeTab === 'my_activity' && <MyActivityView />}
            </>
          )}
        </main>
      </div>
      <ToastContainer />
    </div>
  );
};

const AppContent: React.FC = () => {
  const { isAuthenticated, loading, user } = useAuth();

  // Handle URL hash changes for deep linking to dashboard
  useEffect(() => {
    const handleHash = () => {
      const hash = window.location.hash.toLowerCase();
      if (hash === '#register') {
        window.location.hash = '#login';
      }
    };

    handleHash();
    window.addEventListener('hashchange', handleHash);
    return () => window.removeEventListener('hashchange', handleHash);
  }, []);

  // Update hash based on auth state
  useEffect(() => {
    if (!loading) {
      if (!isAuthenticated) {
        window.location.hash = '#login';
      } else {
        if (window.location.hash === '#login' || window.location.hash === '#register' || !window.location.hash) {
          window.location.hash = '#dashboard';
        }
      }
    }
  }, [isAuthenticated, loading]);

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-950 flex flex-col items-center justify-center p-6 text-slate-200">
        <div className="bg-slate-900/90 border border-slate-800 p-8 rounded-[32px] shadow-2xl backdrop-blur-xl flex flex-col items-center max-w-sm text-center space-y-4">
          <div className="w-14 h-14 rounded-2xl bg-cyan-950/60 border border-cyan-500/40 text-cyan-400 flex items-center justify-center shadow-lg shadow-cyan-950/50 animate-pulse">
            <div className="w-7 h-7 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
              APEX SIEM // Threat Platform
            </h3>
            <p className="text-xs text-slate-400 mt-1 font-medium">
              Initializing SOC Gateway & verifying authorization...
            </p>
          </div>
        </div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return (
      <LoginPage
        onNavigateToRegister={() => {}}
        onSuccess={() => {
          window.location.hash = '#dashboard';
        }}
      />
    );
  }

  return (
    <SIEMProvider authenticatedUser={user}>
      <AuthGuard>
        <MainLayout />
      </AuthGuard>
    </SIEMProvider>
  );
};

export default function App() {
  return (
    <AuthProvider>
      <AppContent />
    </AuthProvider>
  );
}
