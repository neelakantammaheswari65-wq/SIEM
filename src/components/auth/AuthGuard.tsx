import React from 'react';
import { useAuth } from '../../context/AuthContext';
import { Shield, ShieldAlert, Lock } from 'lucide-react';

interface AuthGuardProps {
  children: React.ReactNode;
  fallback?: React.ReactNode;
}

export const AuthGuard: React.FC<AuthGuardProps> = ({ children, fallback }) => {
  const { isAuthenticated, loading } = useAuth();

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-950 flex flex-col items-center justify-center p-6 text-slate-200">
        <div className="bg-slate-900/90 border border-slate-800 p-8 rounded-[32px] shadow-2xl backdrop-blur-xl flex flex-col items-center max-w-sm text-center space-y-4">
          <div className="w-14 h-14 rounded-2xl bg-cyan-950/60 border border-cyan-500/40 text-cyan-400 flex items-center justify-center shadow-lg shadow-cyan-950/50 animate-pulse">
            <Shield className="w-7 h-7" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
              Verifying Security Session
            </h3>
            <p className="text-xs text-slate-400 mt-1 font-medium">
              Validating cryptographic token and identity credentials...
            </p>
          </div>
          <div className="w-40 h-1 bg-slate-800 rounded-full overflow-hidden">
            <div className="w-full h-full bg-cyan-400 animate-[shimmer_1.5s_infinite]" />
          </div>
        </div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return fallback ? <>{fallback}</> : null;
  }

  return <>{children}</>;
};
