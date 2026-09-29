import React, { useState } from 'react';
import { useAuth } from '../../context/AuthContext';
import {
  Shield,
  Lock,
  User,
  Eye,
  EyeOff,
  AlertCircle,
  Activity,
  Terminal,
  CheckCircle2,
  Network,
  Cpu,
  ArrowRight,
} from 'lucide-react';

interface LoginPageProps {
  onNavigateToRegister: () => void;
  onSuccess?: () => void;
}

export const LoginPage: React.FC<LoginPageProps> = ({ onNavigateToRegister, onSuccess }) => {
  const { login } = useAuth();
  const [identifier, setIdentifier] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (!identifier.trim()) {
      setError('Please enter your Username or Corporate Email.');
      return;
    }
    if (!password) {
      setError('Please enter your Password.');
      return;
    }

    setIsSubmitting(true);
    try {
      const res = await login(identifier, password);
      if (!res.success) {
        setError(res.error || 'Authentication failed. Please check credentials.');
      } else {
        if (onSuccess) onSuccess();
      }
    } catch (err: any) {
      setError(err.message || 'Authentication error occurred.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleQuickLogin = (demoUsername: string) => {
    setIdentifier(demoUsername);
    setPassword('password123');
    setError(null);
  };

  return (
    <div className="min-h-screen bg-[#080D18] text-slate-100 flex flex-col lg:flex-row font-sans selection:bg-[#5B8CFF] selection:text-white">
      {/* ==================================================
          LEFT SIDE: Security-themed Illustration / Abstract Visualization
          ================================================== */}
      <div className="lg:w-7/12 relative bg-[#0D1424] border-b lg:border-b-0 lg:border-r border-[#22304A] p-8 lg:p-14 flex flex-col justify-between overflow-hidden">
        {/* Subtle grid pattern */}
        <div className="absolute inset-0 bg-[linear-gradient(to_right,#22304a25_1px,transparent_1px),linear-gradient(to_bottom,#22304a25_1px,transparent_1px)] bg-[size:36px_36px] pointer-events-none" />

        {/* Top: Brand Header */}
        <div className="relative z-10">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-[#111A2C] border border-[#22304A] flex items-center justify-center text-[#5B8CFF] shadow-sm">
              <Shield className="w-5 h-5 text-[#5B8CFF]" />
            </div>
            <div>
              <div className="text-xs font-bold tracking-wider text-white uppercase">
                SIEM INSIDER THREAT PLATFORM
              </div>
              <div className="text-[11px] text-[#5B8CFF] font-medium">
                Security Operations & Incident Intelligence
              </div>
            </div>
          </div>
        </div>

        {/* Center: Abstract Network Security Visualization */}
        <div className="relative z-10 my-8 lg:my-0 space-y-6">
          <div className="space-y-3 max-w-xl">
            <h1 className="text-3xl lg:text-4xl font-bold tracking-tight text-white leading-tight">
              Continuous Behavioral Monitoring & Insider Risk Analytics
            </h1>
            <p className="text-sm text-slate-300 leading-relaxed">
              Real-time telemetry ingestion, temporal rule evaluation, deterministic time-decayed risk scoring, and automated DLP enforcement.
            </p>
          </div>

          {/* Interactive Topology Nodes Card */}
          <div className="bg-[#111A2C] border border-[#22304A] rounded-xl p-5 shadow-lg space-y-4 max-w-lg">
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span className="font-semibold uppercase tracking-wider">Topology Monitoring</span>
              <span className="text-[#20C997] flex items-center gap-1.5 font-medium">
                <span className="w-1.5 h-1.5 rounded-full bg-[#20C997] animate-pulse" />
                All Engines Online
              </span>
            </div>

            <div className="grid grid-cols-3 gap-3 text-center">
              <div className="p-3 bg-[#0D1424] rounded-lg border border-[#22304A]">
                <Cpu className="w-4 h-4 text-[#5B8CFF] mx-auto mb-1.5" />
                <div className="text-[11px] text-slate-400">Rule Engine</div>
                <div className="text-xs font-bold text-white mt-0.5">7 Rules Active</div>
              </div>
              <div className="p-3 bg-[#0D1424] rounded-lg border border-[#22304A]">
                <Network className="w-4 h-4 text-[#8B7CFF] mx-auto mb-1.5" />
                <div className="text-[11px] text-slate-400">Pipeline</div>
                <div className="text-xs font-bold text-white mt-0.5">Continuous</div>
              </div>
              <div className="p-3 bg-[#0D1424] rounded-lg border border-[#22304A]">
                <Activity className="w-4 h-4 text-[#20C997] mx-auto mb-1.5" />
                <div className="text-[11px] text-slate-400">Isolation Forest</div>
                <div className="text-xs font-bold text-white mt-0.5">99.8% Precision</div>
              </div>
            </div>

            <div className="p-3 bg-[#080D18] rounded-lg border border-[#22304A] font-mono text-[11px] text-slate-400 flex items-center justify-between">
              <span>DEMO DATASET: <strong className="text-white">1,000 Employees</strong></span>
              <span className="text-[#5B8CFF]">Zero-Trust Enforced</span>
            </div>
          </div>
        </div>

        {/* Bottom Banner */}
        <div className="relative z-10 flex items-center justify-between text-xs text-slate-400 pt-4 border-t border-[#22304A]">
          <span>Security Operations Console</span>
          <span>Compliance: SOC2 / ISO 27001</span>
        </div>
      </div>

      {/* ==================================================
          RIGHT SIDE: Clean Authentication Card
          ================================================== */}
      <div className="lg:w-5/12 flex items-center justify-center p-6 sm:p-10 lg:p-14">
        <div className="w-full max-w-md space-y-6">
          {/* Card Header: Title & Subtitle */}
          <div className="space-y-1">
            <h2 className="text-2xl font-bold tracking-tight text-white">
              SIEM INSIDER THREAT PLATFORM
            </h2>
            <p className="text-xs text-slate-400">
              Security Operations & Insider Risk Monitoring
            </p>
          </div>

          {/* Error Banner */}
          {error && (
            <div className="p-3 rounded-lg bg-[#FF5C6C]/10 border border-[#FF5C6C]/30 text-[#FF5C6C] text-xs flex items-center gap-2">
              <AlertCircle className="w-4 h-4 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {/* Form */}
          <form onSubmit={handleSubmit} className="space-y-4 text-xs">
            <div>
              <label className="text-slate-300 font-medium block mb-1.5">
                Username / Corporate Email
              </label>
              <div className="relative">
                <User className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  placeholder="admin or amercer@company.com"
                  value={identifier}
                  onChange={(e) => setIdentifier(e.target.value)}
                  className="w-full bg-[#111A2C] border border-[#22304A] rounded-lg pl-9 pr-3 py-2 text-slate-200 placeholder-slate-500 focus:outline-none focus:border-[#5B8CFF] transition-colors"
                  required
                />
              </div>
            </div>

            <div>
              <label className="text-slate-300 font-medium block mb-1.5">
                Password
              </label>
              <div className="relative">
                <Lock className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
                <input
                  type={showPassword ? 'text' : 'password'}
                  placeholder="Enter password..."
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full bg-[#111A2C] border border-[#22304A] rounded-lg pl-9 pr-10 py-2 text-slate-200 placeholder-slate-500 focus:outline-none focus:border-[#5B8CFF] transition-colors"
                  required
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-white"
                >
                  {showPassword ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                </button>
              </div>
            </div>

            <button
              type="submit"
              disabled={isSubmitting}
              className="w-full py-2.5 rounded-lg bg-[#5B8CFF] hover:bg-[#4a7cee] text-white font-semibold text-xs transition-colors flex items-center justify-center gap-2 cursor-pointer shadow-md disabled:opacity-50"
            >
              <span>{isSubmitting ? 'Authenticating...' : 'Sign In'}</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </form>

          {/* Demo Login Options */}
          <div className="pt-4 border-t border-[#22304A] space-y-3">
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span className="font-semibold uppercase tracking-wider text-[11px]">
                Demo Login
              </span>
              <span className="text-[11px]">Click to auto-fill</span>
            </div>

            <div className="space-y-2">
              <button
                type="button"
                onClick={() => handleQuickLogin('admin')}
                className="w-full p-2.5 bg-[#111A2C] hover:bg-[#1E2B42] border border-[#22304A] rounded-lg text-left transition-colors flex items-center justify-between cursor-pointer"
              >
                <div>
                  <div className="text-xs font-semibold text-white">Administrator (Full SOC Access)</div>
                  <div className="text-[11px] text-slate-400 font-mono">admin · password123</div>
                </div>
                <span className="text-[10px] px-2 py-0.5 rounded-full bg-[#5B8CFF]/15 text-[#5B8CFF] font-medium border border-[#5B8CFF]/30">
                  Admin
                </span>
              </button>

              <button
                type="button"
                onClick={() => handleQuickLogin('dkim')}
                className="w-full p-2.5 bg-[#111A2C] hover:bg-[#1E2B42] border border-[#22304A] rounded-lg text-left transition-colors flex items-center justify-between cursor-pointer"
              >
                <div>
                  <div className="text-xs font-semibold text-white">Security Analyst (David Kim)</div>
                  <div className="text-[11px] text-slate-400 font-mono">dkim · password123</div>
                </div>
                <span className="text-[10px] px-2 py-0.5 rounded-full bg-[#8B7CFF]/15 text-[#8B7CFF] font-medium border border-[#8B7CFF]/30">
                  Analyst
                </span>
              </button>

              <button
                type="button"
                onClick={() => handleQuickLogin('amercer')}
                className="w-full p-2.5 bg-[#111A2C] hover:bg-[#1E2B42] border border-[#22304A] rounded-lg text-left transition-colors flex items-center justify-between cursor-pointer"
              >
                <div>
                  <div className="text-xs font-semibold text-white">Employee (Alex Mercer - R&D)</div>
                  <div className="text-[11px] text-slate-400 font-mono">amercer · password123</div>
                </div>
                <span className="text-[10px] px-2 py-0.5 rounded-full bg-[#20C997]/15 text-[#20C997] font-medium border border-[#20C997]/30">
                  Employee
                </span>
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
