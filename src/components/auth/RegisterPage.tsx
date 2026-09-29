import React, { useState } from 'react';
import { useAuth } from '../../context/AuthContext';
import { UserRole } from '../../types/siem';
import {
  ShieldAlert,
  UserPlus,
  User,
  Mail,
  Lock,
  Building,
  ShieldCheck,
  AlertCircle,
  Eye,
  EyeOff,
  ArrowRight,
} from 'lucide-react';

interface RegisterPageProps {
  onNavigateToLogin: () => void;
  onSuccess?: () => void;
}

export const RegisterPage: React.FC<RegisterPageProps> = ({ onNavigateToLogin, onSuccess }) => {
  const { register } = useAuth();
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [fullName, setFullName] = useState('');
  const [department, setDepartment] = useState('Cyber Operations');
  const [role, setRole] = useState<UserRole>('SECURITY_ANALYST');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (!username.trim()) {
      setError('Please provide a valid username.');
      return;
    }
    if (!email.trim() || !email.includes('@')) {
      setError('Please provide a valid email address.');
      return;
    }
    if (password.length < 6) {
      setError('Password must be at least 6 characters long.');
      return;
    }
    if (password !== confirmPassword) {
      setError('Passwords do not match. Please verify your input.');
      return;
    }

    setIsSubmitting(true);
    try {
      const res = await register({
        username: username.trim(),
        email: email.trim(),
        fullName: fullName.trim(),
        department,
        role,
        password,
      });

      if (res && res.success) {
        if (onSuccess) onSuccess();
      } else {
        setError(res?.error || 'Account enrollment failed. User may already exist.');
      }
    } catch (err: any) {
      setError(err?.message || 'Enrollment service currently unavailable.');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#080D18] flex items-center justify-center p-6 relative overflow-hidden text-slate-100">
      {/* Background Subtle Grid */}
      <div
        className="absolute inset-0 pointer-events-none opacity-20"
        style={{
          backgroundImage:
            'radial-gradient(circle at 1px 1px, #22304A 1px, transparent 0)',
          backgroundSize: '32px 32px',
        }}
      />

      <div className="w-full max-w-lg space-y-6 relative z-10">
        {/* Brand Header */}
        <div className="text-center space-y-2">
          <div className="inline-flex items-center justify-center w-12 h-12 rounded-xl bg-[#5B8CFF]/15 border border-[#5B8CFF]/30 text-[#5B8CFF] mb-1">
            <UserPlus className="w-6 h-6" />
          </div>

          <div>
            <div className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-[#0D1424] border border-[#22304A] text-[10px] font-mono font-bold text-[#5B8CFF] tracking-wider uppercase mb-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-[#20C997]"></span>
              SOC ANALYST ONBOARDING
            </div>
            <h1 className="text-xl font-bold tracking-tight text-white">Create SOC Account</h1>
            <p className="text-xs text-slate-400 mt-1">
              Enroll analyst identity into SIEM Insider Threat Detection Platform
            </p>
          </div>
        </div>

        {/* Register Form Card */}
        <div className="bg-[#111A2C] border border-[#22304A] p-6 sm:p-8 rounded-xl shadow-xl space-y-5">
          {error && (
            <div
              id="register-error-banner"
              className="p-3 rounded-lg bg-[#FF5C6C]/10 border border-[#FF5C6C]/30 text-[#FF5C6C] text-xs flex items-start gap-2.5"
            >
              <AlertCircle className="w-4 h-4 shrink-0 text-[#FF5C6C] mt-0.5" />
              <div className="font-medium">{error}</div>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="space-y-1">
                <label className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
                  <User className="w-3.5 h-3.5 text-[#5B8CFF]" />
                  Username
                </label>
                <input
                  type="text"
                  id="register-input-username"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="e.g. jdoe"
                  required
                  className="w-full bg-[#0D1424] border border-[#22304A] rounded-lg px-3.5 py-2 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-[#5B8CFF] font-mono"
                />
              </div>

              <div className="space-y-1">
                <label className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
                  <Mail className="w-3.5 h-3.5 text-[#5B8CFF]" />
                  Corporate Email
                </label>
                <input
                  type="email"
                  id="register-input-email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="jdoe@enterprise.com"
                  required
                  className="w-full bg-[#0D1424] border border-[#22304A] rounded-lg px-3.5 py-2 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-[#5B8CFF] font-mono"
                />
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="space-y-1">
                <label className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
                  <User className="w-3.5 h-3.5 text-[#5B8CFF]" />
                  Full Name
                </label>
                <input
                  type="text"
                  id="register-input-fullname"
                  value={fullName}
                  onChange={(e) => setFullName(e.target.value)}
                  placeholder="John Doe"
                  required
                  className="w-full bg-[#0D1424] border border-[#22304A] rounded-lg px-3.5 py-2 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-[#5B8CFF]"
                />
              </div>

              <div className="space-y-1">
                <label className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
                  <Building className="w-3.5 h-3.5 text-[#5B8CFF]" />
                  Department
                </label>
                <input
                  type="text"
                  id="register-input-department"
                  value={department}
                  onChange={(e) => setDepartment(e.target.value)}
                  placeholder="e.g. Incident Response"
                  required
                  className="w-full bg-[#0D1424] border border-[#22304A] rounded-lg px-3.5 py-2 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-[#5B8CFF]"
                />
              </div>
            </div>

            <div className="space-y-1">
              <label className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
                <ShieldCheck className="w-3.5 h-3.5 text-[#5B8CFF]" />
                Assigned RBAC Role
              </label>
              <select
                id="register-select-role"
                value={role}
                onChange={(e) => setRole(e.target.value as UserRole)}
                className="w-full bg-[#0D1424] border border-[#22304A] rounded-lg px-3.5 py-2 text-xs text-slate-100 focus:outline-none focus:border-[#5B8CFF] font-mono cursor-pointer"
              >
                <option value="SECURITY_ANALYST">SECURITY_ANALYST (Triage alerts, correlate threats, inspect logs)</option>
                <option value="ADMIN">ADMIN (Full policy management, rule editing, USB override authority)</option>
                <option value="VIEWER">VIEWER (Read-only forensic telemetry auditing)</option>
              </select>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="space-y-1">
                <label className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
                  <Lock className="w-3.5 h-3.5 text-[#5B8CFF]" />
                  Password
                </label>
                <div className="relative">
                  <input
                    type={showPassword ? 'text' : 'password'}
                    id="register-input-password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="Min 6 characters"
                    required
                    className="w-full bg-[#0D1424] border border-[#22304A] rounded-lg pl-3.5 pr-9 py-2 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-[#5B8CFF] font-mono"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-200 cursor-pointer"
                  >
                    {showPassword ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                  </button>
                </div>
              </div>

              <div className="space-y-1">
                <label className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
                  <Lock className="w-3.5 h-3.5 text-[#5B8CFF]" />
                  Confirm Password
                </label>
                <input
                  type={showPassword ? 'text' : 'password'}
                  id="register-input-confirm-password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  placeholder="Repeat password"
                  required
                  className="w-full bg-[#0D1424] border border-[#22304A] rounded-lg px-3.5 py-2 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-[#5B8CFF] font-mono"
                />
              </div>
            </div>

            <button
              type="submit"
              id="btn-submit-register"
              disabled={isSubmitting}
              className="w-full mt-2 py-2.5 px-4 rounded-lg bg-[#5B8CFF] hover:bg-[#4a7cee] active:scale-[0.99] text-white text-xs font-bold transition-all flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50"
            >
              {isSubmitting ? (
                <>
                  <div className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  <span>Enrolling Account...</span>
                </>
              ) : (
                <>
                  <UserPlus className="w-3.5 h-3.5" />
                  <span>Complete Enrollment & Sign In</span>
                </>
              )}
            </button>
          </form>

          {/* Navigation to Login */}
          <div className="pt-2 text-center text-xs text-slate-400 border-t border-[#22304A]">
            <span>Already have an authorized account? </span>
            <button
              type="button"
              id="link-go-to-login"
              onClick={onNavigateToLogin}
              className="text-[#5B8CFF] hover:underline font-semibold cursor-pointer transition-colors"
            >
              Sign In to Console
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
