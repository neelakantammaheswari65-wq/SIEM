import React from 'react';
import { useSIEM } from '../../context/SIEMContext';
import { ShieldAlert, AlertTriangle, Info, X, Zap } from 'lucide-react';

export const ToastContainer: React.FC = () => {
  const { toasts, removeToast, setActiveTab, setSelectedAlert, alerts } = useSIEM();

  if (toasts.length === 0) return null;

  return (
    <div className="fixed bottom-5 right-5 z-50 flex flex-col gap-2.5 max-w-md w-full pointer-events-none">
      {toasts.map((toast) => {
        const isCritical = toast.severity === 'CRITICAL';
        const isHigh = toast.severity === 'HIGH';
        const isMedium = toast.severity === 'MEDIUM';

        return (
          <div
            key={toast.id}
            id={`toast-${toast.id}`}
            className={`pointer-events-auto p-4 rounded-2xl shadow-2xl border flex items-start gap-3.5 backdrop-blur-md transition-all duration-300 transform translate-y-0 ${
              isCritical
                ? 'bg-red-950/90 border-red-500/60 text-red-100 shadow-red-900/30'
                : isHigh
                ? 'bg-amber-950/90 border-amber-500/60 text-amber-100 shadow-amber-900/30'
                : isMedium
                ? 'bg-blue-950/90 border-blue-500/60 text-blue-100 shadow-blue-900/30'
                : 'bg-slate-900/95 border-slate-700 text-slate-200 shadow-slate-950/50'
            }`}
          >
            <div
              className={`p-2 rounded-xl shrink-0 mt-0.5 ${
                isCritical
                  ? 'bg-red-500/20 text-red-400'
                  : isHigh
                  ? 'bg-amber-500/20 text-amber-400'
                  : isMedium
                  ? 'bg-blue-500/20 text-blue-400'
                  : 'bg-slate-800 text-slate-400'
              }`}
            >
              {isCritical ? (
                <ShieldAlert className="w-5 h-5 animate-pulse" />
              ) : isHigh ? (
                <AlertTriangle className="w-5 h-5" />
              ) : (
                <Zap className="w-5 h-5" />
              )}
            </div>

            <div className="flex-1 min-w-0">
              <div className="flex items-center justify-between gap-2">
                <h4 className="font-bold text-sm truncate">{toast.title}</h4>
                <span className="text-[10px] font-mono opacity-60 shrink-0">{toast.timestamp}</span>
              </div>
              <p className="text-xs mt-1 leading-relaxed opacity-90 break-words font-medium">{toast.message}</p>

              {(isCritical || isHigh) && (
                <button
                  id={`btn-view-alert-${toast.id}`}
                  onClick={() => {
                    setActiveTab('alerts');
                    if (alerts.length > 0) setSelectedAlert(alerts[0]);
                    removeToast(toast.id);
                  }}
                  className="mt-2 text-[11px] font-bold underline hover:text-white transition-colors cursor-pointer"
                >
                  View in Alert Center →
                </button>
              )}
            </div>

            <button
              id={`btn-close-toast-${toast.id}`}
              onClick={() => removeToast(toast.id)}
              className="text-slate-400 hover:text-white p-1.5 rounded-full hover:bg-slate-800 transition-colors cursor-pointer shrink-0"
              aria-label="Dismiss notification"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        );
      })}
    </div>
  );
};
