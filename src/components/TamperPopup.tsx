import React from 'react';
import { AlertOctagon, Check } from 'lucide-react';
import type { TamperAlert } from '../types/tamper';

interface TamperPopupProps {
  alert: TamperAlert;
  pendingCount: number;
  onAcknowledge: (id: string) => Promise<void>;
  onDismissView: () => void;
}

export const TamperPopup: React.FC<TamperPopupProps> = ({
  alert,
  pendingCount,
  onAcknowledge,
  onDismissView,
}) => {
  return (
    <div
      role="alertdialog"
      aria-modal="true"
      aria-labelledby="tamper-popup-title"
      className="fixed bottom-5 right-5 z-50 w-[min(440px,calc(100vw-2.5rem))] bg-[#450A0A] border border-red-600 rounded-lg shadow-2xl p-4 text-red-50"
    >
      <div className="flex items-start gap-3">
        <AlertOctagon className="w-5 h-5 text-red-300 shrink-0 mt-0.5" />
        <div className="flex-1 min-w-0 space-y-2">
          <div className="flex items-center justify-between gap-2">
            <h3 id="tamper-popup-title" className="text-sm font-bold tracking-tight text-red-50">
              Tamper Detected: {alert.kind}
            </h3>
            {pendingCount > 1 && (
              <span className="text-xs font-mono text-red-200 tabular-nums whitespace-nowrap">
                +{pendingCount - 1} more
              </span>
            )}
          </div>

          <div className="font-mono text-xs space-y-1 text-red-100 bg-black/25 border border-red-800/70 rounded p-2.5">
            <div className="truncate">
              <span className="text-red-300">path:</span> {alert.path}
            </div>
            <div>
              <span className="text-red-300">actor:</span> {alert.user} · {alert.comm} (pid={alert.pid})
            </div>
            <div>
              <span className="text-red-300">time:</span> {alert.ts}
            </div>
            <div className="text-red-50 font-sans pt-1">{alert.explanation}</div>
          </div>

          <div className="flex items-center justify-end gap-2 pt-1">
            <button
              type="button"
              onClick={onDismissView}
              className="px-3 py-1.5 text-xs font-medium rounded bg-red-950/80 hover:bg-red-900 text-red-200 border border-red-800 transition-colors whitespace-nowrap"
            >
              Minimize
            </button>
            <button
              type="button"
              onClick={() => void onAcknowledge(alert.id)}
              className="inline-flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-semibold rounded bg-red-600 hover:bg-red-500 text-white transition-colors whitespace-nowrap"
            >
              <Check className="w-3.5 h-3.5" />
              Acknowledge
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
