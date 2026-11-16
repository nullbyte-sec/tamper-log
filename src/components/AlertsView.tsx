import React, { useMemo, useState } from 'react';
import { Check, CheckCheck, ShieldAlert } from 'lucide-react';
import type { TamperAlert } from '../types/tamper';

interface AlertsViewProps {
  alerts: TamperAlert[];
  onAcknowledge: (id: string) => Promise<void>;
  onAcknowledgeAll: () => Promise<void>;
  onJumpToTerminal: () => void;
}

export const AlertsView: React.FC<AlertsViewProps> = ({
  alerts,
  onAcknowledge,
  onAcknowledgeAll,
  onJumpToTerminal,
}) => {
  const [filter, setFilter] = useState<'unacked' | 'all' | 'acked'>('all');

  const unackedCount = useMemo(() => alerts.filter((a) => !a.acknowledged).length, [alerts]);

  const visibleAlerts = useMemo(() => {
    if (filter === 'unacked') return alerts.filter((a) => !a.acknowledged);
    if (filter === 'acked') return alerts.filter((a) => a.acknowledged);
    return alerts;
  }, [alerts, filter]);

  return (
    <div className="flex flex-col gap-4">
      {/* Header Controls */}
      <div className="bg-[#111827] border border-slate-800 rounded-lg p-4 flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="text-sm font-semibold text-slate-100">Tamper Alert &amp; Incident Queue</h2>
          <p className="text-xs text-slate-400 mt-0.5 tabular-nums">
            {unackedCount} unacknowledged · {alerts.length} total recorded in /var/lib/tamper_blocker/alerts.chain
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <div className="flex items-center p-1 bg-[#0B0F17] border border-slate-800 rounded-md">
            {(
              [
                { id: 'all', label: 'All Alerts' },
                { id: 'unacked', label: `Unacknowledged (${unackedCount})` },
                { id: 'acked', label: 'Acknowledged' },
              ] as const
            ).map((tab) => (
              <button
                key={tab.id}
                type="button"
                onClick={() => setFilter(tab.id)}
                className={`px-3 py-1.5 text-xs font-medium rounded transition-colors whitespace-nowrap shrink-0 ${
                  filter === tab.id ? 'bg-slate-800 text-slate-100' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>

          {unackedCount > 0 && (
            <button
              type="button"
              onClick={() => void onAcknowledgeAll()}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md bg-red-600 hover:bg-red-500 text-white transition-colors whitespace-nowrap shrink-0"
            >
              <CheckCheck className="w-3.5 h-3.5" />
              Acknowledge All ({unackedCount})
            </button>
          )}
        </div>
      </div>

      {/* Alert List */}
      {visibleAlerts.length === 0 ? (
        <div className="bg-[#111827] border border-slate-800 rounded-lg p-12 text-center">
          <ShieldAlert className="w-8 h-8 text-slate-500 mx-auto mb-3" />
          <p className="text-sm font-medium text-slate-200 mb-1">
            {alerts.length === 0 ? 'No tamper alerts recorded' : 'No alerts match this filter'}
          </p>
          <p className="text-xs text-slate-400 max-w-md mx-auto mb-4">
            Start <code className="text-sky-400 font-mono">tamplogs</code> in the terminal and run an edit, truncate, permission change, or deletion command to verify real-time alerting.
          </p>
          <button
            type="button"
            onClick={onJumpToTerminal}
            className="px-4 py-2 text-xs font-medium rounded-md bg-sky-600 hover:bg-sky-500 text-white transition-colors"
          >
            Open Interactive Terminal
          </button>
        </div>
      ) : (
        <div className="bg-[#111827] border border-slate-800 rounded-lg divide-y divide-slate-800">
          {visibleAlerts.map((alert) => (
            <div
              key={alert.id}
              className={`p-4 flex flex-col lg:flex-row lg:items-center justify-between gap-4 transition-colors ${
                !alert.acknowledged ? 'bg-red-950/20' : 'bg-transparent opacity-80'
              }`}
            >
              <div className="space-y-1.5 min-w-0">
                <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
                  <span className={alert.severity === 'CRIT' ? 'text-red-400 font-bold' : 'text-amber-400 font-bold'}>
                    [{alert.severity}]
                  </span>
                  <span className="text-slate-100 font-semibold">{alert.kind}</span>
                  <span aria-hidden="true" className="text-slate-600">·</span>
                  <span className="text-sky-400">{alert.path}</span>
                  <span aria-hidden="true" className="text-slate-600">·</span>
                  <span className="text-slate-400 tabular-nums">{alert.ts}</span>
                  <span aria-hidden="true" className="text-slate-600">·</span>
                  <span className={alert.acknowledged ? 'text-emerald-400' : 'text-red-300 font-semibold'}>
                    {alert.acknowledged ? 'Acknowledged' : 'Requires Acknowledgement'}
                  </span>
                </div>

                <p className="text-sm text-slate-200">{alert.explanation}</p>

                <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs font-mono text-slate-400">
                  <span>
                    actor: <strong className="text-slate-200 font-normal">{alert.user}</strong>
                  </span>
                  <span>
                    proc: <strong className="text-slate-200 font-normal">{alert.comm}</strong> ({alert.exe}, pid={alert.pid})
                  </span>
                  <span>
                    diff: <span className="text-slate-500">{alert.beforeSummary}</span> →{' '}
                    <span className="text-red-300">{alert.afterSummary}</span>
                  </span>
                  <span>
                    chain: <span className="text-slate-500">#{alert.seq} {alert.chainHash.slice(0, 12)}…</span>
                  </span>
                </div>
              </div>

              <div className="flex items-center gap-2 shrink-0">
                {alert.acknowledged ? (
                  <span className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-emerald-400 border border-emerald-900/60 bg-emerald-950/30 rounded-md whitespace-nowrap">
                    <Check className="w-3.5 h-3.5" />
                    Acknowledged
                  </span>
                ) : (
                  <button
                    type="button"
                    onClick={() => void onAcknowledge(alert.id)}
                    className="inline-flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-medium rounded-md bg-red-600 hover:bg-red-500 text-white transition-colors whitespace-nowrap shrink-0"
                  >
                    <Check className="w-3.5 h-3.5" />
                    Acknowledge
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
