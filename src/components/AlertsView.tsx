import React, { useMemo, useState } from 'react';
import { Check, CheckCheck, Download, ShieldAlert } from 'lucide-react';
import type { TamperAlert } from '../types/tamper';
import { exportAlertsToCsv, exportAlertsToJson } from '../utils/exportForensics';

interface AlertsViewProps {
  alerts: TamperAlert[];
  selectedAgentId: string;
  onAcknowledge: (id: string) => Promise<void>;
  onAcknowledgeAll: () => Promise<void>;
  onJumpToTerminal: () => void;
}

export const AlertsView: React.FC<AlertsViewProps> = ({
  alerts,
  selectedAgentId,
  onAcknowledge,
  onAcknowledgeAll,
  onJumpToTerminal,
}) => {
  const [filter, setFilter] = useState<'unacked' | 'all' | 'acked'>('all');
  const [selectedAlert, setSelectedAlert] = useState<TamperAlert | null>(null);

  const scopedAlerts = useMemo(
    () => (selectedAgentId === 'ALL' ? alerts : alerts.filter((a) => a.agentId === selectedAgentId)),
    [alerts, selectedAgentId],
  );

  const unackedCount = useMemo(() => scopedAlerts.filter((a) => !a.acknowledged).length, [scopedAlerts]);

  const visibleAlerts = useMemo(() => {
    if (filter === 'unacked') return scopedAlerts.filter((a) => !a.acknowledged);
    if (filter === 'acked') return scopedAlerts.filter((a) => a.acknowledged);
    return scopedAlerts;
  }, [scopedAlerts, filter]);

  const activeDetail = selectedAlert && scopedAlerts.some((a) => a.id === selectedAlert.id)
    ? selectedAlert
    : visibleAlerts[0] ?? null;

  const scopeLabel = selectedAgentId === 'ALL' ? 'all-hosts' : selectedAgentId;

  return (
    <div className="flex flex-col gap-4">
      <div className="bg-[#111827] border border-slate-800 rounded-lg p-4 flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="text-sm font-semibold text-slate-100">Live Tamper Alerts &amp; Wazuh Incident Queue</h2>
          <p className="text-xs text-slate-400 mt-0.5 tabular-nums">
            {unackedCount} unacknowledged · {scopedAlerts.length} total recorded in /var/lib/tamper_blocker/alerts.chain
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

          <button
            type="button"
            disabled={visibleAlerts.length === 0}
            onClick={() => exportAlertsToCsv(visibleAlerts, scopeLabel)}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md bg-slate-800 hover:bg-slate-700 disabled:opacity-40 disabled:pointer-events-none text-slate-200 border border-slate-700 transition-colors whitespace-nowrap shrink-0"
            title="Export visible alerts to RFC-4180 CSV for forensic analysis"
          >
            <Download className="w-3.5 h-3.5 text-sky-400" />
            Export CSV
          </button>

          <button
            type="button"
            disabled={visibleAlerts.length === 0}
            onClick={() => exportAlertsToJson(visibleAlerts, scopeLabel)}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md bg-slate-800 hover:bg-slate-700 disabled:opacity-40 disabled:pointer-events-none text-slate-200 border border-slate-700 transition-colors whitespace-nowrap shrink-0"
            title="Export visible alerts to structured JSON for forensic analysis"
          >
            <Download className="w-3.5 h-3.5 text-emerald-400" />
            Export JSON
          </button>

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

      {visibleAlerts.length === 0 ? (
        <div className="bg-[#111827] border border-slate-800 rounded-lg p-12 text-center">
          <ShieldAlert className="w-8 h-8 text-slate-500 mx-auto mb-3" />
          <p className="text-sm font-medium text-slate-200 mb-1">
            {scopedAlerts.length === 0 ? 'No tamper alerts recorded' : 'No alerts match this filter'}
          </p>
          <p className="text-xs text-slate-400 max-w-md mx-auto mb-4">
            Start <code className="text-sky-400 font-mono">tamplogs</code> in the terminal or run a tamper drill on a remote Linux agent to inspect live detections.
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
        <div className="grid grid-cols-1 xl:grid-cols-12 gap-4">
          {/* Master Alert Queue */}
          <div className="xl:col-span-7 bg-[#111827] border border-slate-800 rounded-lg divide-y divide-slate-800 max-h-[540px] overflow-y-auto">
            {visibleAlerts.map((alert) => {
              const isSelected = activeDetail?.id === alert.id;
              return (
                <div
                  key={alert.id}
                  onClick={() => setSelectedAlert(alert)}
                  className={`p-4 flex items-start justify-between gap-4 cursor-pointer transition-colors ${
                    isSelected
                      ? 'bg-sky-950/40'
                      : !alert.acknowledged
                        ? 'bg-red-950/20 hover:bg-red-950/35'
                        : 'hover:bg-slate-800/40 opacity-85'
                  }`}
                >
                  <div className="space-y-1 min-w-0">
                    <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
                      <span className={alert.severity === 'CRIT' ? 'text-red-400 font-bold' : 'text-amber-400 font-bold'}>
                        [{alert.severity}]
                      </span>
                      <span className="text-slate-100 font-semibold">Rule {alert.wazuhRuleId} · {alert.kind}</span>
                      <span aria-hidden="true" className="text-slate-600">·</span>
                      <span className="text-emerald-400">{alert.host}</span>
                      <span aria-hidden="true" className="text-slate-600">·</span>
                      <span className="text-sky-400 truncate">{alert.path}</span>
                    </div>
                    <p className="text-xs text-slate-300">{alert.explanation}</p>
                    <div className="text-[11px] font-mono text-slate-500 tabular-nums">
                      {alert.ts} · {alert.mitreId} ({alert.mitreTactic}) · {alert.user}/{alert.comm}
                    </div>
                  </div>

                  <div className="shrink-0">
                    {alert.acknowledged ? (
                      <span className="inline-flex items-center gap-1 px-2.5 py-1 text-xs font-medium text-emerald-400 border border-emerald-900/60 bg-emerald-950/30 rounded whitespace-nowrap">
                        <Check className="w-3 h-3" />
                        Acked
                      </span>
                    ) : (
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          void onAcknowledge(alert.id);
                        }}
                        className="inline-flex items-center gap-1 px-3 py-1.5 text-xs font-medium rounded bg-red-600 hover:bg-red-500 text-white transition-colors whitespace-nowrap"
                      >
                        <Check className="w-3 h-3" />
                        Acknowledge
                      </button>
                    )}
                  </div>
                </div>
              );
            })}
          </div>

          {/* Burp-style Right Alert Forensics Inspector */}
          {activeDetail && (
            <div className="xl:col-span-5 bg-[#080C12] border border-slate-800 rounded-lg p-5 space-y-4">
              <div className="border-b border-slate-800 pb-3">
                <div className="text-xs font-mono text-red-400 font-semibold">
                  Rule {activeDetail.wazuhRuleId} (Level {activeDetail.ruleLevel}) · {activeDetail.mitreId}
                </div>
                <h3 className="text-sm font-semibold text-slate-100 mt-1">{activeDetail.kind}</h3>
                <p className="text-xs text-slate-400 mt-1">{activeDetail.explanation}</p>
              </div>

              <div className="space-y-2 text-xs font-mono">
                <div className="flex justify-between gap-2 py-1 border-b border-slate-800/60">
                  <span className="text-slate-500">Host / Agent</span>
                  <span className="text-slate-200">{activeDetail.host} ({activeDetail.agentId})</span>
                </div>
                <div className="flex justify-between gap-2 py-1 border-b border-slate-800/60">
                  <span className="text-slate-500">Target Path</span>
                  <span className="text-sky-400 break-all text-right">{activeDetail.path}</span>
                </div>
                <div className="flex justify-between gap-2 py-1 border-b border-slate-800/60">
                  <span className="text-slate-500">Auditd Actor</span>
                  <span className="text-slate-200">{activeDetail.user} · {activeDetail.comm} (pid={activeDetail.pid})</span>
                </div>
                <div className="flex justify-between gap-2 py-1 border-b border-slate-800/60">
                  <span className="text-slate-500">Executable</span>
                  <span className="text-slate-300">{activeDetail.exe}</span>
                </div>
                <div className="flex justify-between gap-2 py-1 border-b border-slate-800/60">
                  <span className="text-slate-500">Baseline Before</span>
                  <span className="text-slate-400 text-right">{activeDetail.beforeSummary}</span>
                </div>
                <div className="flex justify-between gap-2 py-1 border-b border-slate-800/60">
                  <span className="text-slate-500">Observed After</span>
                  <span className="text-red-300 text-right">{activeDetail.afterSummary}</span>
                </div>
                <div className="py-1">
                  <div className="text-slate-500 mb-1">Chain Proof (seq #{activeDetail.seq})</div>
                  <div className="p-2 bg-[#0E1522] border border-slate-800 rounded text-[11px] text-emerald-400 break-all">
                    hash: {activeDetail.chainHash}
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
