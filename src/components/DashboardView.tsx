import React, { useMemo } from 'react';
import {
  Activity,
  Check,
  CheckCheck,
  Download,
  FlaskConical,
  Play,
  Search,
  Server,
  ShieldAlert,
  Terminal,
} from 'lucide-react';
import type {
  AgentNode,
  BaselineRecord,
  LogEvent,
  MonitorStatus,
  TamperAlert,
} from '../types/tamper';
import {
  exportAlertsToCsv,
  exportAlertsToJson,
  exportLogsToCsv,
  exportLogsToJson,
} from '../utils/exportForensics';

interface DashboardViewProps {
  status: MonitorStatus;
  agents: AgentNode[];
  logs: LogEvent[];
  alerts: TamperAlert[];
  baselines: BaselineRecord[];
  selectedAgentId: string;
  onSelectAgent: (agentId: string) => void;
  onAcknowledge: (id: string) => Promise<void>;
  onAcknowledgeAll: () => Promise<void>;
  onStartMonitor: () => Promise<void>;
  onNavigate: (tab: 'alerts' | 'search' | 'agents' | 'fim' | 'terminal' | 'tests') => void;
  onRunQuickSpl: (query: string) => void;
}

export const DashboardView: React.FC<DashboardViewProps> = ({
  status,
  agents,
  logs,
  alerts,
  baselines,
  selectedAgentId,
  onSelectAgent,
  onAcknowledge,
  onAcknowledgeAll,
  onStartMonitor,
  onNavigate,
  onRunQuickSpl,
}) => {
  const scopedLogs = useMemo(
    () => (selectedAgentId === 'ALL' ? logs : logs.filter((l) => l.agentId === selectedAgentId)),
    [logs, selectedAgentId],
  );
  const scopedAlerts = useMemo(
    () => (selectedAgentId === 'ALL' ? alerts : alerts.filter((a) => a.agentId === selectedAgentId)),
    [alerts, selectedAgentId],
  );
  const scopedBaselines = useMemo(
    () => (selectedAgentId === 'ALL' ? baselines : baselines.filter((b) => b.agentId === selectedAgentId)),
    [baselines, selectedAgentId],
  );

  const openAlerts = useMemo(() => scopedAlerts.filter((a) => !a.acknowledged), [scopedAlerts]);
  const verifiedCount = useMemo(
    () => scopedBaselines.filter((b) => b.status === 'verified' || b.status === 'rotated').length,
    [scopedBaselines],
  );
  const scopeLabel = selectedAgentId === 'ALL' ? 'all-hosts' : selectedAgentId;

  // 16-bucket timeline histogram for Dashboard overview
  const timelineBuckets = useMemo(() => {
    const now = Date.now();
    const minTs = scopedLogs.length > 0 ? Math.min(...scopedLogs.map((l) => l.epochMs)) : now - 600_000;
    const maxTs = Math.max(now, scopedLogs.length > 0 ? Math.max(...scopedLogs.map((l) => l.epochMs)) : now);
    const span = Math.max(60_000, maxTs - minTs);
    const count = 16;
    const width = span / count;
    const buckets = Array.from({ length: count }, (_, i) => {
      const start = minTs + i * width;
      return {
        label: new Date(start).toTimeString().slice(0, 5),
        info: 0,
        warn: 0,
        crit: 0,
        total: 0,
      };
    });
    for (const ev of scopedLogs) {
      const idx = Math.min(count - 1, Math.max(0, Math.floor((ev.epochMs - minTs) / width)));
      const b = buckets[idx];
      if (ev.severity === 'CRIT') b.crit += 1;
      else if (ev.severity === 'WARN') b.warn += 1;
      else b.info += 1;
      b.total += 1;
    }
    return buckets;
  }, [scopedLogs]);

  const maxBucket = Math.max(1, ...timelineBuckets.map((b) => b.total));

  const ruleBreakdown = useMemo(() => {
    const counts = new Map<string, { kind: string; ruleId: string; mitreId: string; count: number }>();
    for (const a of scopedAlerts) {
      const cur = counts.get(a.kind) ?? {
        kind: a.kind,
        ruleId: a.wazuhRuleId,
        mitreId: a.mitreId,
        count: 0,
      };
      cur.count += 1;
      counts.set(a.kind, cur);
    }
    return Array.from(counts.values()).sort((a, b) => b.count - a.count).slice(0, 6);
  }, [scopedAlerts]);

  return (
    <div className="flex flex-col gap-5">
      {/* Forensic Export & Host Telemetry Toolbar */}
      <div className="bg-[#111827] border border-slate-800 rounded-lg px-4 py-3 flex flex-wrap items-center justify-between gap-3">
        <div className="text-xs text-slate-400 font-mono tabular-nums">
          Host: <span className="text-slate-100 font-semibold">{status.hostname}</span> · Kernel{' '}
          <span className="text-slate-300">{status.kernel}</span> · Live machine logs under{' '}
          <span className="text-sky-400">/var/log</span>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            disabled={scopedLogs.length === 0}
            onClick={() => exportLogsToCsv(scopedLogs, scopeLabel)}
            className="inline-flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-medium rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-40 disabled:pointer-events-none text-slate-200 border border-slate-700 transition-colors whitespace-nowrap shrink-0"
            title="Export current machine logs as CSV"
          >
            <Download className="w-3.5 h-3.5 text-sky-400" />
            Logs CSV ({scopedLogs.length})
          </button>
          <button
            type="button"
            disabled={scopedLogs.length === 0}
            onClick={() => exportLogsToJson(scopedLogs, scopeLabel)}
            className="inline-flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-medium rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-40 disabled:pointer-events-none text-slate-200 border border-slate-700 transition-colors whitespace-nowrap shrink-0"
            title="Export current machine logs as JSON"
          >
            <Download className="w-3.5 h-3.5 text-emerald-400" />
            Logs JSON
          </button>
          <button
            type="button"
            disabled={scopedAlerts.length === 0}
            onClick={() => exportAlertsToCsv(scopedAlerts, scopeLabel)}
            className="inline-flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-medium rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-40 disabled:pointer-events-none text-slate-200 border border-slate-700 transition-colors whitespace-nowrap shrink-0"
            title="Export current tamper alerts as CSV"
          >
            <Download className="w-3.5 h-3.5 text-amber-400" />
            Alerts CSV ({scopedAlerts.length})
          </button>
          <button
            type="button"
            disabled={scopedAlerts.length === 0}
            onClick={() => exportAlertsToJson(scopedAlerts, scopeLabel)}
            className="inline-flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-medium rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-40 disabled:pointer-events-none text-slate-200 border border-slate-700 transition-colors whitespace-nowrap shrink-0"
            title="Export current tamper alerts as JSON"
          >
            <Download className="w-3.5 h-3.5 text-red-400" />
            Alerts JSON
          </button>
        </div>
      </div>

      {/* Urgent Live Alert Strip if Unacknowledged Alerts > 0 */}
      {openAlerts.length > 0 && (
        <div className="bg-[#3B0A0A] border border-red-700 rounded-lg p-4 flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-start gap-3 min-w-0">
            <ShieldAlert className="w-5 h-5 text-red-300 shrink-0 mt-0.5" />
            <div className="min-w-0">
              <div className="text-sm font-semibold text-red-50">
                {openAlerts.length} Unacknowledged Tamper Alert{openAlerts.length > 1 ? 's' : ''} Requiring Triage
              </div>
              <div className="text-xs font-mono text-red-200 mt-0.5 truncate">
                Latest: Rule {openAlerts[0].wazuhRuleId} ({openAlerts[0].kind}) on {openAlerts[0].host}:{openAlerts[0].path} · {openAlerts[0].user}/{openAlerts[0].comm}
              </div>
            </div>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <button
              type="button"
              onClick={() => onNavigate('alerts')}
              className="px-3 py-1.5 text-xs font-medium rounded bg-red-950/90 hover:bg-red-900 text-red-100 border border-red-700 transition-colors whitespace-nowrap"
            >
              Inspect Queue
            </button>
            <button
              type="button"
              onClick={() => void onAcknowledgeAll()}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded bg-red-600 hover:bg-red-500 text-white transition-colors whitespace-nowrap"
            >
              <CheckCheck className="w-3.5 h-3.5" />
              Acknowledge All
            </button>
          </div>
        </div>
      )}

      {/* 4-Column KPI Strip */}
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
        <div className="bg-[#111827] border border-slate-800 rounded-lg p-4 flex flex-col justify-between gap-2">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Connected Linux Agents</span>
            <Server className="w-4 h-4 text-sky-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-slate-100 tabular-nums">
            {status.activeAgentsCount} <span className="text-sm font-normal text-slate-500">/ {status.totalAgentsCount}</span>
          </div>
          <div className="text-xs text-slate-400">
            <button type="button" onClick={() => onNavigate('agents')} className="text-sky-400 hover:underline">
              Manage fleet &amp; enroll hosts
            </button>
          </div>
        </div>

        <div className="bg-[#111827] border border-slate-800 rounded-lg p-4 flex flex-col justify-between gap-2">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Open Tamper Alerts</span>
            <ShieldAlert className={`w-4 h-4 ${openAlerts.length > 0 ? 'text-red-400' : 'text-emerald-400'}`} />
          </div>
          <div className={`text-2xl font-bold font-mono tabular-nums ${openAlerts.length > 0 ? 'text-red-400' : 'text-emerald-400'}`}>
            {openAlerts.length}
          </div>
          <div className="text-xs text-slate-400 tabular-nums">
            {scopedAlerts.length} total alerts recorded in chain
          </div>
        </div>

        <div className="bg-[#111827] border border-slate-800 rounded-lg p-4 flex flex-col justify-between gap-2">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>FIM Baseline Integrity</span>
            <Activity className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-slate-100 tabular-nums">
            {verifiedCount} <span className="text-sm font-normal text-slate-500">/ {scopedBaselines.length}</span>
          </div>
          <div className="text-xs text-slate-400">
            <button type="button" onClick={() => onNavigate('fim')} className="text-sky-400 hover:underline">
              Inspect SHA-256 baselines
            </button>
          </div>
        </div>

        <div className="bg-[#111827] border border-slate-800 rounded-lg p-4 flex flex-col justify-between gap-2">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Indexed Machine Logs</span>
            <Search className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-slate-100 tabular-nums">
            {scopedLogs.length.toLocaleString()}
          </div>
          <div className="text-xs text-slate-400">
            <button type="button" onClick={() => onNavigate('search')} className="text-sky-400 hover:underline">
              Open SPL Search &amp; Analytics
            </button>
          </div>
        </div>
      </div>

      {/* Middle Row: Splunk-style Event Volume Histogram + Live Actions */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-5">
        <div className="xl:col-span-8 bg-[#111827] border border-slate-800 rounded-lg p-5 flex flex-col justify-between gap-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <h2 className="text-sm font-semibold text-slate-100">Security Event &amp; Tamper Volume Timeline</h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Real distribution across INFO, WARN, and CRIT events from machine logs · Click severity to pivot to SPL Search
              </p>
            </div>
            <div className="flex items-center gap-3 text-xs font-mono">
              <button
                type="button"
                onClick={() => onRunQuickSpl('severity=INFO')}
                className="text-sky-400 hover:underline"
              >
                INFO ({scopedLogs.filter((l) => l.severity === 'INFO').length})
              </button>
              <button
                type="button"
                onClick={() => onRunQuickSpl('severity=WARN')}
                className="text-amber-400 hover:underline"
              >
                WARN ({scopedLogs.filter((l) => l.severity === 'WARN').length})
              </button>
              <button
                type="button"
                onClick={() => onRunQuickSpl('severity=CRIT')}
                className="text-red-400 hover:underline"
              >
                CRIT ({scopedLogs.filter((l) => l.severity === 'CRIT').length})
              </button>
            </div>
          </div>

          <div className="h-36 flex items-end gap-1.5 pt-2 border-b border-slate-800 pb-2">
            {timelineBuckets.map((b, idx) => {
              const infoH = Math.round((b.info / maxBucket) * 108);
              const warnH = Math.round((b.warn / maxBucket) * 108);
              const critH = Math.round((b.crit / maxBucket) * 108);
              return (
                <div key={`${b.label}-${idx}`} className="flex-1 flex flex-col items-center justify-end gap-1 group" title={`${b.label}: ${b.total} events (${b.crit} CRIT, ${b.warn} WARN)`}>
                  <div className="w-full max-w-[34px] flex flex-col-reverse rounded-t overflow-hidden bg-slate-900/50">
                    {b.info > 0 && <div style={{ height: `${Math.max(3, infoH)}px` }} className="bg-sky-600/80" />}
                    {b.warn > 0 && <div style={{ height: `${Math.max(4, warnH)}px` }} className="bg-amber-500" />}
                    {b.crit > 0 && <div style={{ height: `${Math.max(5, critH)}px` }} className="bg-red-500" />}
                  </div>
                </div>
              );
            })}
          </div>
          <div className="flex justify-between text-[11px] font-mono text-slate-500 tabular-nums">
            <span>{timelineBuckets[0]?.label}</span>
            <span>{timelineBuckets[Math.floor(timelineBuckets.length / 2)]?.label}</span>
            <span>{timelineBuckets[timelineBuckets.length - 1]?.label}</span>
          </div>
        </div>

        {/* Right: Quick Workbench Triggers & MITRE Summary */}
        <div className="xl:col-span-4 bg-[#111827] border border-slate-800 rounded-lg p-5 flex flex-col justify-between gap-4">
          <div>
            <h2 className="text-sm font-semibold text-slate-100">Live Workbench Controls</h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Monitor state: <span className={status.active ? 'text-emerald-400 font-medium' : 'text-amber-300 font-medium'}>
                {status.active ? `Active (${status.mode})` : 'Standby'}
              </span>
            </p>
          </div>

          <div className="space-y-2">
            {!status.active && (
              <button
                type="button"
                onClick={() => void onStartMonitor()}
                className="w-full flex items-center justify-center gap-2 px-3 py-2 text-xs font-semibold rounded-md bg-sky-600 hover:bg-sky-500 text-white transition-colors"
              >
                <Play className="w-3.5 h-3.5" />
                Start Real-Time Monitoring (tamplogs)
              </button>
            )}
            <button
              type="button"
              onClick={() => onNavigate('terminal')}
              className="w-full flex items-center justify-between px-3 py-2 text-xs font-medium rounded-md bg-[#0B0F17] hover:bg-slate-800/80 text-slate-200 border border-slate-800 transition-colors"
            >
              <span className="flex items-center gap-2">
                <Terminal className="w-3.5 h-3.5 text-sky-400" />
                Open Host Terminal (tamplogs)
              </span>
              <span className="font-mono text-slate-500">CLI</span>
            </button>
            <button
              type="button"
              onClick={() => onNavigate('tests')}
              className="w-full flex items-center justify-between px-3 py-2 text-xs font-medium rounded-md bg-[#0B0F17] hover:bg-slate-800/80 text-slate-200 border border-slate-800 transition-colors"
            >
              <span className="flex items-center gap-2">
                <FlaskConical className="w-3.5 h-3.5 text-emerald-400" />
                Run /var/log/test.log Safe Drills
              </span>
              <span className="font-mono text-slate-500">Test Plan</span>
            </button>
          </div>

          <div className="pt-2 border-t border-slate-800">
            <div className="text-xs font-medium text-slate-300 mb-2">Top Triggered Wazuh / MITRE Rules</div>
            {ruleBreakdown.length === 0 ? (
              <p className="text-xs text-slate-500 font-mono">No tamper rules triggered yet.</p>
            ) : (
              <div className="space-y-1.5 text-xs font-mono">
                {ruleBreakdown.map((r) => (
                  <button
                    key={r.kind}
                    type="button"
                    onClick={() => onRunQuickSpl(`rule=${r.kind}`)}
                    className="w-full flex items-center justify-between text-left hover:bg-slate-800/50 px-1.5 py-1 rounded transition-colors"
                  >
                    <span className="text-slate-300 truncate">
                      [{r.ruleId}] {r.kind}
                    </span>
                    <span className="text-red-400 font-semibold tabular-nums shrink-0">{r.count}</span>
                  </button>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Bottom Row: Live Alert Feed + Wazuh Agent Fleet Table */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-5">
        {/* Live Alert Feed */}
        <div className="xl:col-span-7 bg-[#111827] border border-slate-800 rounded-lg overflow-hidden flex flex-col">
          <div className="px-4 py-3 bg-[#0E1522] border-b border-slate-800 flex flex-wrap items-center justify-between gap-2">
            <h3 className="text-xs font-semibold text-slate-200">Live Tamper Alert Feed (Wazuh Rule Engine)</h3>
            <div className="flex items-center gap-3">
              <button
                type="button"
                disabled={scopedAlerts.length === 0}
                onClick={() => exportAlertsToCsv(scopedAlerts, scopeLabel)}
                className="text-xs text-slate-300 hover:text-white disabled:opacity-40 disabled:pointer-events-none"
              >
                Export CSV
              </button>
              <button
                type="button"
                disabled={scopedAlerts.length === 0}
                onClick={() => exportAlertsToJson(scopedAlerts, scopeLabel)}
                className="text-xs text-slate-300 hover:text-white disabled:opacity-40 disabled:pointer-events-none"
              >
                Export JSON
              </button>
              <button type="button" onClick={() => onNavigate('alerts')} className="text-xs text-sky-400 hover:underline">
                View All ({scopedAlerts.length})
              </button>
            </div>
          </div>

          {scopedAlerts.length === 0 ? (
            <div className="p-8 text-center text-xs text-slate-400">
              No tamper alerts yet. All monitored logs across connected Linux agents match their SHA-256 baselines.
            </div>
          ) : (
            <div className="divide-y divide-slate-800/80 max-h-[340px] overflow-y-auto">
              {scopedAlerts.slice(0, 8).map((a) => (
                <div
                  key={a.id}
                  className={`px-4 py-3 flex items-start justify-between gap-3 ${!a.acknowledged ? 'bg-red-950/20' : ''}`}
                >
                  <div className="min-w-0 space-y-1">
                    <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
                      <span className={a.severity === 'CRIT' ? 'text-red-400 font-bold' : 'text-amber-400 font-bold'}>
                        [{a.severity}]
                      </span>
                      <span className="text-slate-100 font-semibold">Rule {a.wazuhRuleId} · {a.kind}</span>
                      <span aria-hidden="true" className="text-slate-600">·</span>
                      <span className="text-sky-400">{a.host}</span>
                      <span aria-hidden="true" className="text-slate-600">·</span>
                      <span className="text-slate-400">{a.mitreId}</span>
                    </div>
                    <div className="text-xs text-slate-300 truncate">{a.path} — {a.explanation}</div>
                    <div className="text-[11px] font-mono text-slate-500 tabular-nums">
                      {a.ts} · actor={a.user} · proc={a.comm} (pid={a.pid})
                    </div>
                  </div>
                  {!a.acknowledged && (
                    <button
                      type="button"
                      onClick={() => void onAcknowledge(a.id)}
                      className="inline-flex items-center gap-1 px-2.5 py-1 text-xs font-medium rounded bg-red-600 hover:bg-red-500 text-white transition-colors whitespace-nowrap shrink-0"
                    >
                      <Check className="w-3 h-3" />
                      Ack
                    </button>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Agent Fleet Overview */}
        <div className="xl:col-span-5 bg-[#111827] border border-slate-800 rounded-lg overflow-hidden flex flex-col">
          <div className="px-4 py-3 bg-[#0E1522] border-b border-slate-800 flex items-center justify-between">
            <h3 className="text-xs font-semibold text-slate-200">Linux Agent Fleet</h3>
            <button type="button" onClick={() => onNavigate('agents')} className="text-xs text-sky-400 hover:underline">
              Enroll New Host
            </button>
          </div>
          <div className="divide-y divide-slate-800/80">
            {agents.map((ag) => {
              const selected = selectedAgentId === ag.id;
              return (
                <div
                  key={ag.id}
                  onClick={() => onSelectAgent(selected ? 'ALL' : ag.id)}
                  className={`px-4 py-3 cursor-pointer transition-colors flex items-center justify-between gap-3 ${
                    selected ? 'bg-sky-950/30' : 'hover:bg-slate-800/40'
                  }`}
                >
                  <div className="min-w-0">
                    <div className="flex items-center gap-2 text-xs">
                      <span className="font-semibold text-slate-100 truncate">{ag.hostname}</span>
                      <span aria-hidden="true" className="text-slate-600">·</span>
                      <span className="font-mono text-slate-400">{ag.ip}</span>
                      <span aria-hidden="true" className="text-slate-600">·</span>
                      <span className={ag.status === 'active' ? 'text-emerald-400 font-medium' : ag.status === 'pending' ? 'text-amber-300 font-medium' : 'text-red-400 font-medium'}>
                        {ag.status === 'active' ? 'Active' : ag.status === 'pending' ? 'Pending' : 'Disconnected'}
                      </span>
                    </div>
                    <div className="text-[11px] font-mono text-slate-500 mt-0.5 truncate">
                      {ag.id} · {ag.os} · files: {ag.watchedCount} · events: {ag.eventsCount}
                    </div>
                  </div>
                  <div className="text-right font-mono text-xs tabular-nums shrink-0">
                    <div className={ag.openAlerts > 0 ? 'text-red-400 font-bold' : 'text-slate-400'}>
                      {ag.openAlerts} alerts
                    </div>
                    <div className="text-[11px] text-slate-500">load {ag.cpuLoad}</div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
};
