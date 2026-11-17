import React, { useState } from 'react';
import { AlertTriangle, CheckCircle2, Play, ShieldCheck, Square } from 'lucide-react';
import type { AuditRuleEntry, ChainRecord, ChainVerifyResult, ServiceStatus } from '../types/tamper';

interface ChainsAuditViewProps {
  chainVerify: {
    alerts: ChainVerifyResult;
    mirror: ChainVerifyResult;
  };
  recentAlertChain: ChainRecord[];
  recentMirrorChain: ChainRecord[];
  auditRules: AuditRuleEntry[];
  services: ServiceStatus[];
  demoActionsEnabled: boolean;
  onVerifyChains: () => Promise<void>;
  onCorruptDemo: () => Promise<void>;
  onToggleService: (svc: ServiceStatus['name'], currentlyActive: boolean) => Promise<void>;
}

export const ChainsAuditView: React.FC<ChainsAuditViewProps> = ({
  chainVerify,
  recentAlertChain,
  recentMirrorChain,
  auditRules,
  services,
  demoActionsEnabled,
  onVerifyChains,
  onCorruptDemo,
  onToggleService,
}) => {
  const [chainTab, setChainTab] = useState<'alerts' | 'mirror'>('alerts');
  const activeRecords = chainTab === 'alerts' ? recentAlertChain : recentMirrorChain;

  return (
    <div className="flex flex-col gap-5">
      {/* Top Grid: Chain Verification Status + Services */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* SHA-256 Hash Chains */}
        <div className="lg:col-span-7 bg-[#111827] border border-slate-800 rounded-lg p-5 flex flex-col justify-between gap-4">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <h2 className="text-sm font-semibold text-slate-100">Cryptographic Hash Chains (--verify)</h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Every alert &amp; tailed log line is linked by <code className="font-mono text-slate-300">SHA-256(prev + canonicalJSON)</code>.
              </p>
            </div>
            <div className="flex items-center gap-2 shrink-0">
              <button
                type="button"
                onClick={() => void onVerifyChains()}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md bg-sky-600 hover:bg-sky-500 text-white transition-colors whitespace-nowrap"
              >
                <ShieldCheck className="w-3.5 h-3.5" />
                Verify Chains
              </button>
              <button
                type="button"
                onClick={() => void onCorruptDemo()}
                disabled={!demoActionsEnabled}
                title={demoActionsEnabled ? 'Modify last record in alerts.chain for tamper-verification test' : 'Disabled unless TAMPERER_ENABLE_DEMO_ACTIONS=1'}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md bg-slate-800 hover:bg-slate-700 disabled:opacity-45 text-amber-300 border border-slate-700 transition-colors whitespace-nowrap"
              >
                <AlertTriangle className="w-3.5 h-3.5" />
                Simulate Chain Edit
              </button>
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-2 border-t border-slate-800/80">
            {[chainVerify.alerts, chainVerify.mirror].map((res) => (
              <div key={res.chain} className="bg-[#0B0F17] border border-slate-800 rounded-md p-3.5 space-y-1.5">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-xs font-semibold text-slate-200">{res.chain}</span>
                  {res.ok ? (
                    <span className="inline-flex items-center gap-1 text-xs font-medium text-emerald-400">
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      True None
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-1 text-xs font-medium text-red-400">
                      <AlertTriangle className="w-3.5 h-3.5" />
                      False (Line {res.brokenLine})
                    </span>
                  )}
                </div>
                <p className="text-xs font-mono text-slate-400 tabular-nums">
                  {res.totalLines} records · head {res.headHash.slice(0, 14)}…
                </p>
                {!res.ok && res.reason && (
                  <p className="text-xs text-red-300 font-mono">{res.reason}</p>
                )}
              </div>
            ))}
          </div>
        </div>

        {/* Logging Services Watchdog */}
        <div className="lg:col-span-5 bg-[#111827] border border-slate-800 rounded-lg p-5 space-y-3">
          <div>
            <h2 className="text-sm font-semibold text-slate-100">Logging Daemon Watchdog</h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Polled every 5 s; stopping any daemon raises <code className="font-mono text-slate-300">LOGGING_SERVICE_STOPPED</code>.
            </p>
          </div>
          <div className="divide-y divide-slate-800 border-t border-slate-800/80">
            {services.map((svc) => (
              <div key={svc.name} className="py-2.5 flex items-center justify-between gap-3">
                <div>
                  <div className="font-mono text-xs font-semibold text-slate-200">{svc.name}.service</div>
                  <div className="text-xs font-mono text-slate-400 tabular-nums">
                    <span className={svc.active ? 'text-emerald-400' : 'text-red-400 font-semibold'}>
                      {svc.active ? 'Active' : 'Inactive'}
                    </span>
                    <span aria-hidden="true"> · </span>
                    <span>pid {svc.pid}</span>
                    <span aria-hidden="true"> · </span>
                    <span>up {svc.uptime}</span>
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => void onToggleService(svc.name, svc.active)}
                  className={`inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium rounded border transition-colors whitespace-nowrap shrink-0 ${
                    svc.active
                      ? 'bg-slate-800 hover:bg-red-950/60 text-slate-200 hover:text-red-200 border-slate-700'
                      : 'bg-emerald-950/50 hover:bg-emerald-900/50 text-emerald-300 border-emerald-800'
                  }`}
                >
                  {svc.active ? <Square className="w-3 h-3" /> : <Play className="w-3 h-3" />}
                  {svc.active ? 'Stop' : 'Start'}
                </button>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Auditd Rules & Chain Ledger */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Chain Ledger */}
        <div className="lg:col-span-7 bg-[#111827] border border-slate-800 rounded-lg overflow-hidden">
          <div className="flex items-center justify-between px-4 py-3 bg-[#0E1522] border-b border-slate-800">
            <h3 className="text-xs font-semibold text-slate-200">Hash Chain Ledger</h3>
            <div className="flex items-center p-0.5 bg-[#0B0F17] border border-slate-800 rounded">
              <button
                type="button"
                onClick={() => setChainTab('alerts')}
                className={`px-2.5 py-1 text-xs font-mono rounded ${
                  chainTab === 'alerts' ? 'bg-slate-800 text-slate-100' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                alerts.chain
              </button>
              <button
                type="button"
                onClick={() => setChainTab('mirror')}
                className={`px-2.5 py-1 text-xs font-mono rounded ${
                  chainTab === 'mirror' ? 'bg-slate-800 text-slate-100' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                mirror.chain
              </button>
            </div>
          </div>

          <div className="max-h-[360px] overflow-auto divide-y divide-slate-800/70 font-mono text-xs">
            {activeRecords.length === 0 ? (
              <div className="p-8 text-center text-slate-400">
                No records written to {chainTab}.chain yet. Start <code className="text-sky-400">tamplogs</code> to record chained events.
              </div>
            ) : (
              activeRecords.map((rec) => (
                <div key={`${rec.seq}-${rec.hash}`} className="p-3 space-y-1 hover:bg-slate-900/40">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="text-sky-400 font-semibold">
                      #{rec.seq} · {rec.kind || rec.severity || 'EVENT'} · {rec.path || rec.file}
                    </span>
                    <span className="text-slate-500 tabular-nums">{rec.ts}</span>
                  </div>
                  {rec.line && <div className="text-slate-300 truncate">{rec.line}</div>}
                  <div className="text-[11px] text-slate-500">
                    prev: {rec.prev.slice(0, 16)}… → hash: <span className="text-emerald-400">{rec.hash.slice(0, 20)}…</span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* auditctl -l Rules */}
        <div className="lg:col-span-5 bg-[#111827] border border-slate-800 rounded-lg overflow-hidden">
          <div className="flex items-center justify-between px-4 py-3 bg-[#0E1522] border-b border-slate-800">
            <h3 className="text-xs font-semibold text-slate-200">Active Kernel Audit Rules (auditctl -l)</h3>
            <span className="text-xs font-mono text-slate-400 tabular-nums">
              {auditRules.filter((r) => r.loaded).length} / {auditRules.length} loaded
            </span>
          </div>
          <div className="p-4 space-y-2 font-mono text-xs max-h-[360px] overflow-auto">
            {auditRules.length === 0 ? (
              <div className="p-4 bg-[#0B0F17] border border-slate-800 rounded text-slate-400 font-sans space-y-1">
                <p className="text-slate-200 font-medium">No active kernel auditd rules detected</p>
                <p>
                  <code className="font-mono text-slate-300">auditctl</code> returned 0 loaded rules or is not installed on this host container. On a Kali Linux host, run <code className="font-mono text-sky-400">install.sh</code> to deploy <code className="font-mono text-slate-300">/etc/audit/rules.d/tamper_blocker.rules</code>.
                </p>
              </div>
            ) : (
              auditRules.map((r) => (
                <div key={r.rule} className="p-2.5 bg-[#0B0F17] border border-slate-800 rounded space-y-1">
                  <div className="flex items-center justify-between">
                    <span className={r.kind === 'never' ? 'text-amber-300 font-semibold' : 'text-sky-400 font-semibold'}>
                      {r.kind === 'never' ? 'EXCLUDE (never,exit)' : `WATCH (${r.key ?? 'log_tamper'})`}
                    </span>
                    <span className={r.loaded ? 'text-emerald-400' : 'text-red-400'}>
                      {r.loaded ? 'Loaded' : 'Missing'}
                    </span>
                  </div>
                  <div className="text-slate-300 break-all">{r.rule}</div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
