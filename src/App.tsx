import React, { useCallback, useEffect, useRef, useState } from 'react';
import {
  Activity,
  CheckCheck,
  FileCode2,
  FlaskConical,
  HardDrive,
  Link2,
  Menu,
  Play,
  RotateCcw,
  ScrollText,
  ShieldAlert,
  Square,
  Terminal,
  Volume2,
  VolumeX,
  X,
} from 'lucide-react';
import { AlertsView } from './components/AlertsView';
import { ChainsAuditView } from './components/ChainsAuditView';
import { FimView } from './components/FimView';
import { KaliSourceView } from './components/KaliSourceView';
import { LogStreamView } from './components/LogStreamView';
import { TamperPopup } from './components/TamperPopup';
import { TerminalView } from './components/TerminalView';
import { TestPlanView } from './components/TestPlanView';
import type {
  AppSnapshot,
  BaselineRecord,
  ChainVerifyResult,
  LogEvent,
  MonitorStatus,
  ServiceStatus,
  TamperAlert,
  TerminalExecResult,
  TestStepResult,
} from './types/tamper';
import { playTamperChime } from './utils/sound';

type NavSection = 'terminal' | 'logs' | 'alerts' | 'fim' | 'chains' | 'tests' | 'source';

export default function App() {
  const [snapshot, setSnapshot] = useState<AppSnapshot | null>(null);
  const [activeNav, setActiveNav] = useState<NavSection>('terminal');
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [soundEnabled, setSoundEnabled] = useState(true);
  const [popupDismissed, setPopupDismissed] = useState(false);
  const [clockText, setClockText] = useState(() => new Date().toISOString().replace('T', ' ').slice(0, 19));

  const soundRef = useRef(soundEnabled);
  soundRef.current = soundEnabled;

  const fetchSnapshot = useCallback(async () => {
    try {
      const res = await fetch('/api/state');
      if (res.ok) {
        const data = (await res.json()) as AppSnapshot;
        setSnapshot(data);
      }
    } catch {
      // ignore transient network error
    }
  }, []);

  useEffect(() => {
    void fetchSnapshot();
    const timer = setInterval(() => {
      setClockText(new Date().toISOString().replace('T', ' ').slice(0, 19));
    }, 1000);
    return () => clearInterval(timer);
  }, [fetchSnapshot]);

  // Real-time SSE connection
  useEffect(() => {
    const es = new EventSource('/api/stream');

    es.addEventListener('status', (e) => {
      const status = JSON.parse((e as MessageEvent).data) as MonitorStatus;
      setSnapshot((prev) => (prev ? { ...prev, status } : prev));
    });

    es.addEventListener('log', (e) => {
      const ev = JSON.parse((e as MessageEvent).data) as LogEvent;
      setSnapshot((prev) => {
        if (!prev) return prev;
        if (prev.logs.some((l) => l.id === ev.id)) return prev;
        return {
          ...prev,
          logs: [ev, ...prev.logs].slice(0, 500),
          status: {
            ...prev.status,
            totalEventsCount: prev.status.totalEventsCount + 1,
          },
        };
      });
    });

    es.addEventListener('alert', (e) => {
      const alert = JSON.parse((e as MessageEvent).data) as TamperAlert;
      setPopupDismissed(false);
      setSnapshot((prev) => {
        if (!prev) return prev;
        const already = prev.alerts.some((a) => a.id === alert.id);
        const nextAlerts = already ? prev.alerts : [alert, ...prev.alerts].slice(0, 200);
        if (!already && prev.status.mode === 'interactive' && soundRef.current) {
          playTamperChime();
        }
        return {
          ...prev,
          alerts: nextAlerts,
        };
      });
    });

    es.addEventListener('alerts_updated', (e) => {
      const alerts = JSON.parse((e as MessageEvent).data) as TamperAlert[];
      setSnapshot((prev) => (prev ? { ...prev, alerts } : prev));
    });

    es.addEventListener('baselines', (e) => {
      const baselines = JSON.parse((e as MessageEvent).data) as BaselineRecord[];
      setSnapshot((prev) => (prev ? { ...prev, baselines } : prev));
    });

    es.addEventListener('services', (e) => {
      const services = JSON.parse((e as MessageEvent).data) as ServiceStatus[];
      setSnapshot((prev) => (prev ? { ...prev, services } : prev));
    });

    es.addEventListener('chain', (e) => {
      const chainVerify = JSON.parse((e as MessageEvent).data) as {
        alerts: ChainVerifyResult;
        mirror: ChainVerifyResult;
      };
      setSnapshot((prev) => (prev ? { ...prev, chainVerify } : prev));
    });

    return () => {
      es.close();
    };
  }, []);

  const handleExecuteCommand = async (command: string): Promise<TerminalExecResult | null> => {
    try {
      const res = await fetch('/api/terminal/exec', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ command }),
      });
      if (!res.ok) return null;
      const data = (await res.json()) as { result: TerminalExecResult; snapshot: AppSnapshot };
      setSnapshot(data.snapshot);
      if (data.result.triggeredRules.length > 0 && data.snapshot.status.mode === 'interactive') {
        setPopupDismissed(false);
        if (soundRef.current) playTamperChime();
      }
      return data.result;
    } catch {
      return null;
    }
  };

  const handleStartMonitor = async () => {
    const res = await fetch('/api/monitor/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode: 'interactive' }),
    });
    if (res.ok) {
      setSnapshot((await res.json()) as AppSnapshot);
    }
  };

  const handleStopMonitor = async () => {
    const res = await fetch('/api/monitor/stop', { method: 'POST' });
    if (res.ok) {
      setSnapshot((await res.json()) as AppSnapshot);
    }
  };

  const handleToggleLiveNoise = async () => {
    if (!snapshot) return;
    await fetch('/api/monitor/noise', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled: !snapshot.status.liveNoiseEnabled }),
    });
    void fetchSnapshot();
  };

  const handleAcknowledge = async (id: string) => {
    const res = await fetch(`/api/alerts/${encodeURIComponent(id)}/ack`, { method: 'POST' });
    if (res.ok) {
      const data = (await res.json()) as { snapshot: AppSnapshot };
      setSnapshot(data.snapshot);
    }
  };

  const handleAcknowledgeAll = async () => {
    const res = await fetch('/api/alerts/ack-all', { method: 'POST' });
    if (res.ok) {
      const data = (await res.json()) as { snapshot: AppSnapshot };
      setSnapshot(data.snapshot);
      setPopupDismissed(true);
    }
  };

  const handleHarden = async (paths?: string[]) => {
    const res = await fetch('/api/files/harden', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ paths }),
    });
    if (res.ok) {
      const data = (await res.json()) as { snapshot: AppSnapshot };
      setSnapshot(data.snapshot);
    }
  };

  const handleUnharden = async (paths?: string[]) => {
    const res = await fetch('/api/files/unharden', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ paths }),
    });
    if (res.ok) {
      const data = (await res.json()) as { snapshot: AppSnapshot };
      setSnapshot(data.snapshot);
    }
  };

  const handleRebaseline = async (path: string) => {
    const res = await fetch('/api/files/rebaseline', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ path }),
    });
    if (res.ok) {
      const data = (await res.json()) as { snapshot: AppSnapshot };
      setSnapshot(data.snapshot);
    }
  };

  const handleVerifyChains = async () => {
    await fetch('/api/chains/verify', { method: 'POST' });
    void fetchSnapshot();
  };

  const handleCorruptDemo = async () => {
    const res = await fetch('/api/chains/corrupt-demo', { method: 'POST' });
    if (res.ok) {
      const data = (await res.json()) as { snapshot: AppSnapshot };
      setSnapshot(data.snapshot);
    }
  };

  const handleToggleService = async (svc: ServiceStatus['name'], currentlyActive: boolean) => {
    const cmd = `sudo systemctl ${currentlyActive ? 'stop' : 'start'} ${svc}`;
    await handleExecuteCommand(cmd);
  };

  const handleRunTestStep = async (step: number): Promise<TestStepResult | null> => {
    const res = await fetch('/api/test-plan/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ step }),
    });
    if (!res.ok) return null;
    const data = (await res.json()) as { result: TestStepResult; snapshot: AppSnapshot };
    setSnapshot(data.snapshot);
    return data.result;
  };

  const handleResetSandbox = async () => {
    const res = await fetch('/api/sandbox/reset', { method: 'POST' });
    if (res.ok) {
      setSnapshot((await res.json()) as AppSnapshot);
      setPopupDismissed(false);
    }
  };

  if (!snapshot) {
    return (
      <div className="min-h-screen bg-[#0B0F17] flex items-center justify-center p-6">
        <div className="w-full max-w-md bg-[#111827] border border-slate-800 rounded-lg p-6 space-y-3">
          <div className="h-5 w-40 bg-slate-800 rounded animate-pulse" />
          <div className="h-3 w-64 bg-slate-800/80 rounded animate-pulse" />
          <div className="h-3 w-52 bg-slate-800/60 rounded animate-pulse" />
        </div>
      </div>
    );
  }

  const unackedAlerts = snapshot.alerts.filter((a) => !a.acknowledged);
  const unackedCount = unackedAlerts.length;
  const latestUnacked = unackedAlerts[0] ?? null;

  const navItems: Array<{ id: NavSection; label: string; icon: React.ReactNode; badge?: number }> = [
    { id: 'terminal', label: 'Terminal (tamplogs)', icon: <Terminal className="w-4 h-4" /> },
    { id: 'logs', label: 'All Logs Stream', icon: <ScrollText className="w-4 h-4" /> },
    { id: 'alerts', label: 'Tamper Alerts', icon: <ShieldAlert className="w-4 h-4" />, badge: unackedCount },
    { id: 'fim', label: 'File Integrity', icon: <HardDrive className="w-4 h-4" /> },
    { id: 'chains', label: 'Hash Chains & Auditd', icon: <Link2 className="w-4 h-4" /> },
    { id: 'tests', label: 'Safe Test Plan', icon: <FlaskConical className="w-4 h-4" /> },
    { id: 'source', label: 'Kali Linux Source', icon: <FileCode2 className="w-4 h-4" /> },
  ];

  const sectionTitles: Record<NavSection, string> = {
    terminal: 'Interactive Terminal · tamplogs',
    logs: 'Unified Log Stream · All Logs',
    alerts: 'Tamper Alerts & Acknowledgement',
    fim: 'File Integrity Baseline Inventory',
    chains: 'Hash Chains & Kernel Auditd',
    tests: 'Section 12 Safe Verification Suite',
    source: 'Kali Linux Python 3.14 Deployment',
  };

  return (
    <div className="min-h-screen bg-[#0B0F17] text-slate-100 flex">
      {/* Mobile Sidebar Backdrop */}
      {mobileMenuOpen && (
        <div
          className="fixed inset-0 bg-black/60 z-30 lg:hidden"
          onClick={() => setMobileMenuOpen(false)}
        />
      )}

      {/* Left Sidebar (252px) */}
      <aside
        className={`fixed lg:static inset-y-0 left-0 z-40 w-[252px] shrink-0 bg-[#0E1522] border-r border-slate-800 flex flex-col transition-transform duration-200 ${
          mobileMenuOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'
        }`}
      >
        <div className="h-14 px-5 border-b border-slate-800 flex items-center justify-between">
          <span className="text-base font-bold tracking-tight text-slate-100 whitespace-nowrap">
            Tamper Blocker
          </span>
          <button
            type="button"
            onClick={() => setMobileMenuOpen(false)}
            className="lg:hidden text-slate-400 hover:text-slate-200 p-1"
            aria-label="Close navigation"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <nav className="flex-1 p-3 space-y-1 overflow-y-auto">
          {navItems.map((item) => {
            const active = activeNav === item.id;
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => {
                  setActiveNav(item.id);
                  setMobileMenuOpen(false);
                }}
                className={`w-full flex items-center justify-between px-3 py-2.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap ${
                  active
                    ? 'bg-sky-600/20 text-sky-200 border border-sky-600/50'
                    : 'text-slate-400 hover:text-slate-100 hover:bg-slate-800/50 border border-transparent'
                }`}
              >
                <span className="flex items-center gap-2.5 truncate">
                  {item.icon}
                  <span className="truncate">{item.label}</span>
                </span>
                {item.badge !== undefined && item.badge > 0 && (
                  <span className="font-mono text-xs font-bold text-red-400 tabular-nums">
                    {item.badge}
                  </span>
                )}
              </button>
            );
          })}
        </nav>

        {/* Bottom Workspace Controls */}
        <div className="p-3 border-t border-slate-800 space-y-1.5 text-xs">
          <button
            type="button"
            onClick={() => setSoundEnabled((s) => !s)}
            className="w-full flex items-center justify-between px-3 py-2 rounded-md text-slate-300 hover:bg-slate-800/60 transition-colors"
          >
            <span className="flex items-center gap-2">
              {soundEnabled ? <Volume2 className="w-3.5 h-3.5 text-sky-400" /> : <VolumeX className="w-3.5 h-3.5 text-slate-500" />}
              Alert Chime
            </span>
            <span className="font-mono text-slate-400">{soundEnabled ? 'On' : 'Off'}</span>
          </button>

          <button
            type="button"
            onClick={() => void handleToggleLiveNoise()}
            className="w-full flex items-center justify-between px-3 py-2 rounded-md text-slate-300 hover:bg-slate-800/60 transition-colors"
          >
            <span className="flex items-center gap-2">
              <Activity className="w-3.5 h-3.5 text-slate-400" />
              Daemon Feed
            </span>
            <span className="font-mono text-slate-400">{snapshot.status.liveNoiseEnabled ? 'Live' : 'Quiet'}</span>
          </button>

          <button
            type="button"
            onClick={() => void handleResetSandbox()}
            className="w-full flex items-center gap-2 px-3 py-2 rounded-md text-slate-400 hover:text-slate-200 hover:bg-slate-800/60 transition-colors"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            Reset Kali Sandbox
          </button>
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="flex-1 min-w-0 flex flex-col">
        {/* Top Bar — Turns crimson when tamper alerts > 0 (Section 1 3-second takeaway) */}
        <header
          className={`h-14 px-4 lg:px-6 border-b flex items-center justify-between gap-4 transition-colors ${
            unackedCount > 0
              ? 'bg-[#7F1D1D] border-red-700 text-red-50'
              : 'bg-[#0E1522] border-slate-800 text-slate-100'
          }`}
        >
          <div className="flex items-center gap-3 min-w-0">
            <button
              type="button"
              onClick={() => setMobileMenuOpen(true)}
              className="lg:hidden p-1.5 rounded hover:bg-white/10"
              aria-label="Open navigation"
            >
              <Menu className="w-4 h-4" />
            </button>
            <h1 className="text-sm font-semibold truncate">{sectionTitles[activeNav]}</h1>
            <span aria-hidden="true" className="hidden md:inline text-slate-500">·</span>
            <div className="hidden md:flex items-center gap-2 text-xs font-mono tabular-nums whitespace-nowrap">
              <span>{snapshot.status.hostname}</span>
              <span aria-hidden="true">/</span>
              <span>{clockText}</span>
              <span aria-hidden="true">·</span>
              <span>files: {snapshot.status.watchedFilesCount}</span>
              <span aria-hidden="true">·</span>
              <span className={unackedCount > 0 ? 'font-bold text-white' : 'text-emerald-400'}>
                tamper alerts: {unackedCount}
              </span>
            </div>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            {unackedCount > 0 && (
              <button
                type="button"
                onClick={() => void handleAcknowledgeAll()}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-md bg-red-600 hover:bg-red-500 text-white border border-red-400/40 transition-colors whitespace-nowrap shrink-0"
              >
                <CheckCheck className="w-3.5 h-3.5" />
                Acknowledge ({unackedCount})
              </button>
            )}

            {snapshot.status.active ? (
              <button
                type="button"
                onClick={() => void handleStopMonitor()}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md bg-slate-900/70 hover:bg-slate-900 text-slate-100 border border-slate-700 transition-colors whitespace-nowrap shrink-0"
              >
                <Square className="w-3.5 h-3.5 text-red-400" />
                Stop Monitor
              </button>
            ) : (
              <button
                type="button"
                onClick={() => void handleStartMonitor()}
                className="inline-flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-medium rounded-md bg-sky-600 hover:bg-sky-500 text-white transition-colors whitespace-nowrap shrink-0"
              >
                <Play className="w-3.5 h-3.5" />
                Start tamplogs
              </button>
            )}
          </div>
        </header>

        {/* Active View Viewport */}
        <main className="flex-1 p-4 lg:p-6 overflow-y-auto max-w-[1440px] w-full mx-auto">
          {activeNav === 'terminal' && (
            <TerminalView
              status={snapshot.status}
              liveLogs={snapshot.logs}
              onExecute={handleExecuteCommand}
              onStartMonitor={handleStartMonitor}
              onStopMonitor={handleStopMonitor}
            />
          )}

          {activeNav === 'logs' && (
            <LogStreamView
              logs={snapshot.logs}
              monitoringActive={snapshot.status.active}
              onStartMonitor={handleStartMonitor}
            />
          )}

          {activeNav === 'alerts' && (
            <AlertsView
              alerts={snapshot.alerts}
              onAcknowledge={handleAcknowledge}
              onAcknowledgeAll={handleAcknowledgeAll}
              onJumpToTerminal={() => setActiveNav('terminal')}
            />
          )}

          {activeNav === 'fim' && (
            <FimView
              baselines={snapshot.baselines}
              onHarden={handleHarden}
              onUnharden={handleUnharden}
              onRebaseline={handleRebaseline}
            />
          )}

          {activeNav === 'chains' && (
            <ChainsAuditView
              chainVerify={snapshot.chainVerify}
              recentAlertChain={snapshot.recentAlertChain}
              recentMirrorChain={snapshot.recentMirrorChain}
              auditRules={snapshot.auditRules}
              services={snapshot.services}
              onVerifyChains={handleVerifyChains}
              onCorruptDemo={handleCorruptDemo}
              onToggleService={handleToggleService}
            />
          )}

          {activeNav === 'tests' && (
            <TestPlanView
              onRunStep={handleRunTestStep}
              onResetSandbox={handleResetSandbox}
            />
          )}

          {activeNav === 'source' && <KaliSourceView />}
        </main>
      </div>

      {/* Persistent Tamper Alert Popup (Section 8) */}
      {latestUnacked && !popupDismissed && snapshot.status.mode === 'interactive' && (
        <TamperPopup
          alert={latestUnacked}
          pendingCount={unackedCount}
          onAcknowledge={handleAcknowledge}
          onDismissView={() => setPopupDismissed(true)}
        />
      )}
    </div>
  );
}
