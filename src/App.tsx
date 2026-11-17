import React, { useCallback, useEffect, useRef, useState } from 'react';
import {
  CheckCheck,
  FileCode2,
  FlaskConical,
  HardDrive,
  LayoutDashboard,
  Link2,
  Play,
  RotateCcw,
  ScrollText,
  Search,
  Server,
  ShieldAlert,
  Square,
  Terminal,
  Volume2,
  VolumeX,
} from 'lucide-react';
import { AgentsView } from './components/AgentsView';
import { AlertsView } from './components/AlertsView';
import { ChainsAuditView } from './components/ChainsAuditView';
import { DashboardView } from './components/DashboardView';
import { FimView } from './components/FimView';
import { KaliSourceView } from './components/KaliSourceView';
import { LogStreamView } from './components/LogStreamView';
import { SplunkSearchView } from './components/SplunkSearchView';
import { TamperPopup } from './components/TamperPopup';
import { TerminalView } from './components/TerminalView';
import { TestPlanView } from './components/TestPlanView';
import type {
  AgentNode,
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

type WorkbenchTab =
  | 'dashboard'
  | 'alerts'
  | 'search'
  | 'agents'
  | 'logs'
  | 'fim'
  | 'terminal'
  | 'chains'
  | 'tests'
  | 'source';

export default function App() {
  const [snapshot, setSnapshot] = useState<AppSnapshot | null>(null);
  const [activeTab, setActiveTab] = useState<WorkbenchTab>('dashboard');
  const [selectedAgentId, setSelectedAgentId] = useState<string>('ALL');
  const [splInitialQuery, setSplInitialQuery] = useState<string>('*');
  const [soundEnabled, setSoundEnabled] = useState(true);
  const [popupDismissed, setPopupDismissed] = useState(false);

  const soundRef = useRef(soundEnabled);
  soundRef.current = soundEnabled;

  const fetchSnapshot = useCallback(async () => {
    try {
      const res = await fetch('/api/state');
      if (res.ok) {
        setSnapshot((await res.json()) as AppSnapshot);
      }
    } catch {
      // ignore transient network error
    }
  }, []);

  useEffect(() => {
    void fetchSnapshot();
  }, [fetchSnapshot]);

  useEffect(() => {
    const es = new EventSource('/api/stream');

    es.addEventListener('status', (e) => {
      const status = JSON.parse((e as MessageEvent).data) as MonitorStatus;
      setSnapshot((prev) => (prev ? { ...prev, status } : prev));
    });

    es.addEventListener('agents', (e) => {
      const agents = JSON.parse((e as MessageEvent).data) as AgentNode[];
      setSnapshot((prev) => (prev ? { ...prev, agents } : prev));
    });

    es.addEventListener('log', (e) => {
      const ev = JSON.parse((e as MessageEvent).data) as LogEvent;
      setSnapshot((prev) => {
        if (!prev) return prev;
        if (prev.logs.some((l) => l.id === ev.id)) return prev;
        return {
          ...prev,
          logs: [ev, ...prev.logs].slice(0, 800),
          status: { ...prev.status, totalEventsCount: prev.status.totalEventsCount + 1 },
        };
      });
    });

    es.addEventListener('alert', (e) => {
      const alert = JSON.parse((e as MessageEvent).data) as TamperAlert;
      setPopupDismissed(false);
      setSnapshot((prev) => {
        if (!prev) return prev;
        const already = prev.alerts.some((a) => a.id === alert.id);
        const nextAlerts = already ? prev.alerts : [alert, ...prev.alerts].slice(0, 300);
        if (!already && prev.status.mode === 'interactive' && soundRef.current) {
          playTamperChime();
        }
        return { ...prev, alerts: nextAlerts };
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

    return () => es.close();
  }, []);

  const [actionError, setActionError] = useState<string | null>(null);

  const readErrorMessage = async (res: Response, fallback: string): Promise<string> => {
    try {
      const payload = (await res.json()) as { error?: string };
      if (payload?.error) return payload.error;
    } catch {
      // ignore parse failure
    }
    return `${fallback} (HTTP ${res.status})`;
  };

  const handleExecuteCommand = async (command: string): Promise<TerminalExecResult | null> => {
    try {
      const res = await fetch('/api/terminal/exec', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ command }),
      });
      if (!res.ok) {
        const msg = await readErrorMessage(res, 'Terminal command rejected');
        return { command, stdout: [], stderr: [msg], exitCode: res.status, cwd: '/', triggeredRules: [] };
      }
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
    if (res.ok) setSnapshot((await res.json()) as AppSnapshot);
  };

  const handleStopMonitor = async () => {
    const res = await fetch('/api/monitor/stop', { method: 'POST' });
    if (res.ok) setSnapshot((await res.json()) as AppSnapshot);
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
    if (res.ok) setSnapshot(((await res.json()) as { snapshot: AppSnapshot }).snapshot);
  };

  const handleUnharden = async (paths?: string[]) => {
    const res = await fetch('/api/files/unharden', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ paths }),
    });
    if (res.ok) setSnapshot(((await res.json()) as { snapshot: AppSnapshot }).snapshot);
  };

  const handleRebaseline = async (path: string) => {
    const res = await fetch('/api/files/rebaseline', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ path }),
    });
    if (res.ok) setSnapshot(((await res.json()) as { snapshot: AppSnapshot }).snapshot);
  };

  const handleVerifyChains = async () => {
    await fetch('/api/chains/verify', { method: 'POST' });
    void fetchSnapshot();
  };

  const handleCorruptDemo = async () => {
    setActionError(null);
    const res = await fetch('/api/chains/corrupt-demo', { method: 'POST' });
    if (res.ok) {
      setSnapshot(((await res.json()) as { snapshot: AppSnapshot }).snapshot);
    } else {
      setActionError(await readErrorMessage(res, 'Simulate chain edit failed'));
    }
  };

  const handleToggleService = async (svc: ServiceStatus['name'], currentlyActive: boolean) => {
    const res = await handleExecuteCommand(`sudo systemctl ${currentlyActive ? 'stop' : 'start'} ${svc}`);
    if (res && res.exitCode !== 0 && res.stderr.length > 0) {
      setActionError(res.stderr[0]);
    }
  };

  const handleRunTestStep = async (step: number): Promise<TestStepResult | null> => {
    const res = await fetch('/api/test-plan/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ step }),
    });
    if (!res.ok) {
      const msg = await readErrorMessage(res, 'Test step failed');
      return { step, name: `Step ${step}`, command: '', expected: '', passed: false, observed: msg, durationMs: 0 };
    }
    const data = (await res.json()) as { result: TestStepResult; snapshot: AppSnapshot };
    setSnapshot(data.snapshot);
    return data.result;
  };

  const handleResetSandbox = async () => {
    setActionError(null);
    const res = await fetch('/api/sandbox/reset', { method: 'POST' });
    if (res.ok) {
      setSnapshot((await res.json()) as AppSnapshot);
      setPopupDismissed(false);
      setSelectedAgentId('ALL');
    } else {
      setActionError(await readErrorMessage(res, 'Reset failed'));
    }
  };

  const handleEnrollAgent = async (name: string, ip: string, os: string): Promise<{ agent: AgentNode | null; error?: string }> => {
    const res = await fetch('/api/agents/enroll', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, ip, os }),
    });
    if (!res.ok) {
      return { agent: null, error: await readErrorMessage(res, 'Agent enrollment failed') };
    }
    const data = (await res.json()) as { agent: AgentNode; snapshot: AppSnapshot };
    setSnapshot(data.snapshot);
    return { agent: data.agent };
  };

  const handleAgentAction = async (
    agentId: string,
    action: 'toggle-status' | 'rebaseline',
  ) => {
    const res = await fetch(`/api/agents/${encodeURIComponent(agentId)}/action`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action }),
    });
    if (res.ok) {
      const data = (await res.json()) as { snapshot: AppSnapshot };
      setSnapshot(data.snapshot);
    }
  };

  if (!snapshot) {
    return (
      <div className="min-h-screen bg-[#0B0F17] flex items-center justify-center p-6">
        <div className="w-full max-w-md bg-[#111827] border border-slate-800 rounded-lg p-6 space-y-3">
          <div className="h-5 w-44 bg-slate-800 rounded animate-pulse" />
          <div className="h-3 w-64 bg-slate-800/80 rounded animate-pulse" />
          <div className="h-3 w-52 bg-slate-800/60 rounded animate-pulse" />
        </div>
      </div>
    );
  }

  const unackedAlerts = snapshot.alerts.filter((a) => !a.acknowledged);
  const unackedCount = unackedAlerts.length;
  const latestUnacked = unackedAlerts[0] ?? null;

  const tabs: Array<{ id: WorkbenchTab; label: string; icon: React.ReactNode; badge?: number }> = [
    { id: 'dashboard', label: 'Dashboard', icon: <LayoutDashboard className="w-3.5 h-3.5" /> },
    { id: 'alerts', label: 'Live Alerts', icon: <ShieldAlert className="w-3.5 h-3.5" />, badge: unackedCount },
    { id: 'search', label: 'Search & SPL', icon: <Search className="w-3.5 h-3.5" /> },
    { id: 'agents', label: 'Agents', icon: <Server className="w-3.5 h-3.5" /> },
    { id: 'logs', label: 'Log Stream', icon: <ScrollText className="w-3.5 h-3.5" /> },
    { id: 'fim', label: 'File Integrity', icon: <HardDrive className="w-3.5 h-3.5" /> },
    { id: 'terminal', label: 'Terminal', icon: <Terminal className="w-3.5 h-3.5" /> },
    { id: 'chains', label: 'Audit & Chains', icon: <Link2 className="w-3.5 h-3.5" /> },
    { id: 'tests', label: 'Test Plan', icon: <FlaskConical className="w-3.5 h-3.5" /> },
    { id: 'source', label: 'Kali App (tamperer)', icon: <FileCode2 className="w-3.5 h-3.5" /> },
  ];

  return (
    <div className="min-h-screen bg-[#0B0F17] text-slate-100 flex flex-col">
      {/* Top Workbench Header — Turns crimson when unacknowledged tamper alerts > 0 */}
      <header
        className={`h-13 px-4 lg:px-6 border-b flex items-center justify-between gap-4 transition-colors ${
          unackedCount > 0
            ? 'bg-[#7F1D1D] border-red-700 text-red-50'
            : 'bg-[#0E1522] border-slate-800 text-slate-100'
        }`}
      >
        <div className="flex items-center gap-4 min-w-0">
          <span className="text-base font-bold tracking-tight whitespace-nowrap shrink-0">
            Tamperer
          </span>

          <div className="hidden md:flex items-center gap-2 text-xs font-mono tabular-nums whitespace-nowrap">
            <span className="text-slate-400">scope:</span>
            <select
              value={selectedAgentId}
              onChange={(e) => setSelectedAgentId(e.target.value)}
              aria-label="Scope by Linux host"
              className="bg-[#080C12]/80 border border-slate-700 rounded px-2 py-1 text-xs font-mono text-slate-100 focus:outline-none"
            >
              <option value="ALL">All Linux Hosts ({snapshot.agents.length})</option>
              {snapshot.agents.map((ag) => (
                <option key={ag.id} value={ag.id}>
                  {ag.hostname} ({ag.ip})
                </option>
              ))}
            </select>
            <span aria-hidden="true" className="text-slate-500">·</span>
            <span>agents: {snapshot.status.activeAgentsCount}/{snapshot.status.totalAgentsCount}</span>
            <span aria-hidden="true">·</span>
            <span>files: {snapshot.status.watchedFilesCount}</span>
            <span aria-hidden="true">·</span>
            <span className={unackedCount > 0 ? 'font-bold text-white' : 'text-emerald-400'}>
              tamper alerts: {unackedCount}
            </span>
          </div>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <button
            type="button"
            onClick={() => setSoundEnabled((s) => !s)}
            className="p-1.5 rounded bg-black/25 hover:bg-black/40 border border-white/10 text-slate-200 transition-colors"
            title={soundEnabled ? 'Mute alert chime' : 'Enable alert chime'}
            aria-label="Toggle alert sound"
          >
            {soundEnabled ? <Volume2 className="w-3.5 h-3.5" /> : <VolumeX className="w-3.5 h-3.5 text-slate-400" />}
          </button>

          <button
            type="button"
            onClick={() => void handleResetSandbox()}
            className="p-1.5 rounded bg-black/25 hover:bg-black/40 border border-white/10 text-slate-300 transition-colors"
            title="Reset baselines & clean /var/log/test.log"
            aria-label="Reset baselines & clean /var/log/test.log"
          >
            <RotateCcw className="w-3.5 h-3.5" />
          </button>

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
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md bg-slate-900/80 hover:bg-slate-900 text-slate-100 border border-slate-700 transition-colors whitespace-nowrap shrink-0"
            >
              <Square className="w-3.5 h-3.5 text-red-400" />
              Stop Monitor
            </button>
          ) : (
            <button
              type="button"
              onClick={() => void handleStartMonitor()}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-md bg-sky-600 hover:bg-sky-500 text-white transition-colors whitespace-nowrap shrink-0"
            >
              <Play className="w-3.5 h-3.5" />
              Start Monitor
            </button>
          )}
        </div>
      </header>

      {/* Burp Suite-Style Horizontal Workbench Tab Bar */}
      <nav
        aria-label="Tamperer Workbench Tabs"
        className="bg-[#0B0F17] border-b border-slate-800 px-4 lg:px-6 flex items-center gap-1 overflow-x-auto"
      >
        {tabs.map((tab) => {
          const active = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              type="button"
              onClick={() => setActiveTab(tab.id)}
              className={`inline-flex items-center gap-2 px-3.5 py-2.5 text-xs font-medium border-b-2 transition-colors whitespace-nowrap shrink-0 ${
                active
                  ? 'border-sky-500 text-slate-100 bg-[#111827]/70'
                  : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-900/40'
              }`}
            >
              {tab.icon}
              <span>{tab.label}</span>
              {tab.badge !== undefined && tab.badge > 0 && (
                <span className="font-mono text-[11px] font-bold text-red-400 tabular-nums">
                  ({tab.badge})
                </span>
              )}
            </button>
          );
        })}
      </nav>

      {/* Main Workbench Viewport */}
      <main className="flex-1 p-4 lg:p-6 max-w-[1440px] w-full mx-auto">
        {actionError && (
          <div className="mb-4 px-4 py-2.5 bg-amber-950/50 border border-amber-800/60 rounded-lg flex items-center justify-between gap-3 text-xs text-amber-200 font-mono">
            <span>{actionError}</span>
            <button type="button" onClick={() => setActionError(null)} className="text-amber-300 hover:text-white font-sans font-medium">
              Dismiss
            </button>
          </div>
        )}

        {activeTab === 'dashboard' && (
          <DashboardView
            status={snapshot.status}
            agents={snapshot.agents}
            logs={snapshot.logs}
            alerts={snapshot.alerts}
            baselines={snapshot.baselines}
            selectedAgentId={selectedAgentId}
            onSelectAgent={setSelectedAgentId}
            onAcknowledge={handleAcknowledge}
            onAcknowledgeAll={handleAcknowledgeAll}
            onStartMonitor={handleStartMonitor}
            onNavigate={(t) => setActiveTab(t)}
            onRunQuickSpl={(q) => {
              setSplInitialQuery(q);
              setActiveTab('search');
            }}
          />
        )}

        {activeTab === 'alerts' && (
          <AlertsView
            alerts={snapshot.alerts}
            selectedAgentId={selectedAgentId}
            onAcknowledge={handleAcknowledge}
            onAcknowledgeAll={handleAcknowledgeAll}
            onJumpToTerminal={() => setActiveTab('terminal')}
          />
        )}

        {activeTab === 'search' && (
          <SplunkSearchView
            initialQuery={splInitialQuery}
            onPivotToHost={(agentId) => {
              setSelectedAgentId(agentId);
              setActiveTab('dashboard');
            }}
          />
        )}

        {activeTab === 'agents' && (
          <AgentsView
            agents={snapshot.agents}
            selectedAgentId={selectedAgentId}
            onSelectAgent={setSelectedAgentId}
            onEnrollAgent={handleEnrollAgent}
            onAgentAction={handleAgentAction}
          />
        )}

        {activeTab === 'logs' && (
          <LogStreamView
            logs={snapshot.logs}
            monitoringActive={snapshot.status.active}
            selectedAgentId={selectedAgentId}
            onStartMonitor={handleStartMonitor}
          />
        )}

        {activeTab === 'fim' && (
          <FimView
            baselines={snapshot.baselines}
            selectedAgentId={selectedAgentId}
            onHarden={handleHarden}
            onUnharden={handleUnharden}
            onRebaseline={handleRebaseline}
          />
        )}

        {activeTab === 'terminal' && (
          <TerminalView
            status={snapshot.status}
            liveLogs={snapshot.logs}
            terminalEnabled={snapshot.capabilities?.terminalEnabled ?? false}
            onExecute={handleExecuteCommand}
            onStartMonitor={handleStartMonitor}
            onStopMonitor={handleStopMonitor}
          />
        )}

        {activeTab === 'chains' && (
          <ChainsAuditView
            chainVerify={snapshot.chainVerify}
            recentAlertChain={snapshot.recentAlertChain}
            recentMirrorChain={snapshot.recentMirrorChain}
            auditRules={snapshot.auditRules}
            services={snapshot.services}
            demoActionsEnabled={snapshot.capabilities?.demoActionsEnabled ?? false}
            onVerifyChains={handleVerifyChains}
            onCorruptDemo={handleCorruptDemo}
            onToggleService={handleToggleService}
          />
        )}

        {activeTab === 'tests' && (
          <TestPlanView
            demoActionsEnabled={snapshot.capabilities?.demoActionsEnabled ?? false}
            onRunStep={handleRunTestStep}
            onResetSandbox={handleResetSandbox}
          />
        )}

        {activeTab === 'source' && <KaliSourceView />}
      </main>

      {/* Persistent Live Alert Popup (Section 8) */}
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
