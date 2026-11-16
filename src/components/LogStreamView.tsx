import React, { useEffect, useMemo, useRef, useState } from 'react';
import { Download, Pause, Play, Search, X } from 'lucide-react';
import type { LogEvent, Severity } from '../types/tamper';

interface LogStreamViewProps {
  logs: LogEvent[];
  monitoringActive: boolean;
  selectedAgentId: string;
  onStartMonitor: () => Promise<void>;
}

export const LogStreamView: React.FC<LogStreamViewProps> = ({
  logs,
  monitoringActive,
  selectedAgentId,
  onStartMonitor,
}) => {
  const [selectedView, setSelectedView] = useState<string>('ALL');
  const [severityFilter, setSeverityFilter] = useState<'ALL' | Severity>('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [paused, setPaused] = useState(false);
  const [frozenLogs, setFrozenLogs] = useState<LogEvent[]>(logs);
  const [selectedEvent, setSelectedEvent] = useState<LogEvent | null>(null);
  const searchRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (!paused) {
      setFrozenLogs(logs);
    }
  }, [logs, paused]);

  const activeLogs = useMemo(() => {
    const base = paused ? frozenLogs : logs;
    return selectedAgentId === 'ALL' ? base : base.filter((l) => l.agentId === selectedAgentId);
  }, [logs, frozenLogs, paused, selectedAgentId]);

  const users = useMemo(() => {
    const set = new Set<string>();
    for (const l of activeLogs) {
      if (l.user) set.add(l.user);
    }
    return Array.from(set).sort();
  }, [activeLogs]);

  const files = useMemo(() => {
    const set = new Set<string>();
    for (const l of activeLogs) {
      if (l.file) set.add(l.file);
    }
    return Array.from(set).sort();
  }, [activeLogs]);

  const viewTabs = useMemo(() => {
    return [
      { id: 'ALL', label: 'All Logs' },
      { id: 'ALERTS', label: 'ALERTS' },
      ...users.map((u) => ({ id: `user:${u}`, label: `user:${u}` })),
      ...files.map((f) => ({ id: `file:${f}`, label: f })),
    ];
  }, [users, files]);

  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement | null;
      const isInputFocused = target && (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA' || target.tagName === 'SELECT');

      if (e.key === '/' && !isInputFocused) {
        e.preventDefault();
        searchRef.current?.focus();
        return;
      }
      if (e.key === 'Escape') {
        if (searchQuery) setSearchQuery('');
        searchRef.current?.blur();
        return;
      }
      if (isInputFocused) return;

      if (e.key.toLowerCase() === 'p') {
        e.preventDefault();
        setPaused((prev) => !prev);
      } else if (e.key === 'ArrowLeft') {
        e.preventDefault();
        const idx = viewTabs.findIndex((t) => t.id === selectedView);
        const prevIdx = (idx - 1 + viewTabs.length) % viewTabs.length;
        setSelectedView(viewTabs[prevIdx].id);
      } else if (e.key === 'ArrowRight') {
        e.preventDefault();
        const idx = viewTabs.findIndex((t) => t.id === selectedView);
        const nextIdx = (idx + 1) % viewTabs.length;
        setSelectedView(viewTabs[nextIdx].id);
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [searchQuery, selectedView, viewTabs]);

  const filteredLogs = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    return activeLogs.filter((ev) => {
      if (selectedView === 'ALERTS' && !ev.isTamper) return false;
      if (selectedView.startsWith('user:') && ev.user !== selectedView.slice(5)) return false;
      if (selectedView.startsWith('file:') && ev.file !== selectedView.slice(5)) return false;
      if (severityFilter !== 'ALL' && ev.severity !== severityFilter) return false;
      if (q) {
        const hay = `${ev.timeShort} ${ev.host} ${ev.severity} ${ev.user} ${ev.file} ${ev.message}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }, [activeLogs, selectedView, severityFilter, searchQuery]);

  const handleExport = () => {
    const text = filteredLogs
      .map((ev) => `${ev.ts} ${ev.host} [${ev.severity}] ${ev.user} ${ev.file}: ${ev.message}`)
      .join('\n');
    const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `tamperer-${selectedView.replace(/[^a-zA-Z0-9_-]/g, '_')}.log`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="flex flex-col gap-4 h-full">
      <div className="bg-[#111827] border border-slate-800 rounded-lg p-4 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="relative flex-1 min-w-[240px] max-w-md">
            <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
            <input
              ref={searchRef}
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Filter logs by host, path, user, message (/ focus, Esc clear)..."
              className="w-full pl-9 pr-8 py-2 text-xs font-mono bg-[#0B0F17] border border-slate-800 rounded-md text-slate-100 placeholder-slate-500 focus:outline-none focus:border-sky-500"
            />
            {searchQuery && (
              <button
                type="button"
                onClick={() => setSearchQuery('')}
                aria-label="Clear search"
                className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-200"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            )}
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <div className="flex items-center p-1 bg-[#0B0F17] border border-slate-800 rounded-md">
              {(['ALL', 'INFO', 'WARN', 'CRIT'] as const).map((sev) => (
                <button
                  key={sev}
                  type="button"
                  onClick={() => setSeverityFilter(sev)}
                  className={`px-2.5 py-1 text-xs font-mono rounded transition-colors whitespace-nowrap shrink-0 ${
                    severityFilter === sev
                      ? 'bg-slate-800 text-slate-100 font-semibold'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {sev}
                </button>
              ))}
            </div>

            <button
              type="button"
              onClick={() => setPaused((p) => !p)}
              className={`inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md border transition-colors whitespace-nowrap shrink-0 ${
                paused
                  ? 'bg-amber-950/60 border-amber-700 text-amber-200'
                  : 'bg-slate-800 border-slate-700 text-slate-200 hover:bg-slate-700'
              }`}
            >
              {paused ? <Play className="w-3.5 h-3.5" /> : <Pause className="w-3.5 h-3.5" />}
              {paused ? 'Resume (p)' : 'Pause (p)'}
            </button>

            <button
              type="button"
              onClick={handleExport}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors whitespace-nowrap shrink-0"
            >
              <Download className="w-3.5 h-3.5" />
              Export Log
            </button>
          </div>
        </div>

        <div className="flex items-center gap-1.5 overflow-x-auto pb-1">
          {viewTabs.map((tab) => {
            const active = selectedView === tab.id;
            const isAlertsTab = tab.id === 'ALERTS';
            return (
              <button
                key={tab.id}
                type="button"
                onClick={() => setSelectedView(tab.id)}
                className={`px-3 py-1.5 text-xs font-mono rounded-md border transition-colors whitespace-nowrap shrink-0 ${
                  active
                    ? isAlertsTab
                      ? 'bg-red-950 border-red-700 text-red-200 font-semibold'
                      : 'bg-sky-600/20 border-sky-500/70 text-sky-200 font-semibold'
                    : 'bg-[#0B0F17] border-slate-800 text-slate-400 hover:text-slate-200 hover:border-slate-700'
                }`}
              >
                {tab.label}
              </button>
            );
          })}
        </div>
      </div>

      {/* Master Log List */}
      <div className="flex-1 bg-[#080C12] border border-slate-800 rounded-lg overflow-hidden flex flex-col min-h-[340px]">
        <div className="flex items-center justify-between px-4 py-2.5 bg-[#0E1522] border-b border-slate-800 text-xs text-slate-400">
          <div className="flex items-center gap-2 font-mono">
            <span className="text-slate-200 font-semibold">{selectedView === 'ALL' ? 'All Logs' : selectedView}</span>
            <span aria-hidden="true">·</span>
            <span>{filteredLogs.length} lines</span>
            {paused && (
              <>
                <span aria-hidden="true">·</span>
                <span className="text-amber-400 font-semibold">PAUSED</span>
              </>
            )}
          </div>
          <span className="font-mono text-slate-500 hidden sm:inline">Click any row to open Event Inspector</span>
        </div>

        {filteredLogs.length === 0 ? (
          <div className="flex-1 flex flex-col items-center justify-center p-10 text-center">
            <p className="text-sm font-medium text-slate-200 mb-1">No log entries match this filter</p>
            <p className="text-xs text-slate-400 max-w-md mb-4">
              {!monitoringActive
                ? 'Monitoring is currently in standby. Start tamplogs to stream real-time appends, agent feeds, and tamper alerts.'
                : 'Clear your active search or switch back to All Logs to inspect incoming events.'}
            </p>
            {!monitoringActive && (
              <button
                type="button"
                onClick={() => void onStartMonitor()}
                className="px-3.5 py-2 text-xs font-medium rounded-md bg-sky-600 hover:bg-sky-500 text-white transition-colors"
              >
                Start Real-Time Monitoring
              </button>
            )}
          </div>
        ) : (
          <div className="flex-1 overflow-auto font-mono text-xs divide-y divide-slate-800/40 max-h-[380px]">
            {filteredLogs.map((ev) => {
              const sevClass =
                ev.severity === 'CRIT'
                  ? 'text-red-400 font-bold'
                  : ev.severity === 'WARN'
                    ? 'text-amber-300 font-semibold'
                    : 'text-slate-300';
              const isSelected = selectedEvent?.id === ev.id;
              const rowBg = isSelected
                ? 'bg-sky-950/50'
                : ev.isTamper
                  ? 'bg-red-950/25 hover:bg-red-950/40'
                  : 'hover:bg-slate-900/50';
              return (
                <div
                  key={ev.id}
                  onClick={() => setSelectedEvent(ev)}
                  className={`grid grid-cols-[68px_112px_54px_82px_190px_1fr] gap-2 px-4 py-2 items-baseline cursor-pointer transition-colors ${rowBg}`}
                >
                  <span className="text-slate-500 tabular-nums">{ev.timeShort}</span>
                  <span className="text-emerald-400/90 truncate">{ev.host}</span>
                  <span className={sevClass}>[{ev.severity}]</span>
                  <span className="text-sky-400 truncate">{ev.user}</span>
                  <span className="text-slate-400 truncate" title={ev.file}>{ev.file}</span>
                  <span className={`break-all ${ev.severity === 'CRIT' ? 'text-red-200' : ev.severity === 'WARN' ? 'text-amber-100' : 'text-slate-200'}`}>
                    {ev.message}
                  </span>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Burp Suite-style Bottom Raw Event Inspector */}
      {selectedEvent && (
        <div className="bg-[#111827] border border-slate-800 rounded-lg p-4 space-y-2">
          <div className="flex items-center justify-between border-b border-slate-800 pb-2">
            <div className="text-xs font-semibold text-slate-200 font-mono">
              Inspector · {selectedEvent.host} · {selectedEvent.file} · {selectedEvent.ts}
            </div>
            <button
              type="button"
              onClick={() => setSelectedEvent(null)}
              className="text-slate-400 hover:text-slate-200"
              aria-label="Close inspector"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 text-xs font-mono">
            <div><span className="text-slate-500">agent:</span> <span className="text-slate-200">{selectedEvent.agentId}</span></div>
            <div><span className="text-slate-500">user:</span> <span className="text-slate-200">{selectedEvent.user}</span></div>
            <div><span className="text-slate-500">source:</span> <span className="text-slate-200">{selectedEvent.source}</span></div>
            <div><span className="text-slate-500">rule:</span> <span className="text-red-300">{selectedEvent.ruleKind || 'NORMAL'}</span></div>
            <div><span className="text-slate-500">mitre:</span> <span className="text-amber-300">{selectedEvent.mitreId || '-'}</span></div>
          </div>
          <pre className="p-3 bg-[#080C12] border border-slate-800 rounded font-mono text-xs text-slate-200 whitespace-pre-wrap break-all">
            {selectedEvent.message}
          </pre>
        </div>
      )}
    </div>
  );
};
