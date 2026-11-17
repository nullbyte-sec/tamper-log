import React, { useEffect, useRef, useState } from 'react';
import { Play, Square, Terminal as TerminalIcon, Trash2 } from 'lucide-react';
import type { LogEvent, MonitorStatus, TerminalExecResult } from '../types/tamper';

interface TerminalLine {
  id: string;
  kind: 'prompt' | 'stdout' | 'stderr' | 'system' | 'alert';
  text: string;
}

interface TerminalViewProps {
  status: MonitorStatus;
  liveLogs: LogEvent[];
  terminalEnabled: boolean;
  onExecute: (command: string) => Promise<TerminalExecResult | null>;
  onStartMonitor: () => Promise<void>;
  onStopMonitor: () => Promise<void>;
}

const COMMAND_SUGGESTIONS = [
  'tamperer',
  'tamplogs',
  'tamplogs --verify',
  'tamplogs --status',
  'tamplogs --harden',
  'tamplogs --unharden',
  'tamplogs --headless',
  'tamplogs --stop',
  'ls -la /var/log',
  'tail -n 20 /var/log/nginx/access.log',
  'tail -n 20 /var/log/dpkg.log',
  'stat /var/log/dpkg.log',
  'lsattr /var/log/dpkg.log',
  'echo test | sudo tee -a /var/log/test.log',
  "sudo sed -i 's/test/EDIT/' /var/log/test.log",
  'sudo truncate -s 0 /var/log/test.log',
  'sudo chmod 777 /var/log/test.log',
  'sudo rm /var/log/test.log',
  'help',
];

const QUICK_MACROS: Array<{ label: string; command: string; tone: 'primary' | 'safe' | 'warn' | 'danger' }> = [
  { label: 'tamperer', command: 'tamperer', tone: 'primary' },
  { label: 'tamplogs', command: 'tamplogs', tone: 'primary' },
  { label: 'tamplogs --verify', command: 'tamplogs --verify', tone: 'safe' },
  { label: 'ls -la /var/log', command: 'ls -la /var/log', tone: 'safe' },
  { label: 'tail nginx/access.log', command: 'tail -n 20 /var/log/nginx/access.log', tone: 'safe' },
  { label: 'tail dpkg.log', command: 'tail -n 20 /var/log/dpkg.log', tone: 'safe' },
  { label: 'Safe Append (test.log)', command: 'echo "test" | sudo tee -a /var/log/test.log', tone: 'safe' },
  { label: 'Tamper Edit (sed -i)', command: "sudo sed -i 's/test/EDIT/' /var/log/test.log", tone: 'danger' },
  { label: 'Truncate test.log', command: 'sudo truncate -s 0 /var/log/test.log', tone: 'danger' },
  { label: 'chmod 777 test.log', command: 'sudo chmod 777 /var/log/test.log', tone: 'warn' },
  { label: 'Delete test.log (rm)', command: 'sudo rm /var/log/test.log', tone: 'danger' },
];

export const TerminalView: React.FC<TerminalViewProps> = ({
  status,
  liveLogs,
  terminalEnabled,
  onExecute,
  onStartMonitor,
  onStopMonitor,
}) => {
  const promptPrefix = `root@${status.hostname || 'localhost'}:~$`;
  const [lines, setLines] = useState<TerminalLine[]>([
    {
      id: 'init-1',
      kind: 'system',
      text: `${status.hostname || 'localhost'} (Linux ${status.kernel}) — Tamperer Real Host Shell`,
    },
    {
      id: 'init-2',
      kind: 'system',
      text: "Type 'tamperer' or 'tamplogs' to monitor real /var/log files on this machine, or 'help' for available commands.",
    },
  ]);
  const [input, setInput] = useState('');
  const [history, setHistory] = useState<string[]>([]);
  const [histIdx, setHistIdx] = useState(-1);
  const [busy, setBusy] = useState(false);

  const outputRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (outputRef.current) {
      outputRef.current.scrollTop = outputRef.current.scrollHeight;
    }
  }, [lines]);

  const appendLines = (newItems: Omit<TerminalLine, 'id'>[]) => {
    setLines((prev) => [
      ...prev.slice(-300),
      ...newItems.map((item, i) => ({
        ...item,
        id: `${Date.now()}-${Math.random().toString(36).slice(2, 7)}-${i}`,
      })),
    ]);
  };

  const runCommand = async (raw: string) => {
    const trimmed = raw.trim();
    if (!trimmed || busy) return;

    if (trimmed === 'clear') {
      setLines([]);
      setInput('');
      return;
    }

    setHistory((prev) => [trimmed, ...prev.slice(0, 49)]);
    setHistIdx(-1);
    setInput('');
    setBusy(true);

    appendLines([{ kind: 'prompt', text: `${promptPrefix} ${trimmed}` }]);

    const res = await onExecute(trimmed);
    setBusy(false);

    if (!res) {
      appendLines([{ kind: 'stderr', text: 'Failed to communicate with Tamper Blocker backend.' }]);
      return;
    }

    const outItems: Omit<TerminalLine, 'id'>[] = [];
    for (const s of res.stdout) {
      outItems.push({ kind: 'stdout', text: s });
    }
    for (const e of res.stderr) {
      outItems.push({ kind: 'stderr', text: e });
    }
    if (res.triggeredRules.length > 0) {
      outItems.push({
        kind: 'alert',
        text: `[TAMPER DETECTED] Rules triggered: ${res.triggeredRules.join(', ')}`,
      });
    }
    if (outItems.length > 0) {
      appendLines(outItems);
    }
    inputRef.current?.focus();
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      void runCommand(input);
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (history.length === 0) return;
      const nextIdx = Math.min(histIdx + 1, history.length - 1);
      setHistIdx(nextIdx);
      setInput(history[nextIdx]);
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      if (histIdx <= 0) {
        setHistIdx(-1);
        setInput('');
      } else {
        const nextIdx = histIdx - 1;
        setHistIdx(nextIdx);
        setInput(history[nextIdx]);
      }
    } else if (e.key === 'Tab') {
      e.preventDefault();
      const val = input.trim();
      if (!val) return;
      const match = COMMAND_SUGGESTIONS.find((c) => c.startsWith(val));
      if (match) setInput(match);
    } else if (e.ctrlKey && e.key.toLowerCase() === 'l') {
      e.preventDefault();
      setLines([]);
    }
  };

  return (
    <div className="flex flex-col gap-5 h-full">
      {/* Command Presets Toolbar */}
      <div className="bg-[#111827] border border-slate-800 rounded-lg p-4">
        <div className="flex flex-wrap items-center justify-between gap-3 mb-3">
          <div>
            <h2 className="text-sm font-semibold text-slate-100">Interactive Kali Terminal &amp; Quick Commands</h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Type <code className="text-sky-400 font-mono">tamplogs</code> to start real-time monitoring across all logs, or execute Kali commands below to test detection.
            </p>
            {!terminalEnabled && (
              <p className="text-xs text-amber-300 font-mono mt-1.5">
                Host shell execution is currently disabled (`TAMPERER_ENABLE_TERMINAL=0`). Use &quot;Run tamplogs&quot; / &quot;Start Monitor&quot; buttons, or set `TAMPERER_ENABLE_TERMINAL=1` to enable shell commands.
              </p>
            )}
          </div>
          <div className="flex items-center gap-2 shrink-0">
            {status.active ? (
              <button
                type="button"
                onClick={() => void onStopMonitor()}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors whitespace-nowrap shrink-0"
              >
                <Square className="w-3.5 h-3.5 text-red-400" />
                Stop Monitor
              </button>
            ) : (
              <button
                type="button"
                onClick={() => void onStartMonitor()}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md bg-sky-600 hover:bg-sky-500 text-white transition-colors whitespace-nowrap shrink-0"
              >
                <Play className="w-3.5 h-3.5" />
                Run tamplogs
              </button>
            )}
            <button
              type="button"
              onClick={() => setLines([])}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md bg-slate-800/80 hover:bg-slate-800 text-slate-300 border border-slate-700/80 transition-colors whitespace-nowrap shrink-0"
            >
              <Trash2 className="w-3.5 h-3.5" />
              Clear
            </button>
          </div>
        </div>

        <div className="flex flex-wrap gap-2">
          {QUICK_MACROS.map((macro) => {
            const toneClass =
              macro.tone === 'primary'
                ? 'bg-sky-600/20 hover:bg-sky-600/30 text-sky-300 border-sky-700/60'
                : macro.tone === 'danger'
                  ? 'bg-red-950/50 hover:bg-red-900/50 text-red-300 border-red-800/60'
                  : macro.tone === 'warn'
                    ? 'bg-amber-950/50 hover:bg-amber-900/50 text-amber-300 border-amber-800/60'
                    : 'bg-slate-800/70 hover:bg-slate-800 text-slate-200 border-slate-700';
            return (
              <button
                key={macro.label}
                type="button"
                onClick={() => void runCommand(macro.command)}
                disabled={busy}
                className={`px-2.5 py-1 text-xs font-mono rounded border transition-colors whitespace-nowrap shrink-0 ${toneClass}`}
              >
                {macro.label}
              </button>
            );
          })}
        </div>
      </div>

      {/* Split Workspace: Interactive Terminal + Live tamplogs Stream */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-5 flex-1 min-h-[460px]">
        {/* Left: Kali Shell */}
        <div
          className="xl:col-span-7 flex flex-col bg-[#080C12] border border-slate-800 rounded-lg overflow-hidden"
          onClick={() => inputRef.current?.focus()}
        >
          <div className="flex items-center justify-between px-4 py-2.5 bg-[#0E1522] border-b border-slate-800 text-xs text-slate-400">
            <div className="flex items-center gap-2 font-mono">
              <TerminalIcon className="w-3.5 h-3.5 text-sky-400" />
              <span className="text-slate-200 font-medium">root@{status.hostname || 'localhost'}: ~</span>
              <span aria-hidden="true">·</span>
              <span>bash</span>
            </div>
            <span className="font-mono text-slate-500">Tab complete · Up/Down history</span>
          </div>

          <div ref={outputRef} className="flex-1 p-4 overflow-y-auto font-mono text-[13px] leading-relaxed space-y-1 max-h-[480px]">
            {lines.map((line) => {
              const cls =
                line.kind === 'prompt'
                  ? 'text-sky-400 font-semibold pt-1.5'
                  : line.kind === 'stderr'
                    ? 'text-red-400'
                    : line.kind === 'alert'
                      ? 'text-red-300 bg-red-950/60 px-2 py-1 rounded border border-red-800/60 font-semibold mt-1'
                      : line.kind === 'system'
                        ? 'text-slate-400'
                        : 'text-slate-200';
              return (
                <div key={line.id} className={`whitespace-pre-wrap break-all ${cls}`}>
                  {line.text}
                </div>
              );
            })}
          </div>

          <div className="flex items-center gap-2 px-4 py-3 bg-[#0C121D] border-t border-slate-800 font-mono text-[13px]">
            <span className="text-emerald-400 font-semibold shrink-0">{promptPrefix}</span>
            <input
              ref={inputRef}
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="Type 'tamperer', 'tamplogs', or any host command..."
              className="flex-1 bg-transparent text-slate-100 placeholder-slate-600 focus:outline-none"
              autoFocus
            />
          </div>
        </div>

        {/* Right: Live tamplogs Real-Time Output Tail */}
        <div className="xl:col-span-5 flex flex-col bg-[#080C12] border border-slate-800 rounded-lg overflow-hidden">
          <div className="flex items-center justify-between px-4 py-2.5 bg-[#0E1522] border-b border-slate-800 text-xs">
            <div className="flex items-center gap-2">
              <span className="font-semibold text-slate-200">tamplogs Live Tail</span>
              <span aria-hidden="true" className="text-slate-600">·</span>
              <span className={status.active ? 'text-emerald-400 font-medium' : 'text-slate-400'}>
                {status.active ? `Active (${status.mode})` : 'Standby'}
              </span>
            </div>
            <span className="font-mono text-slate-500 tabular-nums">{liveLogs.length} events</span>
          </div>

          <div className="flex-1 p-3 overflow-y-auto font-mono text-xs leading-5 space-y-1 max-h-[520px]">
            {!status.active && liveLogs.length === 0 ? (
              <div className="h-full flex flex-col items-center justify-center text-center px-6 py-12 text-slate-500">
                <p className="text-sm text-slate-300 font-sans font-medium mb-1">Monitor in standby</p>
                <p className="text-xs font-sans text-slate-400 mb-4">
                  Type <code className="text-sky-400 font-mono">tamplogs</code> in the terminal to stream real-time log appends and tamper alerts.
                </p>
                <button
                  type="button"
                  onClick={() => void runCommand('tamplogs')}
                  className="px-3 py-1.5 text-xs font-sans font-medium rounded-md bg-sky-600 hover:bg-sky-500 text-white transition-colors"
                >
                  Start tamplogs Now
                </button>
              </div>
            ) : (
              liveLogs.slice(0, 80).map((ev) => {
                const rowColor =
                  ev.severity === 'CRIT'
                    ? 'text-red-400 font-semibold'
                    : ev.severity === 'WARN'
                      ? 'text-amber-300'
                      : 'text-slate-300';
                return (
                  <div key={ev.id} className={`whitespace-pre-wrap break-all ${rowColor}`}>
                    <span className="text-slate-500">{ev.timeShort}</span>{' '}
                    <span>[{ev.severity}]</span>{' '}
                    <span className="text-sky-400">{ev.user}</span>{' '}
                    <span className="text-slate-400">{ev.file}:</span>{' '}
                    <span>{ev.message}</span>
                  </div>
                );
              })
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
