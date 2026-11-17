import React, { useState } from 'react';
import { CheckCircle2, Play, RotateCcw, XCircle } from 'lucide-react';
import type { TestStepResult } from '../types/tamper';

interface TestPlanViewProps {
  demoActionsEnabled: boolean;
  onRunStep: (step: number) => Promise<TestStepResult | null>;
  onResetSandbox: () => Promise<void>;
}

const SECTION_12_STEPS = [
  { step: 1, name: 'Append', command: 'echo test | sudo tee -a /var/log/test.log', expected: 'White [INFO] line in dashboard, no alert.' },
  { step: 2, name: 'Edit', command: "echo AAAA | sudo tee -a /var/log/test.log; sudo sed -i 's/test/EDIT/' /var/log/test.log", expected: 'SED_INPLACE_ON_LOG and INODE_REPLACED or CONTENT_MODIFIED.' },
  { step: 3, name: 'Truncate', command: 'sudo truncate -s 0 /var/log/test.log', expected: 'TRUNCATED + LOG_FILE_COMMAND.' },
  { step: 4, name: 'Permissions', command: 'sudo chmod 777 /var/log/test.log', expected: 'PERM_OWNER_CHANGE.' },
  { step: 5, name: 'Delete', command: 'sudo rm /var/log/test.log', expected: 'DELETED_OR_MOVED; alert names rm and user.' },
  { step: 6, name: 'Rotation', command: 'sudo logrotate -f /etc/logrotate.conf', expected: 'Only info lines marked allowed.' },
  { step: 7, name: 'Service stop', command: 'sudo systemctl stop rsyslog; sudo systemctl start rsyslog', expected: 'LOGGING_SERVICE_STOPPED.' },
  { step: 8, name: 'Vacuum', command: 'sudo journalctl --vacuum-size=500M', expected: 'JOURNAL_VACUUM.' },
  { step: 9, name: 'Chain', command: 'sudo tamplogs --verify', expected: 'Prints True None; fails with line number if chain edited.' },
  { step: 10, name: 'Audit rules', command: 'sudo auditctl -l; sudo ausearch -k log_tamper -i -c tee --start recent', expected: 'never and always rules listed; SYSCALL record with comm=tee.' },
];

export const TestPlanView: React.FC<TestPlanViewProps> = ({ demoActionsEnabled, onRunStep, onResetSandbox }) => {
  const [results, setResults] = useState<Record<number, TestStepResult>>({});
  const [runningStep, setRunningStep] = useState<number | null>(null);
  const [runningAll, setRunningAll] = useState(false);

  const handleRunOne = async (step: number) => {
    setRunningStep(step);
    const res = await onRunStep(step);
    if (res) {
      setResults((prev) => ({ ...prev, [step]: res }));
    }
    setRunningStep(null);
  };

  const handleRunAll = async () => {
    setRunningAll(true);
    setResults({});
    for (const item of SECTION_12_STEPS) {
      setRunningStep(item.step);
      const res = await onRunStep(item.step);
      if (res) {
        setResults((prev) => ({ ...prev, [item.step]: res }));
      }
    }
    setRunningStep(null);
    setRunningAll(false);
  };

  const passedCount = Object.values(results).filter((r) => r.passed).length;

  return (
    <div className="flex flex-col gap-4">
      <div className="bg-[#111827] border border-slate-800 rounded-lg p-4 flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="text-sm font-semibold text-slate-100">Section 12 Safe Verification Suite (10 Steps)</h2>
          <p className="text-xs text-slate-400 mt-0.5 tabular-nums">
            Executes real commands against <code className="font-mono text-slate-300">/var/log/test.log</code> &amp; daemons ·{' '}
            {Object.keys(results).length > 0 ? `${passedCount} / ${Object.keys(results).length} passed` : 'Ready to execute'}
          </p>
          {!demoActionsEnabled && (
            <p className="text-xs text-amber-300 font-mono mt-1.5">
              Destructive test-plan steps &amp; reset are disabled (`TAMPERER_ENABLE_DEMO_ACTIONS=0`). Set `TAMPERER_ENABLE_DEMO_ACTIONS=1` in server env to run automated drills.
            </p>
          )}
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <button
            type="button"
            disabled={runningAll || runningStep !== null}
            onClick={() => void handleRunAll()}
            className="inline-flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-medium rounded-md bg-sky-600 hover:bg-sky-500 disabled:opacity-50 text-white transition-colors whitespace-nowrap"
          >
            <Play className="w-3.5 h-3.5" />
            {runningAll ? 'Running Suite...' : 'Run All 10 Steps'}
          </button>
          <button
            type="button"
            disabled={runningAll}
            onClick={async () => {
              await onResetSandbox();
              setResults({});
            }}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors whitespace-nowrap"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            Reset Results
          </button>
        </div>
      </div>

      <div className="bg-[#111827] border border-slate-800 rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="bg-[#0E1522] border-b border-slate-800 text-slate-400 font-medium">
                <th className="py-2.5 px-4 w-12">#</th>
                <th className="py-2.5 px-3 w-28">Test</th>
                <th className="py-2.5 px-3">Command</th>
                <th className="py-2.5 px-3">Expected Result</th>
                <th className="py-2.5 px-3">Observed</th>
                <th className="py-2.5 px-4 text-right w-28">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {SECTION_12_STEPS.map((item) => {
                const res = results[item.step];
                const isRunning = runningStep === item.step;
                return (
                  <tr key={item.step} className="hover:bg-slate-800/30 transition-colors align-top">
                    <td className="py-3 px-4 font-mono text-slate-400 tabular-nums">{item.step}</td>
                    <td className="py-3 px-3 font-medium text-slate-200 whitespace-nowrap">{item.name}</td>
                    <td className="py-3 px-3 font-mono text-sky-300 max-w-[300px] break-all">{item.command}</td>
                    <td className="py-3 px-3 text-slate-400 max-w-[260px]">{item.expected}</td>
                    <td className="py-3 px-3 max-w-[260px]">
                      {isRunning ? (
                        <span className="text-sky-400 font-mono">Executing...</span>
                      ) : res ? (
                        <div className="space-y-0.5">
                          <div className={`inline-flex items-center gap-1 font-medium ${res.passed ? 'text-emerald-400' : 'text-red-400'}`}>
                            {res.passed ? <CheckCircle2 className="w-3.5 h-3.5" /> : <XCircle className="w-3.5 h-3.5" />}
                            <span>{res.passed ? 'PASS' : 'FAIL'}</span>
                            <span className="text-slate-500 font-mono text-[11px] tabular-nums">({res.durationMs} ms)</span>
                          </div>
                          <div className="font-mono text-[11px] text-slate-300 break-words">{res.observed}</div>
                        </div>
                      ) : (
                        <span className="text-slate-600 font-mono">Not run</span>
                      )}
                    </td>
                    <td className="py-3 px-4 text-right">
                      <button
                        type="button"
                        disabled={runningAll || isRunning}
                        onClick={() => void handleRunOne(item.step)}
                        className="inline-flex items-center gap-1 px-2.5 py-1 text-xs font-medium rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-slate-200 border border-slate-700 transition-colors whitespace-nowrap"
                      >
                        <Play className="w-3 h-3" />
                        Run
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
