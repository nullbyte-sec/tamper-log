import React, { useState } from 'react';
import { Check, Copy, Download, Plus, RefreshCw, Server } from 'lucide-react';
import type { AgentNode } from '../types/tamper';

interface AgentsViewProps {
  agents: AgentNode[];
  selectedAgentId: string;
  onSelectAgent: (agentId: string) => void;
  onEnrollAgent: (name: string, ip: string, os: string) => Promise<AgentNode | null>;
  onAgentAction: (agentId: string, action: 'toggle-status' | 'rebaseline') => Promise<void>;
}

export const AgentsView: React.FC<AgentsViewProps> = ({
  agents,
  selectedAgentId,
  onSelectAgent,
  onEnrollAgent,
  onAgentAction,
}) => {
  const [name, setName] = useState('');
  const [ip, setIp] = useState('');
  const [os, setOs] = useState('Ubuntu 24.04 LTS');
  const [enrolling, setEnrolling] = useState(false);
  const [deployedAgent, setDeployedAgent] = useState<AgentNode | null>(agents.find((a) => !a.isManager) ?? null);
  const [copiedCmd, setCopiedCmd] = useState(false);

  const handleEnroll = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) return;
    setEnrolling(true);
    const created = await onEnrollAgent(name.trim(), ip.trim() || '10.14.2.50', os.trim());
    setEnrolling(false);
    if (created) {
      setDeployedAgent(created);
      setName('');
      setIp('');
    }
  };

  const origin = typeof window !== 'undefined' ? window.location.origin : 'http://127.0.0.1:3000';
  const installOneLiner = deployedAgent
    ? `curl -sSL "${origin}/api/agents/install.sh?agentId=${encodeURIComponent(deployedAgent.id)}&token=${encodeURIComponent(deployedAgent.token)}" | sudo bash`
    : '';

  const handleCopy = async () => {
    if (!installOneLiner) return;
    try {
      await navigator.clipboard.writeText(installOneLiner);
      setCopiedCmd(true);
      setTimeout(() => setCopiedCmd(false), 1800);
    } catch {
      // ignore clipboard errors
    }
  };

  return (
    <div className="flex flex-col gap-5">
      {/* Enroll New Remote Linux Host */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-5">
        <form
          onSubmit={handleEnroll}
          className="xl:col-span-5 bg-[#111827] border border-slate-800 rounded-lg p-5 space-y-4"
        >
          <div>
            <h2 className="text-sm font-semibold text-slate-100">Enroll Remote Linux Agent (Wazuh Model)</h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Register another Kali, Ubuntu, Debian, or RHEL host to stream its <code className="font-mono text-slate-300">/var/log</code> &amp; FIM hashes here in real time.
            </p>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
            <div>
              <label className="block text-slate-400 mb-1">Hostname</label>
              <input
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="e.g. kali-target-02"
                required
                className="w-full px-3 py-2 font-mono bg-[#0B0F17] border border-slate-700 rounded-md text-slate-100 placeholder-slate-600 focus:outline-none focus:border-sky-500"
              />
            </div>
            <div>
              <label className="block text-slate-400 mb-1">Host IP Address</label>
              <input
                type="text"
                value={ip}
                onChange={(e) => setIp(e.target.value)}
                placeholder="10.14.2.45"
                className="w-full px-3 py-2 font-mono bg-[#0B0F17] border border-slate-700 rounded-md text-slate-100 placeholder-slate-600 focus:outline-none focus:border-sky-500"
              />
            </div>
          </div>

          <div className="text-xs">
            <label className="block text-slate-400 mb-1">Linux Distribution</label>
            <input
              type="text"
              value={os}
              onChange={(e) => setOs(e.target.value)}
              className="w-full px-3 py-2 font-mono bg-[#0B0F17] border border-slate-700 rounded-md text-slate-100 focus:outline-none focus:border-sky-500"
            />
          </div>

          <button
            type="submit"
            disabled={enrolling}
            className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-semibold rounded-md bg-sky-600 hover:bg-sky-500 disabled:opacity-50 text-white transition-colors"
          >
            <Plus className="w-3.5 h-3.5" />
            {enrolling ? 'Generating Token...' : 'Enroll Linux Host'}
          </button>
        </form>

        {/* Agent Deployment One-Liner */}
        <div className="xl:col-span-7 bg-[#111827] border border-slate-800 rounded-lg p-5 flex flex-col justify-between gap-4">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <h2 className="text-sm font-semibold text-slate-100">
                Deploy Agent{deployedAgent ? ` · ${deployedAgent.hostname} (${deployedAgent.id})` : ''}
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Run this command on the target Linux machine to install <code className="font-mono text-slate-300">tamperer-agent.service</code> and stream live logs &amp; tamper alerts.
              </p>
            </div>
            {deployedAgent && (
              <a
                href={`/api/agents/agent.py?agentId=${encodeURIComponent(deployedAgent.id)}&token=${encodeURIComponent(deployedAgent.token)}`}
                download={`tamperer-agent-${deployedAgent.id}.py`}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors whitespace-nowrap"
              >
                <Download className="w-3.5 h-3.5" />
                Download agent.py
              </a>
            )}
          </div>

          {deployedAgent ? (
            <div className="space-y-3">
              <div className="bg-[#080C12] border border-slate-800 rounded-md p-3 font-mono text-xs text-sky-300 break-all">
                {installOneLiner}
              </div>
              <div className="flex flex-wrap items-center justify-between gap-3 text-xs font-mono text-slate-400">
                <span>
                  Agent ID: <strong className="text-slate-200">{deployedAgent.id}</strong> · Token:{' '}
                  <strong className="text-slate-200">{deployedAgent.token}</strong>
                </span>
                <button
                  type="button"
                  onClick={() => void handleCopy()}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-sans font-medium rounded bg-sky-600/20 hover:bg-sky-600/30 text-sky-300 border border-sky-600/50 transition-colors"
                >
                  {copiedCmd ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  {copiedCmd ? 'Copied Command' : 'Copy Install Command'}
                </button>
              </div>
            </div>
          ) : (
            <div className="text-xs text-slate-500">Enroll a remote Linux host on the left to generate its systemd installer &amp; token.</div>
          )}
        </div>
      </div>

      {/* Enrolled Agents Table */}
      <div className="bg-[#111827] border border-slate-800 rounded-lg overflow-hidden">
        <div className="px-4 py-3 bg-[#0E1522] border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2 text-xs font-semibold text-slate-200">
            <Server className="w-4 h-4 text-sky-400" />
            Enrolled Linux Nodes ({agents.length})
          </div>
          <span className="text-xs font-mono text-slate-400">
            Click a host to filter Dashboard, Logs, Alerts &amp; FIM
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="bg-[#0B0F17] border-b border-slate-800 text-slate-400 font-medium">
                <th className="py-2.5 px-4">ID · Hostname</th>
                <th className="py-2.5 px-3">IP · OS</th>
                <th className="py-2.5 px-3">Status</th>
                <th className="py-2.5 px-3 text-right">Files</th>
                <th className="py-2.5 px-3 text-right">Events</th>
                <th className="py-2.5 px-3 text-right">Open Alerts</th>
                <th className="py-2.5 px-3">Last Keepalive</th>
                <th className="py-2.5 px-4 text-right">Controls</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70 font-mono">
              {agents.map((ag) => {
                const isSelected = selectedAgentId === ag.id;
                const statusColor =
                  ag.status === 'active'
                    ? 'text-emerald-400'
                    : ag.status === 'pending'
                      ? 'text-amber-300'
                      : 'text-red-400';
                return (
                  <tr
                    key={ag.id}
                    className={`transition-colors ${isSelected ? 'bg-sky-950/35' : 'hover:bg-slate-800/35'}`}
                  >
                    <td className="py-3 px-4">
                      <button
                        type="button"
                        onClick={() => onSelectAgent(isSelected ? 'ALL' : ag.id)}
                        className="text-left hover:underline"
                      >
                        <div className="text-slate-100 font-semibold font-sans">{ag.hostname}</div>
                        <div className="text-[11px] text-slate-500">
                          {ag.id} {ag.isManager ? '· Local Manager' : ''}
                        </div>
                      </button>
                    </td>
                    <td className="py-3 px-3">
                      <div className="text-slate-300">{ag.ip}</div>
                      <div className="text-[11px] text-slate-500 font-sans truncate max-w-[190px]">{ag.os}</div>
                    </td>
                    <td className={`py-3 px-3 font-sans font-medium ${statusColor}`}>
                      {ag.status === 'active' ? 'Active' : ag.status === 'pending' ? 'Pending' : 'Disconnected'}
                    </td>
                    <td className="py-3 px-3 text-right text-slate-300 tabular-nums">{ag.watchedCount}</td>
                    <td className="py-3 px-3 text-right text-slate-300 tabular-nums">{ag.eventsCount}</td>
                    <td className={`py-3 px-3 text-right tabular-nums font-bold ${ag.openAlerts > 0 ? 'text-red-400' : 'text-slate-400'}`}>
                      {ag.openAlerts}
                    </td>
                    <td className="py-3 px-3 text-slate-400 tabular-nums whitespace-nowrap">{ag.lastKeepAlive}</td>
                    <td className="py-3 px-4 text-right">
                      <div className="inline-flex items-center gap-1.5 font-sans">
                        {!ag.isManager && (
                          <button
                            type="button"
                            onClick={() => setDeployedAgent(ag)}
                            className="px-2 py-1 text-xs rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 whitespace-nowrap"
                            title="Show install command"
                          >
                            Install Cmd
                          </button>
                        )}
                        <button
                          type="button"
                          onClick={() => void onAgentAction(ag.id, 'rebaseline')}
                          className="p-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700"
                          title="Re-baseline agent files"
                        >
                          <RefreshCw className="w-3.5 h-3.5" />
                        </button>
                        {!ag.isManager && (
                          <button
                            type="button"
                            onClick={() => void onAgentAction(ag.id, 'toggle-status')}
                            className="px-2 py-1 text-xs rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 whitespace-nowrap"
                          >
                            {ag.status === 'active' ? 'Disconnect' : 'Reconnect'}
                          </button>
                        )}
                      </div>
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
