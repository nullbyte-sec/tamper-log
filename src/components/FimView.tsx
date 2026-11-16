import React, { useMemo, useState } from 'react';
import { Eye, Lock, RefreshCw, Search, Unlock, X } from 'lucide-react';
import type { BaselineRecord } from '../types/tamper';

interface FimViewProps {
  baselines: BaselineRecord[];
  onHarden: (paths?: string[]) => Promise<void>;
  onUnharden: (paths?: string[]) => Promise<void>;
  onRebaseline: (path: string) => Promise<void>;
}

const CATEGORIES: Array<{ id: 'all' | BaselineRecord['category']; label: string }> = [
  { id: 'all', label: 'All Files' },
  { id: 'system', label: 'System' },
  { id: 'package', label: 'APT / DPKG' },
  { id: 'web', label: 'Apache / Nginx' },
  { id: 'audit', label: 'Auditd' },
  { id: 'binary', label: 'Binary (wtmp/btmp)' },
  { id: 'journal', label: 'Journal' },
  { id: 'history', label: 'Shell History' },
  { id: 'chain', label: 'Hash Chains' },
];

export const FimView: React.FC<FimViewProps> = ({
  baselines,
  onHarden,
  onUnharden,
  onRebaseline,
}) => {
  const [category, setCategory] = useState<'all' | BaselineRecord['category']>('all');
  const [query, setQuery] = useState('');
  const [inspectedPath, setInspectedPath] = useState<string | null>(null);
  const [inspectedData, setInspectedData] = useState<{
    exists: boolean;
    isBinary: boolean;
    content: string;
    size: number;
    sha256: string;
  } | null>(null);
  const [loadingInspect, setLoadingInspect] = useState(false);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return baselines.filter((b) => {
      if (category !== 'all' && b.category !== category) return false;
      if (q && !b.path.toLowerCase().includes(q) && !b.digest.toLowerCase().includes(q)) return false;
      return true;
    });
  }, [baselines, category, query]);

  const inspectFile = async (filePath: string) => {
    setInspectedPath(filePath);
    setLoadingInspect(true);
    try {
      const res = await fetch(`/api/files/content?path=${encodeURIComponent(filePath)}`);
      const data = await res.json();
      setInspectedData(data);
    } catch {
      setInspectedData(null);
    } finally {
      setLoadingInspect(false);
    }
  };

  return (
    <div className="flex flex-col gap-4">
      {/* Toolbar */}
      <div className="bg-[#111827] border border-slate-800 rounded-lg p-4 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-sm font-semibold text-slate-100">File Integrity Baseline Inventory</h2>
            <p className="text-xs text-slate-400 mt-0.5 tabular-nums">
              {baselines.length} watched targets · SHA-256 prefix &amp; rolling chunk verification + inode/mode/uid/gid checks
            </p>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <button
              type="button"
              onClick={() => void onHarden()}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md bg-slate-800 hover:bg-slate-700 text-slate-100 border border-slate-700 transition-colors whitespace-nowrap shrink-0"
            >
              <Lock className="w-3.5 h-3.5 text-sky-400" />
              Harden Core (+a)
            </button>
            <button
              type="button"
              onClick={() => void onUnharden()}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition-colors whitespace-nowrap shrink-0"
            >
              <Unlock className="w-3.5 h-3.5" />
              Unharden All (-a)
            </button>
          </div>
        </div>

        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-1 overflow-x-auto pb-1">
            {CATEGORIES.map((c) => (
              <button
                key={c.id}
                type="button"
                onClick={() => setCategory(c.id)}
                className={`px-2.5 py-1 text-xs font-medium rounded transition-colors whitespace-nowrap shrink-0 ${
                  category === c.id
                    ? 'bg-sky-600/20 text-sky-300 border border-sky-600/60'
                    : 'bg-[#0B0F17] text-slate-400 border border-slate-800 hover:text-slate-200'
                }`}
              >
                {c.label}
              </button>
            ))}
          </div>

          <div className="relative min-w-[220px]">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search path or SHA-256..."
              className="w-full pl-8 pr-3 py-1.5 text-xs font-mono bg-[#0B0F17] border border-slate-800 rounded-md text-slate-100 placeholder-slate-500 focus:outline-none focus:border-sky-500"
            />
          </div>
        </div>
      </div>

      {/* Data Table */}
      <div className="bg-[#111827] border border-slate-800 rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="bg-[#0E1522] border-b border-slate-800 text-slate-400 font-medium">
                <th className="py-2.5 px-4">Path</th>
                <th className="py-2.5 px-3">Integrity</th>
                <th className="py-2.5 px-3 text-right">Size (B)</th>
                <th className="py-2.5 px-3 text-right">Inode</th>
                <th className="py-2.5 px-3">Mode · Owner</th>
                <th className="py-2.5 px-3">Attr</th>
                <th className="py-2.5 px-3">Prefix SHA-256</th>
                <th className="py-2.5 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70 font-mono">
              {filtered.map((b) => {
                const statusColor =
                  b.status === 'tampered' || b.status === 'missing'
                    ? 'text-red-400 font-semibold'
                    : b.status === 'rotated'
                      ? 'text-amber-300'
                      : 'text-emerald-400';
                const statusLabel =
                  b.status === 'tampered'
                    ? 'Tampered'
                    : b.status === 'missing'
                      ? 'Missing'
                      : b.status === 'rotated'
                        ? 'Rotated'
                        : 'Verified';
                return (
                  <tr key={b.path} className="hover:bg-slate-800/35 transition-colors">
                    <td className="py-2.5 px-4 text-slate-200 max-w-[260px] truncate" title={b.path}>
                      {b.path}
                    </td>
                    <td className={`py-2.5 px-3 font-sans ${statusColor}`}>{statusLabel}</td>
                    <td className="py-2.5 px-3 text-right text-slate-300 tabular-nums">{b.size.toLocaleString()}</td>
                    <td className="py-2.5 px-3 text-right text-slate-400 tabular-nums">{b.ino}</td>
                    <td className="py-2.5 px-3 text-slate-400 whitespace-nowrap">
                      {b.modeOctal} · {b.ownerLabel}
                    </td>
                    <td className="py-2.5 px-3 whitespace-nowrap">
                      {b.hardened ? (
                        <span className="text-sky-400 font-semibold">+a</span>
                      ) : b.inplaceOk ? (
                        <span className="text-slate-500">inplace</span>
                      ) : (
                        <span className="text-slate-600">--</span>
                      )}
                    </td>
                    <td className="py-2.5 px-3 text-slate-400">
                      {b.inplaceOk ? '(inplace_ok)' : b.digest ? `${b.digest.slice(0, 16)}…` : '--'}
                    </td>
                    <td className="py-2.5 px-4 text-right">
                      <div className="inline-flex items-center gap-1.5">
                        <button
                          type="button"
                          onClick={() => void inspectFile(b.path)}
                          className="p-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
                          title="Inspect file content"
                        >
                          <Eye className="w-3.5 h-3.5" />
                        </button>
                        <button
                          type="button"
                          onClick={() => void (b.hardened ? onUnharden([b.path]) : onHarden([b.path]))}
                          className="p-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
                          title={b.hardened ? 'Remove chattr +a' : 'Apply chattr +a'}
                        >
                          {b.hardened ? <Unlock className="w-3.5 h-3.5 text-amber-300" /> : <Lock className="w-3.5 h-3.5 text-sky-400" />}
                        </button>
                        <button
                          type="button"
                          onClick={() => void onRebaseline(b.path)}
                          className="p-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
                          title="Re-baseline SHA-256 & stat"
                        >
                          <RefreshCw className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* File Content / Hex Inspector */}
      {inspectedPath && (
        <div className="bg-[#080C12] border border-slate-800 rounded-lg overflow-hidden">
          <div className="flex items-center justify-between px-4 py-2.5 bg-[#0E1522] border-b border-slate-800">
            <div className="flex items-center gap-2 text-xs font-mono">
              <span className="text-slate-100 font-semibold">{inspectedPath}</span>
              {inspectedData && (
                <>
                  <span aria-hidden="true" className="text-slate-600">·</span>
                  <span className="text-slate-400">{inspectedData.size} bytes</span>
                  <span aria-hidden="true" className="text-slate-600">·</span>
                  <span className="text-slate-500">sha256: {inspectedData.sha256.slice(0, 24)}…</span>
                </>
              )}
            </div>
            <button
              type="button"
              onClick={() => setInspectedPath(null)}
              className="text-slate-400 hover:text-slate-200 p-1"
              aria-label="Close inspector"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
          <div className="p-4 max-h-[260px] overflow-auto font-mono text-xs text-slate-300 whitespace-pre-wrap break-all">
            {loadingInspect
              ? 'Reading file from disk...'
              : !inspectedData?.exists
                ? 'File does not exist on disk (deleted or moved).'
                : inspectedData.content || '(empty 0-byte file)'}
          </div>
        </div>
      )}
    </div>
  );
};
