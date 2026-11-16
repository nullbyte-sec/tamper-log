import React, { useCallback, useEffect, useState } from 'react';
import { BarChart3, Clock, List, Play, Search, X } from 'lucide-react';
import type { LogEvent, SplQueryResult } from '../types/tamper';

interface SplunkSearchViewProps {
  initialQuery?: string;
  onPivotToHost: (host: string) => void;
}

const SPL_PRESETS = [
  { label: 'All Events (*)', query: '*' },
  { label: 'Critical Only', query: 'severity=CRIT' },
  { label: 'Tamper Rules Stats', query: 'index=tamper | stats count by rule' },
  { label: 'Events by Host', query: '* | stats count by host' },
  { label: 'Top Targeted Files', query: 'index=tamper | top file' },
  { label: 'Nginx Access Logs', query: '"/var/log/nginx/access.log"' },
  { label: 'Package (dpkg) Logs', query: '"/var/log/dpkg.log"' },
];

export const SplunkSearchView: React.FC<SplunkSearchViewProps> = ({
  initialQuery = '*',
  onPivotToHost,
}) => {
  const [query, setQuery] = useState(initialQuery);
  const [timeRange, setTimeRange] = useState<'15m' | '1h' | '24h' | 'all'>('all');
  const [result, setResult] = useState<SplQueryResult | null>(null);
  const [selectedEvent, setSelectedEvent] = useState<LogEvent | null>(null);
  const [loading, setLoading] = useState(false);

  const executeSpl = useCallback(async (q: string, range: '15m' | '1h' | '24h' | 'all') => {
    setLoading(true);
    try {
      const res = await fetch('/api/spl/query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: q, timeRange: range }),
      });
      if (res.ok) {
        const data = (await res.json()) as SplQueryResult;
        setResult(data);
        if (data.events.length > 0) {
          setSelectedEvent((prev) => (prev && data.events.some((e) => e.id === prev.id) ? prev : data.events[0]));
        } else {
          setSelectedEvent(null);
        }
      }
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    setQuery(initialQuery);
    void executeSpl(initialQuery, timeRange);
  }, [initialQuery, executeSpl, timeRange]);

  const appendFieldFilter = (field: string, value: string) => {
    const cleanVal = value.includes(' ') || value.includes('/') ? `"${value}"` : value;
    const token = `${field}=${cleanVal}`;
    const [base, ...pipes] = query.split('|');
    const trimmedBase = base.trim();
    const nextBase = !trimmedBase || trimmedBase === '*' ? token : `${trimmedBase} ${token}`;
    const nextQuery = pipes.length > 0 ? `${nextBase} | ${pipes.join(' | ')}` : nextBase;
    setQuery(nextQuery);
    void executeSpl(nextQuery, timeRange);
  };

  const maxBucket = Math.max(1, ...(result?.timeline.map((b) => b.total) ?? [1]));

  return (
    <div className="flex flex-col gap-4">
      {/* SPL Query Bar */}
      <div className="bg-[#111827] border border-slate-800 rounded-lg p-4 space-y-3">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void executeSpl(query, timeRange);
          }}
          className="flex flex-wrap items-center gap-2"
        >
          <div className="relative flex-1 min-w-[260px]">
            <Search className="w-4 h-4 text-sky-400 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder='SPL Query: e.g. file=/var/log/nginx/access.log | stats count by severity'
              className="w-full pl-9 pr-8 py-2 text-xs font-mono bg-[#080C12] border border-slate-700 rounded-md text-slate-100 placeholder-slate-500 focus:outline-none focus:border-sky-500"
            />
            {query !== '*' && (
              <button
                type="button"
                onClick={() => {
                  setQuery('*');
                  void executeSpl('*', timeRange);
                }}
                aria-label="Reset query"
                className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-200"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            )}
          </div>

          <div className="flex items-center gap-1.5 bg-[#080C12] border border-slate-700 rounded-md px-2.5 py-1.5 text-xs">
            <Clock className="w-3.5 h-3.5 text-slate-400" />
            <select
              value={timeRange}
              onChange={(e) => setTimeRange(e.target.value as '15m' | '1h' | '24h' | 'all')}
              className="bg-transparent text-slate-200 font-mono focus:outline-none"
            >
              <option value="15m" className="bg-[#0E1522]">Last 15m</option>
              <option value="1h" className="bg-[#0E1522]">Last 1h</option>
              <option value="24h" className="bg-[#0E1522]">Last 24h</option>
              <option value="all" className="bg-[#0E1522]">All Time</option>
            </select>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-semibold rounded-md bg-sky-600 hover:bg-sky-500 disabled:opacity-50 text-white transition-colors whitespace-nowrap shrink-0"
          >
            <Play className="w-3.5 h-3.5" />
            {loading ? 'Searching...' : 'Search'}
          </button>
        </form>

        <div className="flex flex-wrap items-center gap-2 text-xs">
          <span className="text-slate-500">Quick SPL:</span>
          {SPL_PRESETS.map((p) => (
            <button
              key={p.label}
              type="button"
              onClick={() => {
                setQuery(p.query);
                void executeSpl(p.query, timeRange);
              }}
              className="px-2.5 py-1 font-mono rounded bg-[#0B0F17] hover:bg-slate-800 text-slate-300 border border-slate-800 transition-colors whitespace-nowrap"
            >
              {p.label}
            </button>
          ))}
        </div>
      </div>

      {/* Main Split: Left Interesting Fields Sidebar + Right Timeline & Results */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Interesting Fields Sidebar (Splunk-style) */}
        <aside className="lg:col-span-3 bg-[#111827] border border-slate-800 rounded-lg p-3.5 space-y-4 max-h-[680px] overflow-y-auto">
          <div className="flex items-center justify-between border-b border-slate-800 pb-2">
            <h3 className="text-xs font-semibold text-slate-200">Interesting Fields</h3>
            <span className="text-[11px] font-mono text-slate-500 tabular-nums">
              {result ? `${result.totalMatched} hits` : '—'}
            </span>
          </div>

          {result?.facets.map((facet) => (
            <div key={facet.field} className="space-y-1.5">
              <div className="text-xs font-mono font-semibold text-sky-400">{facet.field}</div>
              <div className="space-y-0.5">
                {facet.values.map((v) => (
                  <button
                    key={`${facet.field}-${v.value}`}
                    type="button"
                    onClick={() => appendFieldFilter(facet.field, v.value)}
                    className="w-full flex items-center justify-between gap-2 px-2 py-1 text-xs font-mono rounded hover:bg-slate-800/70 text-left transition-colors"
                    title={`Filter by ${facet.field}=${v.value}`}
                  >
                    <span className="text-slate-300 truncate">{v.value}</span>
                    <span className="text-slate-500 tabular-nums shrink-0">{v.count}</span>
                  </button>
                ))}
              </div>
            </div>
          ))}
        </aside>

        {/* Right: Histogram + Stats / Events + Burp-style Event Inspector */}
        <div className="lg:col-span-9 flex flex-col gap-4 min-w-0">
          {/* Timeline Histogram */}
          <div className="bg-[#111827] border border-slate-800 rounded-lg p-4">
            <div className="flex items-center justify-between text-xs mb-2">
              <span className="font-semibold text-slate-200">Event Distribution Histogram</span>
              <span className="font-mono text-slate-400 tabular-nums">
                {result ? `${result.totalMatched} matched in ${result.executionMs} ms` : 'Loading...'}
              </span>
            </div>
            <div className="h-20 flex items-end gap-1.5 border-b border-slate-800 pb-1">
              {result?.timeline.map((b, i) => {
                const infoH = Math.round((b.info / maxBucket) * 64);
                const warnH = Math.round((b.warn / maxBucket) * 64);
                const critH = Math.round((b.crit / maxBucket) * 64);
                return (
                  <div
                    key={`${b.label}-${i}`}
                    className="flex-1 flex flex-col items-center justify-end"
                    title={`${b.label}: ${b.total} total (${b.crit} CRIT, ${b.warn} WARN)`}
                  >
                    <div className="w-full max-w-[36px] flex flex-col-reverse rounded-t overflow-hidden">
                      {b.info > 0 && <div style={{ height: `${Math.max(2, infoH)}px` }} className="bg-sky-600/80" />}
                      {b.warn > 0 && <div style={{ height: `${Math.max(3, warnH)}px` }} className="bg-amber-500" />}
                      {b.crit > 0 && <div style={{ height: `${Math.max(4, critH)}px` }} className="bg-red-500" />}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Statistics Table when | stats or | top is active */}
          {result?.statsRows && (
            <div className="bg-[#111827] border border-slate-800 rounded-lg overflow-hidden">
              <div className="px-4 py-2.5 bg-[#0E1522] border-b border-slate-800 flex items-center gap-2 text-xs font-semibold text-slate-200">
                <BarChart3 className="w-3.5 h-3.5 text-sky-400" />
                Statistics Aggregation ({result.statsRows.length} groups)
              </div>
              <table className="w-full text-left border-collapse text-xs font-mono">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400">
                    {result.statsColumns.map((col) => (
                      <th key={col} className="py-2 px-4">{col}</th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/70">
                  {result.statsRows.map((row, idx) => (
                    <tr key={idx} className="hover:bg-slate-800/40">
                      {result.statsColumns.map((col) => (
                        <td key={col} className="py-2 px-4 text-slate-200 tabular-nums">
                          {String(row[col] ?? '')}
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* Events Table */}
          <div className="bg-[#080C12] border border-slate-800 rounded-lg overflow-hidden">
            <div className="px-4 py-2.5 bg-[#0E1522] border-b border-slate-800 flex items-center justify-between text-xs">
              <span className="inline-flex items-center gap-2 font-semibold text-slate-200">
                <List className="w-3.5 h-3.5 text-sky-400" />
                Matched Log Events (click row to inspect)
              </span>
              <span className="font-mono text-slate-400 tabular-nums">{result?.events.length ?? 0} shown</span>
            </div>
            <div className="max-h-[300px] overflow-auto divide-y divide-slate-800/50 font-mono text-xs">
              {!result || result.events.length === 0 ? (
                <div className="p-8 text-center text-slate-400 font-sans">
                  No events matched query <code className="font-mono text-sky-400">{query}</code>.
                </div>
              ) : (
                result.events.map((ev) => {
                  const isSel = selectedEvent?.id === ev.id;
                  const sevCls = ev.severity === 'CRIT' ? 'text-red-400 font-bold' : ev.severity === 'WARN' ? 'text-amber-300 font-semibold' : 'text-slate-300';
                  return (
                    <div
                      key={ev.id}
                      onClick={() => setSelectedEvent(ev)}
                      className={`grid grid-cols-[72px_120px_54px_190px_1fr] gap-2 px-4 py-2 cursor-pointer transition-colors ${
                        isSel ? 'bg-sky-950/50' : ev.isTamper ? 'bg-red-950/20 hover:bg-red-950/35' : 'hover:bg-slate-900/60'
                      }`}
                    >
                      <span className="text-slate-500 tabular-nums">{ev.timeShort}</span>
                      <span className="text-sky-400 truncate">{ev.host}</span>
                      <span className={sevCls}>[{ev.severity}]</span>
                      <span className="text-slate-400 truncate">{ev.file}</span>
                      <span className="text-slate-200 truncate">{ev.message}</span>
                    </div>
                  );
                })
              )}
            </div>
          </div>

          {/* Burp Suite-style Bottom Detail Inspector */}
          {selectedEvent && (
            <div className="bg-[#111827] border border-slate-800 rounded-lg p-4 space-y-2.5">
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-2">
                <div className="text-xs font-semibold text-slate-200">
                  Event Inspector · {selectedEvent.host} · {selectedEvent.ts}
                </div>
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={() => appendFieldFilter('host', selectedEvent.host)}
                    className="px-2.5 py-1 text-xs font-mono rounded bg-slate-800 hover:bg-slate-700 text-sky-300 transition-colors"
                  >
                    Filter host={selectedEvent.host}
                  </button>
                  <button
                    type="button"
                    onClick={() => onPivotToHost(selectedEvent.agentId)}
                    className="px-2.5 py-1 text-xs font-medium rounded bg-sky-600/20 hover:bg-sky-600/30 text-sky-300 border border-sky-600/50 transition-colors"
                  >
                    Scope Workbench to Host
                  </button>
                </div>
              </div>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
                <div><span className="text-slate-500">host:</span> <span className="text-slate-200">{selectedEvent.host}</span></div>
                <div><span className="text-slate-500">user:</span> <span className="text-slate-200">{selectedEvent.user}</span></div>
                <div><span className="text-slate-500">source:</span> <span className="text-slate-200">{selectedEvent.source}</span></div>
                <div><span className="text-slate-500">rule:</span> <span className="text-red-300">{selectedEvent.ruleKind || 'NORMAL_APPEND'}</span></div>
              </div>
              <pre className="p-3 bg-[#080C12] border border-slate-800 rounded font-mono text-xs text-slate-200 whitespace-pre-wrap break-all">
                {selectedEvent.message}
              </pre>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
