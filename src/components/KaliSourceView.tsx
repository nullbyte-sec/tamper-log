import React, { useEffect, useState } from 'react';
import { Check, Copy, Download } from 'lucide-react';
import type { KaliBundleFile } from '../types/tamper';

export const KaliSourceView: React.FC = () => {
  const [files, setFiles] = useState<KaliBundleFile[]>([]);
  const [selectedName, setSelectedName] = useState<string>('tamper_blocker.py');
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    fetch('/api/bundle/files')
      .then((r) => r.json())
      .then((data) => {
        if (Array.isArray(data?.files)) {
          setFiles(data.files);
          if (data.files.length > 0) setSelectedName(data.files[0].name);
        }
      })
      .catch(() => {});
  }, []);

  const currentFile = files.find((f) => f.name === selectedName) ?? files[0];

  const handleCopy = async () => {
    if (!currentFile) return;
    try {
      await navigator.clipboard.writeText(currentFile.content);
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    } catch {
      // ignore clipboard errors
    }
  };

  return (
    <div className="flex flex-col gap-4">
      {/* Header & Download */}
      <div className="bg-[#111827] border border-slate-800 rounded-lg p-4 flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="text-sm font-semibold text-slate-100">Kali Linux App (tamperer) &amp; Multi-Agent Python Suite</h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Installs <code className="font-mono text-sky-400">tamperer</code> (Burp-style desktop GUI), <code className="font-mono text-sky-400">tamplogs</code> (CLI/TUI), and <code className="font-mono text-sky-400">tamperer-agent.py</code> for remote Linux nodes.
          </p>
        </div>

        <a
          href="/api/bundle/download"
          download="tamperer_kali_suite.tar.gz"
          className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-medium rounded-md bg-sky-600 hover:bg-sky-500 text-white transition-colors whitespace-nowrap shrink-0"
        >
          <Download className="w-3.5 h-3.5" />
          Download tamperer_kali_suite.tar.gz
        </a>
      </div>

      {/* File Selector + Source Viewer */}
      <div className="bg-[#080C12] border border-slate-800 rounded-lg overflow-hidden">
        <div className="flex items-center justify-between gap-3 px-4 py-2.5 bg-[#0E1522] border-b border-slate-800 overflow-x-auto">
          <div className="flex items-center gap-1.5">
            {files.map((f) => (
              <button
                key={f.name}
                type="button"
                onClick={() => setSelectedName(f.name)}
                className={`px-2.5 py-1 text-xs font-mono rounded transition-colors whitespace-nowrap shrink-0 ${
                  f.name === selectedName
                    ? 'bg-sky-600/20 text-sky-300 border border-sky-600/60'
                    : 'text-slate-400 hover:text-slate-200 border border-transparent'
                }`}
              >
                {f.name}
              </button>
            ))}
          </div>

          <button
            type="button"
            onClick={() => void handleCopy()}
            className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors whitespace-nowrap shrink-0"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            {copied ? 'Copied' : 'Copy File'}
          </button>
        </div>

        {currentFile && (
          <>
            <div className="px-4 py-2 bg-[#0B0F17] border-b border-slate-800/80 text-xs text-slate-400 flex flex-wrap items-center gap-2">
              <span className="font-mono text-sky-400">{currentFile.installPath}</span>
              <span aria-hidden="true">·</span>
              <span>{currentFile.description}</span>
            </div>
            <pre className="p-4 overflow-auto max-h-[540px] font-mono text-xs leading-relaxed text-slate-200">
              {currentFile.content}
            </pre>
          </>
        )}
      </div>
    </div>
  );
};
