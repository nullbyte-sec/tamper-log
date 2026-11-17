import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import type { TamperAlert, TriggerInfo, TriggerUnavailableReason } from '../src/types/tamper.ts';
import type { TamperEngine } from './tamperEngine.ts';

const AUDIT_LOG_PATH = '/var/log/audit/audit.log';
const RING_BUFFER_MAX = 5000;
const POLL_INTERVAL_MS = 2000;
const SLACK_MS = 3000;
const CORRELATION_WINDOW_MS = POLL_INTERVAL_MS + SLACK_MS;
const AUDIT_KEY = 'tamper_watch';
const MAX_AUDIT_RULES = 100;

interface BufferedAuditEvent {
  timestampMs: number;
  path: string;
  pid: number;
  ppid: number;
  uid: number;
  exe: string;
  cwd: string;
  tty: string;
  comm: string;
  argv: string[];
}

export type PreflightStatus =
  | 'ok'
  | 'auditd_missing'
  | 'auditd_not_running'
  | 'rules_not_installed'
  | 'insufficient_privileges';

function parseAuditTimestamp(stamp: string): number {
  const m = stamp.match(/audit\((\d+)\.(\d+):(\d+)\)/);
  if (!m) return 0;
  return Number(m[1]) * 1000 + Math.floor(Number(m[2]) / 1000);
}

function isHex(value: string): boolean {
  return /^[0-9A-Fa-f]+$/.test(value) && value.length % 2 === 0 && value.length > 0;
}

function hexDecode(value: string): string {
  if (!isHex(value)) return value;
  try {
    return Buffer.from(value, 'hex').toString('utf8');
  } catch {
    return value;
  }
}

function extractSerial(line: string): string | null {
  const m = line.match(/audit\(\d+\.\d+:(\d+)\)/);
  return m ? m[1] : null;
}

function parseSyscallFields(line: string, ev: BufferedAuditEvent): void {
  const pid = line.match(/\bpid=(\d+)/);
  if (pid) ev.pid = Number(pid[1]);
  const ppid = line.match(/\bppid=(\d+)/);
  if (ppid) ev.ppid = Number(ppid[1]);
  const uid = line.match(/\buid=(\d+)/);
  if (uid) ev.uid = Number(uid[1]);
  const exe = line.match(/\bexe="([^"]*)"/) ?? line.match(/\bexe=([0-9A-Fa-f]+)/);
  if (exe) ev.exe = hexDecode(exe[1]);
  const comm = line.match(/\bcomm="([^"]*)"/) ?? line.match(/\bcomm=([0-9A-Fa-f]+)/);
  if (comm) ev.comm = hexDecode(comm[1]);
  const tty = line.match(/\btty=([0-9A-Fa-f]+)/);
  if (tty) ev.tty = hexDecode(tty[1]);
  const cwd = line.match(/\bcwd="([^"]*)"/) ?? line.match(/\bcwd=([0-9A-Fa-f]+)/);
  if (cwd) ev.cwd = hexDecode(cwd[1]);
}

function parsePathField(line: string, ev: BufferedAuditEvent): void {
  const name = line.match(/\bname="([^"]*)"/) ?? line.match(/\bname=([0-9A-Fa-f]+)/);
  if (name) ev.path = hexDecode(name[1]);
}

function parseExecveArgs(line: string, ev: BufferedAuditEvent): void {
  const argMatches = line.matchAll(/\ba(\d+)=(?:"([^"]*)"|([0-9A-Fa-f]+))/g);
  for (const m of argMatches) {
    const index = Number(m[1]);
    const value = m[2] !== undefined ? m[2] : hexDecode(m[3]);
    ev.argv[index] = value;
  }
}

export class TriggerCorrelator {
  private readonly engine: TamperEngine;
  private readonly buffer: BufferedAuditEvent[] = [];
  private readonly pending = new Map<string, BufferedAuditEvent>();
  private readonly installedRules = new Set<string>();
  private watcher: fs.FSWatcher | null = null;
  private preflight: PreflightStatus = 'auditd_missing';
  private lastFileOffset = 0;

  constructor(engine: TamperEngine) {
    this.engine = engine;
  }

  public preflightStatus(): PreflightStatus {
    if (!fs.existsSync('/usr/sbin/auditd')) return 'auditd_missing';
    if (typeof process.getuid === 'function' && process.getuid() !== 0) return 'insufficient_privileges';
    try {
      const out = execFileSync('systemctl', ['is-active', 'auditd'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
      if (out !== 'active') return 'auditd_not_running';
    } catch {
      return 'auditd_not_running';
    }
    if (!this.hasOurRules()) return 'rules_not_installed';
    return 'ok';
  }

  private hasOurRules(): boolean {
    try {
      const out = execFileSync('auditctl', ['-l'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
      return out.includes(AUDIT_KEY);
    } catch {
      return false;
    }
  }

  public ensureRules(paths: string[]): string[] {
    const out: string[] = [];
    const status = this.preflightStatus();
    if (status !== 'ok' && status !== 'rules_not_installed') {
      return ['[skip] auditd preflight failed; cannot install rules'];
    }
    const existing = new Set<string>();
    try {
      const raw = execFileSync('auditctl', ['-l'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
      for (const line of raw.split('\n')) {
        const m = line.match(/-w (\S+)/);
        if (m) existing.add(m[1]);
      }
    } catch {
      // ignore
    }
    let count = 0;
    for (const p of paths) {
      if (count >= MAX_AUDIT_RULES) break;
      if (existing.has(p) || this.installedRules.has(p)) continue;
      try {
        execFileSync('auditctl', ['-w', p, '-p', 'w', '-k', AUDIT_KEY], { stdio: 'ignore' });
        this.installedRules.add(p);
        out.push(`[ok] auditctl -w ${p} -p w -k ${AUDIT_KEY}`);
        count += 1;
      } catch {
        out.push(`[skip] could not install rule for ${p}`);
      }
    }
    return out;
  }

  public start(): void {
    this.preflight = this.preflightStatus();
    if (this.preflight !== 'ok') {
      console.warn(`[trigger-correlator] preflight: ${this.preflight}; trigger capture may be unavailable`);
    }
    const baselines = this.engine.getBaselines().map((b) => b.path);
    const candidates = baselines.filter((p) => p.startsWith('/var/log/') && !p.endsWith('.chain'));
    const ruleOutput = this.ensureRules(candidates);
    if (ruleOutput.length > 0) console.log(`[trigger-correlator] ${ruleOutput.length} audit rules ensured`);

    this.loadInitialBuffer();
    this.watchFile();
    this.engine.subscribe((eventName, payload) => {
      if (eventName !== 'alert') return;
      const alert = payload as TamperAlert;
      this.attachTrigger(alert);
    });
  }

  private loadInitialBuffer(): void {
    try {
      if (!fs.existsSync(AUDIT_LOG_PATH)) return;
      const raw = fs.readFileSync(AUDIT_LOG_PATH, 'utf8');
      const lines = raw.split('\n');
      this.lastFileOffset = Buffer.byteLength(raw, 'utf8');
      for (const line of lines) this.ingestLine(line);
      this.flushPending();
    } catch {
      // ignore unreadable audit log
    }
  }

  private watchFile(): void {
    try {
      if (!fs.existsSync(AUDIT_LOG_PATH)) return;
      this.watcher = fs.watch(AUDIT_LOG_PATH, () => {
        try {
          const raw = fs.readFileSync(AUDIT_LOG_PATH, 'utf8');
          const total = Buffer.byteLength(raw, 'utf8');
          if (total < this.lastFileOffset) {
            this.lastFileOffset = 0;
            this.buffer.length = 0;
          }
          const chunk = raw.slice(this.lastFileOffset === 0 ? 0 : this.lastFileOffset);
          this.lastFileOffset = total;
          for (const line of chunk.split('\n')) this.ingestLine(line);
          this.flushPending();
        } catch {
          // ignore transient read errors
        }
      });
    } catch {
      // ignore
    }
  }

  private ingestLine(line: string): void {
    if (!line.includes('type=')) return;
    const serial = extractSerial(line);
    if (!serial) return;
    let ev = this.pending.get(serial);
    if (!ev) {
      ev = { timestampMs: parseAuditTimestamp(line), path: '', pid: 0, ppid: 0, uid: 0, exe: '', cwd: '', tty: '', comm: '', argv: [] };
      this.pending.set(serial, ev);
    }
    if (line.includes('type=SYSCALL')) parseSyscallFields(line, ev);
    if (line.includes('type=PATH')) parsePathField(line, ev);
    if (line.includes('type=EXECVE')) parseExecveArgs(line, ev);
  }

  private flushPending(): void {
    for (const [serial, ev] of this.pending.entries()) {
      if (ev.path && ev.argv.length > 0) {
        this.buffer.push(ev);
        if (this.buffer.length > RING_BUFFER_MAX) this.buffer.shift();
        this.pending.delete(serial);
      }
    }
  }

  public correlateTrigger(targetPath: string, alertEpochMs: number): TriggerInfo | null {
    const windowStart = alertEpochMs - CORRELATION_WINDOW_MS;
    const matches = this.buffer.filter((ev) => ev.path === targetPath && ev.timestampMs >= windowStart && ev.timestampMs <= alertEpochMs);
    if (matches.length === 0) return null;
    const best = matches.reduce((a, b) => (Math.abs(b.timestampMs - alertEpochMs) < Math.abs(a.timestampMs - alertEpochMs) ? b : a));
    return {
      pid: best.pid,
      ppid: best.ppid,
      uid: best.uid,
      exe: best.exe,
      argv: best.argv.filter((a) => a !== undefined),
      cwd: best.cwd,
      tty: best.tty,
      timestamp: new Date(best.timestampMs).toISOString().slice(0, 19),
      source: 'auditd',
      confidence: 'correlated',
      matches: matches.length,
    };
  }

  private attachTrigger(alert: TamperAlert): void {
    if (alert.trigger || alert.triggerUnavailable) return;
    const trigger = this.correlateTrigger(alert.path, alert.epochMs);
    if (trigger) {
      alert.trigger = trigger;
    } else {
      alert.triggerUnavailable = this.preflight === 'ok' ? 'no_event_in_window' : (this.preflight as TriggerUnavailableReason);
    }
  }
}
