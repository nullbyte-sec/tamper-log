import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import type { TamperAlert, TriggerInfo, TriggerUnavailableReason } from '../src/types/tamper.ts';
import type { TamperEngine } from './tamperEngine.ts';

const AUDIT_LOG_PATH = '/var/log/audit/audit.log';
const INITIAL_TAIL_BYTES = 2 * 1024 * 1024;
const RING_BUFFER_MAX = 5000;
const PENDING_MAX = 2000;
const PENDING_TTL_MS = 10_000;
const POLL_INTERVAL_MS = 2000;
const SLACK_MS = 3000;
const CORRELATION_WINDOW_MS = POLL_INTERVAL_MS + SLACK_MS;
const AUDIT_KEY = 'tamper_watch';
const MAX_AUDIT_RULES = 100;

interface BufferedAuditEvent {
  timestampMs: number;
  seenAtMs: number;
  path: string;
  pid: number;
  ppid: number;
  uid: number;
  exe: string;
  cwd: string;
  tty: string;
  comm: string;
  argv: string[];
  ready: boolean;
}

export type PreflightStatus =
  | 'ok'
  | 'auditd_missing'
  | 'auditd_not_running'
  | 'rules_not_installed'
  | 'insufficient_privileges';

export function parseAuditTimestamp(stamp: string): number {
  const m = stamp.match(/audit\((\d+)\.(\d+):(\d+)\)/);
  if (!m) return 0;
  const ms = Number(m[2].padEnd(3, '0').slice(0, 3));
  return Number(m[1]) * 1000 + ms;
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
  const tty = line.match(/\btty="([^"]*)"/) ?? line.match(/\btty=([0-9A-Fa-f]+)/);
  if (tty) ev.tty = hexDecode(tty[1]);
  const cwd = line.match(/\bcwd="([^"]*)"/) ?? line.match(/\bcwd=([0-9A-Fa-f]+)/);
  if (cwd) ev.cwd = hexDecode(cwd[1]);
}

function parseCwdField(line: string, ev: BufferedAuditEvent): void {
  const cwd = line.match(/\bcwd="([^"]*)"/) ?? line.match(/\bcwd=([0-9A-Fa-f]+)/);
  if (cwd) ev.cwd = hexDecode(cwd[1]);
}

function parsePathField(line: string, ev: BufferedAuditEvent): void {
  const name = line.match(/\bname="([^"]*)"/) ?? line.match(/\bname=([0-9A-Fa-f]+)/);
  if (name) {
    const decoded = hexDecode(name[1]);
    if (decoded && !decoded.startsWith('/dev/')) {
      ev.path = decoded;
    }
  }
}

function parseExecveArgs(line: string, ev: BufferedAuditEvent): void {
  const argMatches = line.matchAll(/\ba(\d+)=(?:"([^"]*)"|([0-9A-Fa-f]+))/g);
  for (const m of argMatches) {
    const index = Number(m[1]);
    if (index > 128) continue;
    const value = m[2] !== undefined ? m[2] : hexDecode(m[3]);
    ev.argv[index] = value;
  }
}

function parseProctitle(line: string, ev: BufferedAuditEvent): void {
  if (ev.argv.length > 0) return;
  const pt = line.match(/\bproctitle="([^"]*)"/) ?? line.match(/\bproctitle=([0-9A-Fa-f]+)/);
  if (!pt) return;
  const decoded = hexDecode(pt[1]).replace(/\0/g, ' ').trim();
  if (decoded) {
    ev.argv = decoded.split(/\s+/).filter(Boolean);
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
  private partialLine = '';

  constructor(engine: TamperEngine) {
    this.engine = engine;
  }

  public preflightStatus(): PreflightStatus {
    if (!fs.existsSync('/usr/sbin/auditd') && !fs.existsSync('/sbin/auditd')) return 'auditd_missing';
    if (typeof process.getuid === 'function' && process.getuid() !== 0) return 'insufficient_privileges';

    let active = false;
    try {
      const out = execFileSync('systemctl', ['is-active', 'auditd'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
      active = out === 'active';
    } catch {
      active = false;
    }
    if (!active) {
      try {
        const pOut = execFileSync('pgrep', ['-x', 'auditd'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
        active = pOut.length > 0;
      } catch {
        active = false;
      }
    }
    if (!active) return 'auditd_not_running';
    if (!this.hasOurRules()) return 'rules_not_installed';
    return 'ok';
  }

  private hasOurRules(): boolean {
    try {
      const out = execFileSync('auditctl', ['-l'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
      return out.includes(AUDIT_KEY) || out.includes('log_tamper');
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

  private readRange(startOffset: number, endOffset: number): string {
    const length = endOffset - startOffset;
    if (length <= 0) return '';
    const fd = fs.openSync(AUDIT_LOG_PATH, 'r');
    try {
      const buf = Buffer.alloc(length);
      let totalRead = 0;
      while (totalRead < length) {
        const bytes = fs.readSync(fd, buf, totalRead, length - totalRead, startOffset + totalRead);
        if (bytes <= 0) break;
        totalRead += bytes;
      }
      return buf.subarray(0, totalRead).toString('utf8');
    } finally {
      fs.closeSync(fd);
    }
  }

  private processChunk(chunkText: string): void {
    if (!chunkText) return;
    const combined = this.partialLine + chunkText;
    const lines = combined.split('\n');
    this.partialLine = lines.pop() ?? '';
    for (const line of lines) {
      this.ingestLine(line);
    }
    this.flushPending();
  }

  private loadInitialBuffer(): void {
    try {
      if (!fs.existsSync(AUDIT_LOG_PATH)) return;
      const st = fs.statSync(AUDIT_LOG_PATH);
      const start = Math.max(0, st.size - INITIAL_TAIL_BYTES);
      const chunk = this.readRange(start, st.size);
      this.lastFileOffset = st.size;
      const text = start > 0 ? chunk.slice(chunk.indexOf('\n') + 1) : chunk;
      this.processChunk(text);
    } catch {
      // ignore unreadable audit log
    }
  }

  private watchFile(): void {
    try {
      if (!fs.existsSync(AUDIT_LOG_PATH)) return;
      this.watcher = fs.watch(AUDIT_LOG_PATH, () => {
        try {
          const st = fs.statSync(AUDIT_LOG_PATH);
          if (st.size < this.lastFileOffset) {
            this.lastFileOffset = 0;
            this.partialLine = '';
            this.buffer.length = 0;
            this.pending.clear();
          }
          if (st.size === this.lastFileOffset) return;
          const chunk = this.readRange(this.lastFileOffset, st.size);
          this.lastFileOffset = st.size;
          this.processChunk(chunk);
        } catch {
          // ignore transient read errors
        }
      });
    } catch {
      // ignore
    }
  }

  public ingestLine(line: string): void {
    if (!line.includes('type=')) return;
    const serial = extractSerial(line);
    if (!serial) return;
    let ev = this.pending.get(serial);
    if (!ev) {
      if (this.pending.size >= PENDING_MAX) {
        const oldestKey = this.pending.keys().next().value;
        if (oldestKey !== undefined) this.pending.delete(oldestKey);
      }
      ev = {
        timestampMs: parseAuditTimestamp(line),
        seenAtMs: Date.now(),
        path: '',
        pid: 0,
        ppid: 0,
        uid: 0,
        exe: '',
        cwd: '',
        tty: '',
        comm: '',
        argv: [],
        ready: false,
      };
      this.pending.set(serial, ev);
    }
    if (line.includes('type=SYSCALL')) parseSyscallFields(line, ev);
    if (line.includes('type=CWD')) parseCwdField(line, ev);
    if (line.includes('type=PATH')) parsePathField(line, ev);
    if (line.includes('type=EXECVE')) parseExecveArgs(line, ev);
    if (line.includes('type=PROCTITLE')) parseProctitle(line, ev);
    if (line.includes('type=EOE')) ev.ready = true;
  }

  public flushPending(forceReady = false): void {
    const now = Date.now();
    for (const [serial, ev] of this.pending.entries()) {
      const hasActor = ev.pid > 0 || ev.exe.length > 0 || ev.comm.length > 0 || ev.argv.length > 0;
      const shouldFlush = Boolean(ev.path && hasActor && (ev.ready || forceReady || ev.argv.length > 0 || ev.exe.length > 0));
      if (shouldFlush) {
        if (!ev.path.startsWith('/') && ev.cwd) {
          ev.path = path.posix.resolve(ev.cwd, ev.path);
        }
        this.buffer.push(ev);
        if (this.buffer.length > RING_BUFFER_MAX) this.buffer.shift();
        this.pending.delete(serial);
      } else if (now - ev.seenAtMs > PENDING_TTL_MS) {
        this.pending.delete(serial);
      }
    }
  }

  public correlateTrigger(targetPath: string, alertEpochMs: number): TriggerInfo | null {
    const windowStart = alertEpochMs - CORRELATION_WINDOW_MS;
    const windowEnd = alertEpochMs + 1500;
    const resolvedTarget = path.posix.resolve(targetPath);
    const matches = this.buffer.filter(
      (ev) => ev.path === resolvedTarget && ev.timestampMs >= windowStart && ev.timestampMs <= windowEnd,
    );
    if (matches.length === 0) return null;
    const best = matches.reduce((a, b) =>
      Math.abs(b.timestampMs - alertEpochMs) < Math.abs(a.timestampMs - alertEpochMs) ? b : a,
    );
    const argv = best.argv.filter((a) => a !== undefined);
    if (argv.length === 0 && best.comm) {
      argv.push(best.comm);
    }
    return {
      pid: best.pid,
      ppid: best.ppid,
      uid: best.uid,
      exe: best.exe || (best.comm ? best.comm : 'unknown'),
      argv,
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
    this.flushPending(true);
    const trigger = this.correlateTrigger(alert.path, alert.epochMs);
    if (trigger) {
      alert.trigger = trigger;
    } else {
      alert.triggerUnavailable = this.preflight === 'ok' ? 'no_event_in_window' : (this.preflight as TriggerUnavailableReason);
    }
  }
}
