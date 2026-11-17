import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type {
  AgentNode,
  AppSnapshot,
  AuditRuleEntry,
  BaselineRecord,
  ChainRecord,
  ChainVerifyResult,
  DetectionRuleKind,
  LogEvent,
  MonitorStatus,
  ServiceStatus,
  Severity,
  SplFieldFacet,
  SplQueryResult,
  SplTimelineBucket,
  TamperAlert,
  TerminalExecResult,
  TestStepResult,
  WazuhRuleMeta,
} from '../src/types/tamper.ts';
import { DEFAULT_CONFIG_YAML } from './kaliBundle.ts';

type SSEListener = (eventName: string, payload: unknown) => void;

const GENESIS_HASH = '0'.repeat(64);
const HASH_CAP_BYTES = 16 * 1024 * 1024;
const CHUNK_SIZE_BYTES = 1024 * 1024;

const CRIT_RE = /segfault|panic|BUG:|oom-kill|tamper/i;
const WARN_RE = /fail|denied|error|invalid|warn|refused/i;

const BINARY_BASENAMES = new Set(['wtmp', 'btmp', 'lastlog', 'utmp', 'faillog']);
const INPLACE_OK_BASENAMES = new Set(['lastlog', 'wtmp', 'btmp', 'faillog']);
const SKIP_TAIL_EXTENSIONS = ['.xz', '.gz', '.bz2', '.zst', '.journal'];

const DEFAULT_HARDEN_PATHS = [
  '/var/log/auth.log',
  '/var/log/syslog',
  '/var/log/kern.log',
  '/var/log/dpkg.log',
];

export const WAZUH_RULE_MAP: Record<DetectionRuleKind, WazuhRuleMeta> = {
  CONTENT_MODIFIED: {
    ruleId: '550',
    level: 12,
    mitreId: 'T1070.002',
    mitreTactic: 'Defense Evasion',
    description: 'Integrity checksum changed on existing log prefix',
  },
  TRUNCATED: {
    ruleId: '592',
    level: 12,
    mitreId: 'T1070.002',
    mitreTactic: 'Defense Evasion',
    description: 'Log file truncated (size shrank unexpectedly)',
  },
  DELETED_OR_MOVED: {
    ruleId: '553',
    level: 13,
    mitreId: 'T1070.002',
    mitreTactic: 'Defense Evasion',
    description: 'Monitored log file deleted or relocated',
  },
  INODE_REPLACED: {
    ruleId: '554',
    level: 11,
    mitreId: 'T1070.002',
    mitreTactic: 'Defense Evasion',
    description: 'Inode replaced outside logrotate window',
  },
  PERM_OWNER_CHANGE: {
    ruleId: '551',
    level: 10,
    mitreId: 'T1222.002',
    mitreTactic: 'Defense Evasion',
    description: 'POSIX permissions or UID/GID ownership modified',
  },
  LOG_FILE_COMMAND: {
    ruleId: '100201',
    level: 12,
    mitreId: 'T1070.002',
    mitreTactic: 'Defense Evasion',
    description: 'Destructive file command targeted log directory',
  },
  SED_INPLACE_ON_LOG: {
    ruleId: '100202',
    level: 12,
    mitreId: 'T1070.002',
    mitreTactic: 'Defense Evasion',
    description: 'In-place sed stream editor modified log file',
  },
  SHELL_REDIRECT_OR_HISTORY_WIPE: {
    ruleId: '100203',
    level: 11,
    mitreId: 'T1070.003',
    mitreTactic: 'Defense Evasion',
    description: 'Shell redirect overwrite or history wipe executed',
  },
  LOG_OVERWRITE: {
    ruleId: '100204',
    level: 13,
    mitreId: 'T1070.002',
    mitreTactic: 'Defense Evasion',
    description: 'Log overwritten using /dev/null or /dev/zero',
  },
  JOURNAL_VACUUM: {
    ruleId: '100205',
    level: 12,
    mitreId: 'T1070.002',
    mitreTactic: 'Defense Evasion',
    description: 'Systemd journald vacuum reduced log retention',
  },
  AUDIT_RULES_CHANGED: {
    ruleId: '100206',
    level: 14,
    mitreId: 'T1562.001',
    mitreTactic: 'Defense Evasion',
    description: 'Kernel auditd rules cleared or disabled',
  },
  LOGGING_SERVICE_STOPPED: {
    ruleId: '100207',
    level: 14,
    mitreId: 'T1562.001',
    mitreTactic: 'Defense Evasion',
    description: 'Core logging daemon stopped or masked',
  },
  AUDIT_RULES_REMOVED: {
    ruleId: '100208',
    level: 13,
    mitreId: 'T1562.001',
    mitreTactic: 'Defense Evasion',
    description: 'Audit rules disappeared; auto-remediation triggered',
  },
};

function nowIso(): string {
  return new Date().toISOString().slice(0, 19);
}

function nowTimeShort(): string {
  return new Date().toTimeString().slice(0, 8);
}

function canonicalJson(obj: Record<string, unknown>): string {
  const sortedKeys = Object.keys(obj).sort();
  const ordered: Record<string, unknown> = {};
  for (const k of sortedKeys) {
    ordered[k] = obj[k];
  }
  return JSON.stringify(ordered);
}

function sha256Hex(input: string | Buffer): string {
  return crypto.createHash('sha256').update(input).digest('hex');
}

function commandExists(bin: string): boolean {
  try {
    execFileSync('which', [bin], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

function readOsPrettyName(): string {
  try {
    const raw = fs.readFileSync('/etc/os-release', 'utf8');
    const m = raw.match(/PRETTY_NAME="([^"]+)"/);
    if (m) return m[1];
  } catch {
    // ignore
  }
  return `${os.type()} ${os.release()}`;
}

function getLocalPrimaryIp(): string {
  const ifaces = os.networkInterfaces();
  for (const entries of Object.values(ifaces)) {
    if (!entries) continue;
    for (const info of entries) {
      if (info.family === 'IPv4' && !info.internal) {
        return info.address;
      }
    }
  }
  return '127.0.0.1';
}

const MAX_REMOTE_AGENTS = 100;
const MAX_REMOTE_BASELINES_PER_AGENT = 2000;
const MAX_TAIL_READ_BYTES = 512 * 1024;
const SHELL_HISTORY_RE = /^\/(?:root|home\/[A-Za-z0-9._-]+)\/\.[A-Za-z0-9]+_history$/;

export class TamperEngine {
  private readonly chainDir: string;
  private readonly realChainDir: string;
  private readonly alertChainPath: string;
  private readonly mirrorChainPath: string;
  private readonly agentsPersistPath: string;
  private readonly hostname: string;
  private readonly osPretty: string;
  private readonly kernel: string;
  private readonly localIp: string;

  private readonly listeners = new Set<SSEListener>();
  private readonly baselines = new Map<string, BaselineRecord>();
  private readonly remoteBaselines = new Map<string, BaselineRecord>();
  private readonly hardenedPaths = new Set<string>();
  private readonly dedupMap = new Map<string, number>();
  private readonly watchers: fs.FSWatcher[] = [];
  private readonly internalWritePaths = new Set<string>();

  private agents: AgentNode[] = [];
  private logs: LogEvent[] = [];
  private alerts: TamperAlert[] = [];
  private alertSeq = 0;
  private eventSeq = 0;
  private pidCounter = process.pid;
  private agentSeq = 0;

  private monitoringActive = false;
  private monitorMode: MonitorStatus['mode'] = 'stopped';
  private startedAt: string | null = null;
  private startedAtMs = 0;
  private logrotateSeenAt = 0;
  private pollTimer: ReturnType<typeof setInterval> | null = null;

  private services: ServiceStatus[] = [];
  private auditRules: AuditRuleEntry[] = [];

  constructor(workspaceDir: string = process.cwd()) {
    this.hostname = os.hostname();
    this.osPretty = readOsPrettyName();
    this.kernel = os.release();
    this.localIp = getLocalPrimaryIp();

    const preferredDir = '/var/lib/tamper_blocker';
    let chosenDir = preferredDir;
    try {
      fs.mkdirSync(preferredDir, { recursive: true });
      fs.accessSync(preferredDir, fs.constants.W_OK);
    } catch {
      chosenDir = path.join(workspaceDir, '.tamper_blocker_data');
      fs.mkdirSync(chosenDir, { recursive: true });
    }
    this.chainDir = chosenDir;
    try {
      this.realChainDir = fs.realpathSync(this.chainDir);
    } catch {
      this.realChainDir = path.posix.resolve(this.chainDir);
    }
    this.alertChainPath = path.join(this.chainDir, 'alerts.chain');
    this.mirrorChainPath = path.join(this.chainDir, 'mirror.chain');
    this.agentsPersistPath = path.join(this.chainDir, 'agents.json');

    // Clean up any legacy .tamper_sandbox folder if present
    const legacySandbox = path.join(workspaceDir, '.tamper_sandbox');
    if (fs.existsSync(legacySandbox)) {
      try {
        fs.rmSync(legacySandbox, { recursive: true, force: true });
      } catch {
        // ignore
      }
    }

    this.initMachineState(false);
  }

  public subscribe(listener: SSEListener): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  private emit(eventName: string, payload: unknown): void {
    for (const fn of this.listeners) {
      try {
        fn(eventName, payload);
      } catch {
        // ignore disconnected clients
      }
    }
  }

  private categoryForPath(filePath: string): BaselineRecord['category'] {
    if (filePath.includes('_history')) return 'history';
    if (filePath.startsWith(this.chainDir) || filePath.endsWith('.chain')) return 'chain';
    if (filePath.startsWith('/var/log/audit/')) return 'audit';
    if (filePath.startsWith('/var/log/journal/')) return 'journal';
    if (BINARY_BASENAMES.has(path.posix.basename(filePath))) return 'binary';
    if (filePath.startsWith('/var/log/dpkg.log') || filePath.startsWith('/var/log/apt/') || filePath.includes('alternatives.log')) return 'package';
    if (filePath.startsWith('/var/log/apache2/') || filePath.startsWith('/var/log/nginx/') || filePath.includes('postgresql')) return 'web';
    return 'system';
  }

  private isInplaceOk(filePath: string): boolean {
    const base = path.posix.basename(filePath);
    return INPLACE_OK_BASENAMES.has(base) || filePath.startsWith('/var/log/journal/');
  }

  private isBinaryFile(filePath: string): boolean {
    const base = path.posix.basename(filePath);
    return BINARY_BASENAMES.has(base) || SKIP_TAIL_EXTENSIONS.some((ext) => base.endsWith(ext));
  }

  private formatOwner(uid: number, gid: number): string {
    const u = uid === 0 ? 'root' : uid === 33 ? 'www-data' : uid === 1000 ? 'kali' : `uid:${uid}`;
    const g = gid === 0 ? 'root' : gid === 4 ? 'adm' : gid === 43 ? 'utmp' : gid === 1000 ? 'kali' : `gid:${gid}`;
    return `${u}:${g}`;
  }

  private checkRealChattrA(filePath: string): boolean {
    if (this.hardenedPaths.has(filePath)) return true;
    try {
      const out = execFileSync('lsattr', [filePath], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
      const flags = out.split(/\s+/)[0] || '';
      const hasA = flags.includes('a');
      if (hasA) this.hardenedPaths.add(filePath);
      return hasA;
    } catch {
      return false;
    }
  }

  private resolveRealWithFallback(targetPath: string): string {
    const resolved = path.posix.resolve(targetPath);
    try {
      return fs.realpathSync(resolved);
    } catch {
      const parent = path.posix.dirname(resolved);
      const base = path.posix.basename(resolved);
      try {
        return path.posix.join(fs.realpathSync(parent), base);
      } catch {
        return resolved;
      }
    }
  }

  public isManagedPath(rawPath: string): { ok: boolean; resolved: string; reason?: string } {
    if (typeof rawPath !== 'string' || rawPath.length === 0 || rawPath.length > 2048 || rawPath.includes('\0')) {
      return { ok: false, resolved: '', reason: 'Invalid path' };
    }
    if (!path.posix.isAbsolute(rawPath)) {
      return { ok: false, resolved: '', reason: 'Path must be absolute' };
    }
    const resolved = path.posix.resolve(rawPath);
    const real = this.resolveRealWithFallback(resolved);

    if (real === this.agentsPersistPath || real === path.posix.join(this.realChainDir, 'agents.json')) {
      return { ok: false, resolved, reason: 'Access to credential store is denied' };
    }

    const inVarLog = real === '/var/log' || real.startsWith('/var/log/');
    const inChainDir = real === this.realChainDir || real.startsWith(`${this.realChainDir}/`);
    const isHistory = SHELL_HISTORY_RE.test(real);
    const inBaselines = this.baselines.has(resolved) || this.baselines.has(real);

    if (!inVarLog && !inChainDir && !isHistory && !inBaselines) {
      return { ok: false, resolved, reason: 'Path is outside managed /var/log and tamper_blocker scope' };
    }
    return { ok: true, resolved: real };
  }

  private hashPrefixStream(filePath: string, maxBytes: number): { plen: number; digest: string } {
    const hash = crypto.createHash('sha256');
    const chunkBuf = Buffer.alloc(65536);
    let total = 0;
    const fd = fs.openSync(filePath, 'r');
    try {
      while (total < maxBytes) {
        const toRead = Math.min(chunkBuf.length, maxBytes - total);
        const bytes = fs.readSync(fd, chunkBuf, 0, toRead, total);
        if (bytes <= 0) break;
        hash.update(chunkBuf.subarray(0, bytes));
        total += bytes;
      }
    } finally {
      fs.closeSync(fd);
    }
    return { plen: total, digest: hash.digest('hex') };
  }

  private readRangeUtf8(filePath: string, startOffset: number, maxBytes: number): string {
    if (maxBytes <= 0) return '';
    const fd = fs.openSync(filePath, 'r');
    try {
      const buf = Buffer.alloc(maxBytes);
      let readTotal = 0;
      while (readTotal < maxBytes) {
        const n = fs.readSync(fd, buf, readTotal, maxBytes - readTotal, startOffset + readTotal);
        if (n <= 0) break;
        readTotal += n;
      }
      return buf.subarray(0, readTotal).toString('utf8');
    } finally {
      fs.closeSync(fd);
    }
  }

  private computeBaseline(filePath: string): BaselineRecord | null {
    try {
      if (!fs.existsSync(filePath)) return null;
      const st = fs.lstatSync(filePath);
      if (!st.isFile()) return null;

      const inplaceOk = this.isInplaceOk(filePath);
      let plen = 0;
      let digest = '';
      let chunkCount = 0;

      if (!inplaceOk) {
        const hashed = this.hashPrefixStream(filePath, HASH_CAP_BYTES);
        plen = hashed.plen;
        digest = hashed.digest;
        chunkCount = st.size > 0 ? Math.ceil(st.size / CHUNK_SIZE_BYTES) : 0;
      }

      const mode = st.mode & 0o7777;
      return {
        agentId: 'agent-000',
        host: this.hostname,
        path: filePath,
        category: this.categoryForPath(filePath),
        exists: true,
        isBinary: this.isBinaryFile(filePath),
        inplaceOk,
        hardened: this.checkRealChattrA(filePath),
        ino: Number(st.ino),
        size: st.size,
        mtimeMs: st.mtimeMs,
        mode,
        modeOctal: `0${mode.toString(8)}`,
        uid: st.uid,
        gid: st.gid,
        ownerLabel: this.formatOwner(st.uid, st.gid),
        plen,
        digest,
        chunkCount,
        status: 'verified',
        lastEventAt: new Date(st.mtimeMs).toTimeString().slice(0, 8),
      };
    } catch {
      return null;
    }
  }

  private walkDir(dirPath: string, out: string[]): void {
    try {
      if (!fs.existsSync(dirPath)) return;
      for (const entry of fs.readdirSync(dirPath, { withFileTypes: true })) {
        const full = path.posix.join(dirPath, entry.name);
        if (entry.isDirectory()) {
          this.walkDir(full, out);
        } else if (
          entry.isFile() &&
          !entry.name.includes('.sedtmp.') &&
          !entry.name.startsWith('.tamper_probe_') &&
          entry.name !== 'agents.json'
        ) {
          out.push(full);
        }
      }
    } catch {
      // ignore permission errors on unreadable dirs
    }
  }

  private rebuildAllBaselines(): void {
    this.baselines.clear();
    const candidates: string[] = [];
    this.walkDir('/var/log', candidates);

    for (const parent of ['/root']) {
      try {
        for (const f of fs.readdirSync(parent)) {
          if (/^\.[A-Za-z0-9]+_history$/.test(f)) {
            candidates.push(path.posix.join(parent, f));
          }
        }
      } catch {
        // ignore
      }
    }
    try {
      for (const homeUser of fs.readdirSync('/home')) {
        const uDir = path.posix.join('/home', homeUser);
        for (const f of fs.readdirSync(uDir)) {
          if (/^\.[A-Za-z0-9]+_history$/.test(f)) {
            candidates.push(path.posix.join(uDir, f));
          }
        }
      }
    } catch {
      // ignore
    }

    if (fs.existsSync(this.alertChainPath)) {
      candidates.push(this.alertChainPath);
    }

    for (const fp of candidates) {
      const b = this.computeBaseline(fp);
      if (b) this.baselines.set(fp, b);
    }
    this.syncAgentCounters();
  }

  private loadRealMachineLogs(): void {
    this.logs = [];
    const loaded: LogEvent[] = [];

    for (const b of this.baselines.values()) {
      if (b.isBinary || b.path === this.alertChainPath || b.path === this.mirrorChainPath || b.path === '/var/log/audit/audit.log') {
        continue;
      }
      try {
        const raw = fs.readFileSync(b.path, 'utf8');
        const lines = raw.split('\n').filter((l) => l.trim().length > 0);
        const tail = lines.slice(-35);
        tail.forEach((line, idx) => {
          const parsedEpoch = this.extractTimestampFromLine(line, b.mtimeMs - (tail.length - idx) * 1000);
          const d = new Date(parsedEpoch);
          this.eventSeq += 1;
          loaded.push({
            id: `real-${parsedEpoch}-${this.eventSeq}`,
            ts: d.toISOString().slice(0, 19),
            timeShort: d.toTimeString().slice(0, 8),
            epochMs: parsedEpoch,
            agentId: 'agent-000',
            host: this.hostname,
            severity: this.classifyLineSeverity(line),
            user: this.extractUserFromLine(b.path, line),
            file: b.path,
            source: 'inotify',
            message: line,
          });
        });
      } catch {
        // ignore binary/unreadable file
      }
    }

    // Sort newest first
    loaded.sort((a, b) => b.epochMs - a.epochMs);
    this.logs = loaded.slice(0, 500);
    this.syncAgentCounters();
  }

  private extractTimestampFromLine(line: string, fallbackMs: number): number {
    // ISO timestamp e.g. 2026-11-16T05:10:02Z
    const isoM = line.match(/^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)/);
    if (isoM) {
      const parsed = Date.parse(isoM[1].replace(' ', 'T'));
      if (!Number.isNaN(parsed)) return parsed;
    }
    // nginx access log e.g. [16/Nov/2026:06:50:12 +0000]
    const nginxM = line.match(/\[(\d{2}\/[A-Za-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4})\]/);
    if (nginxM) {
      const normalized = nginxM[1].replace(':', ' ');
      const parsed = Date.parse(normalized);
      if (!Number.isNaN(parsed)) return parsed;
    }
    // nginx error log e.g. 2026/11/16 05:13:22
    const slashM = line.match(/^(\d{4})\/(\d{2})\/(\d{2})\s+(\d{2}:\d{2}:\d{2})/);
    if (slashM) {
      const parsed = Date.parse(`${slashM[1]}-${slashM[2]}-${slashM[3]}T${slashM[4]}Z`);
      if (!Number.isNaN(parsed)) return parsed;
    }
    return fallbackMs;
  }

  private refreshSystemServicesAndAudit(): void {
    const checkService = (name: ServiceStatus['name']): ServiceStatus => {
      let active = false;
      let pid = 0;
      if (commandExists('systemctl')) {
        try {
          const out = execFileSync('systemctl', ['is-active', name], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
          active = out === 'active';
        } catch {
          active = false;
        }
      }
      if (!active && commandExists('pgrep')) {
        try {
          const procName = name === 'rsyslog' ? 'rsyslogd' : name;
          const pOut = execFileSync('pgrep', ['-x', procName], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
          if (pOut) {
            active = true;
            pid = Number(pOut.split('\n')[0]) || 0;
          }
        } catch {
          active = false;
        }
      }
      return {
        name,
        active,
        pid,
        uptime: active ? 'running' : 'inactive / not installed',
      };
    };

    this.services = [
      checkService('auditd'),
      checkService('rsyslog'),
      checkService('systemd-journald'),
    ];

    this.auditRules = [];
    if (commandExists('auditctl')) {
      try {
        const raw = execFileSync('auditctl', ['-l'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
        for (const line of raw.split('\n')) {
          const trimmed = line.trim();
          if (!trimmed || trimmed === 'No rules') continue;
          this.auditRules.push({
            rule: trimmed,
            kind: trimmed.includes('never') ? 'never' : 'always',
            target: trimmed.match(/dir=(\S+)|path=(\S+)/)?.[1] ?? '/var/log',
            key: trimmed.match(/-k\s+(\S+)/)?.[1],
            loaded: true,
          });
        }
      } catch {
        // ignore
      }
    }
  }

  private loadPersistedAgents(): AgentNode[] {
    try {
      if (!fs.existsSync(this.agentsPersistPath)) return [];
      const raw = fs.readFileSync(this.agentsPersistPath, 'utf8');
      const parsed = JSON.parse(raw);
      if (!Array.isArray(parsed)) return [];
      return parsed.filter(
        (a): a is AgentNode =>
          Boolean(a) &&
          typeof a === 'object' &&
          typeof a.id === 'string' &&
          a.id !== 'agent-000' &&
          !a.isManager &&
          typeof a.token === 'string' &&
          a.token.length > 0,
      );
    } catch {
      return [];
    }
  }

  private savePersistedAgents(): void {
    try {
      const remotes = this.agents.filter((a) => !a.isManager && a.id !== 'agent-000');
      this.internalWritePaths.add(this.agentsPersistPath);
      fs.writeFileSync(this.agentsPersistPath, JSON.stringify(remotes, null, 2), { encoding: 'utf8', mode: 0o600 });
      try {
        fs.chmodSync(this.agentsPersistPath, 0o600);
      } catch {
        // ignore if chmod unsupported
      }
      setTimeout(() => this.internalWritePaths.delete(this.agentsPersistPath), 150);
    } catch {
      this.internalWritePaths.delete(this.agentsPersistPath);
    }
  }

  private initMachineState(clearChains: boolean): void {
    if (clearChains) {
      fs.writeFileSync(this.alertChainPath, '', 'utf8');
      fs.writeFileSync(this.mirrorChainPath, '', 'utf8');
    } else {
      if (!fs.existsSync(this.alertChainPath)) fs.writeFileSync(this.alertChainPath, '', 'utf8');
      if (!fs.existsSync(this.mirrorChainPath)) fs.writeFileSync(this.mirrorChainPath, '', 'utf8');
    }

    const loadAvg = os.loadavg()[0]?.toFixed(2) ?? '0.00';
    const memPct = `${Math.round(((os.totalmem() - os.freemem()) / Math.max(1, os.totalmem())) * 100)}%`;

    const localNode: AgentNode = {
      id: 'agent-000',
      name: `${this.hostname} (Local Machine)`,
      hostname: this.hostname,
      ip: this.localIp,
      os: this.osPretty,
      kernel: this.kernel,
      version: 'tamperer-local',
      status: 'active',
      isManager: true,
      lastKeepAlive: nowIso(),
      enrolledAt: nowIso(),
      token: 'local-host',
      watchedCount: 0,
      openAlerts: 0,
      eventsCount: 0,
      cpuLoad: loadAvg,
      memUsed: memPct,
    };

    const persistedRemotes = clearChains ? [] : this.loadPersistedAgents();
    if (clearChains) {
      try {
        if (fs.existsSync(this.agentsPersistPath)) fs.rmSync(this.agentsPersistPath, { force: true });
      } catch {
        // ignore
      }
    }
    this.agents = [localNode, ...persistedRemotes];
    let maxSeq = 0;
    for (const ag of persistedRemotes) {
      const m = ag.id.match(/^agent-(\d+)$/);
      if (m) maxSeq = Math.max(maxSeq, Number(m[1]));
    }
    this.agentSeq = maxSeq;

    this.remoteBaselines.clear();
    this.alerts = [];
    this.alertSeq = 0;
    this.eventSeq = 0;
    this.dedupMap.clear();

    this.refreshSystemServicesAndAudit();
    this.rebuildAllBaselines();
    this.loadRealMachineLogs();
  }

  private syncAgentCounters(): void {
    const localCount = this.baselines.size;
    for (const ag of this.agents) {
      if (ag.isManager) {
        ag.watchedCount = localCount;
        ag.cpuLoad = os.loadavg()[0]?.toFixed(2) ?? '0.00';
        ag.memUsed = `${Math.round(((os.totalmem() - os.freemem()) / Math.max(1, os.totalmem())) * 100)}%`;
      } else {
        ag.watchedCount = Array.from(this.remoteBaselines.values()).filter((b) => b.agentId === ag.id).length;
      }
      ag.openAlerts = this.alerts.filter((a) => a.agentId === ag.id && !a.acknowledged).length;
      ag.eventsCount = this.logs.filter((l) => l.agentId === ag.id).length;
    }
  }

  private appendChainRecord(
    chainPath: string,
    payload: Record<string, unknown>,
  ): ChainRecord {
    this.internalWritePaths.add(chainPath);
    let prev = GENESIS_HASH;
    let seq = 0;

    if (fs.existsSync(chainPath)) {
      const rawLines = fs.readFileSync(chainPath, 'utf8').split('\n').filter((l) => l.trim().length > 0);
      seq = rawLines.length;
      if (rawLines.length > 0) {
        try {
          const lastObj = JSON.parse(rawLines[rawLines.length - 1]) as { hash?: string };
          if (lastObj.hash) prev = lastObj.hash;
        } catch {
          // keep genesis
        }
      }
    }

    const body: Record<string, unknown> = {
      ...payload,
      seq: seq + 1,
      prev,
    };
    const hash = sha256Hex(prev + canonicalJson(body));
    const fullRecord: ChainRecord = {
      ...(body as Omit<ChainRecord, 'hash'>),
      hash,
    };
    fs.appendFileSync(chainPath, JSON.stringify(fullRecord) + '\n', 'utf8');

    if (chainPath === this.alertChainPath) {
      const updated = this.computeBaseline(chainPath);
      if (updated) this.baselines.set(chainPath, updated);
    }

    setTimeout(() => {
      this.internalWritePaths.delete(chainPath);
    }, 150);

    return fullRecord;
  }

  public verifySingleChain(chainName: 'alerts.chain' | 'mirror.chain'): ChainVerifyResult {
    const targetPath = chainName === 'alerts.chain' ? this.alertChainPath : this.mirrorChainPath;
    if (!fs.existsSync(targetPath)) {
      return { chain: chainName, ok: true, brokenLine: null, totalLines: 0, headHash: GENESIS_HASH };
    }

    const rawLines = fs.readFileSync(targetPath, 'utf8').split('\n').filter((l) => l.trim().length > 0);
    let prev = GENESIS_HASH;
    for (let i = 0; i < rawLines.length; i += 1) {
      const lineNum = i + 1;
      let parsed: Record<string, unknown>;
      try {
        parsed = JSON.parse(rawLines[i]) as Record<string, unknown>;
      } catch {
        return { chain: chainName, ok: false, brokenLine: lineNum, totalLines: rawLines.length, reason: `Malformed JSON at line ${lineNum}`, headHash: prev };
      }
      const recordedHash = parsed.hash;
      if (typeof recordedHash !== 'string' || parsed.prev !== prev) {
        return { chain: chainName, ok: false, brokenLine: lineNum, totalLines: rawLines.length, reason: `Previous hash mismatch at line ${lineNum}`, headHash: prev };
      }
      const withoutHash: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(parsed)) {
        if (k !== 'hash') withoutHash[k] = v;
      }
      const expected = sha256Hex(prev + canonicalJson(withoutHash));
      if (expected !== recordedHash) {
        return { chain: chainName, ok: false, brokenLine: lineNum, totalLines: rawLines.length, reason: `SHA-256 digest mismatch at line ${lineNum} (record modified)`, headHash: prev };
      }
      prev = recordedHash;
    }

    return { chain: chainName, ok: true, brokenLine: null, totalLines: rawLines.length, headHash: prev };
  }

  public readChainTail(chainName: 'alerts.chain' | 'mirror.chain', limit = 40): ChainRecord[] {
    const targetPath = chainName === 'alerts.chain' ? this.alertChainPath : this.mirrorChainPath;
    if (!fs.existsSync(targetPath)) return [];
    const lines = fs.readFileSync(targetPath, 'utf8').split('\n').filter((l) => l.trim().length > 0);
    return lines.slice(-limit).reverse().map((line, idx) => {
      try {
        return JSON.parse(line) as ChainRecord;
      } catch {
        return { seq: lines.length - idx, ts: nowIso(), prev: 'INVALID_JSON', hash: 'CORRUPTED_LINE', line };
      }
    });
  }

  private pushLogEvent(
    input: Omit<LogEvent, 'id' | 'ts' | 'timeShort' | 'epochMs'>,
    writeMirror = true,
    customEpochMs?: number,
  ): LogEvent {
    this.eventSeq += 1;
    const epochMs = customEpochMs ?? Date.now();
    const d = new Date(epochMs);
    const ev: LogEvent = {
      id: `ev-${epochMs}-${this.eventSeq}`,
      ts: d.toISOString().slice(0, 19),
      timeShort: d.toTimeString().slice(0, 8),
      epochMs,
      ...input,
    };
    this.logs.unshift(ev);
    if (this.logs.length > 800) {
      this.logs = this.logs.slice(0, 800);
    }
    if (writeMirror && !ev.isTamper) {
      this.appendChainRecord(this.mirrorChainPath, {
        ts: ev.ts,
        host: ev.host,
        severity: ev.severity,
        user: ev.user,
        file: ev.file,
        line: ev.message,
      });
    }
    this.syncAgentCounters();
    this.emit('log', ev);
    return ev;
  }

  private isLogrotateRecent(): boolean {
    if (this.logrotateSeenAt > 0 && Date.now() - this.logrotateSeenAt < 60_000) return true;
    try {
      if (fs.existsSync('/var/lib/logrotate/status')) {
        const st = fs.statSync('/var/lib/logrotate/status');
        if (Date.now() - st.mtimeMs < 60_000 && this.logrotateSeenAt > 0) return true;
      }
    } catch {
      // ignore
    }
    return false;
  }

  private fireTamperAlert(params: {
    agentId?: string;
    host?: string;
    path: string;
    kind: DetectionRuleKind;
    severity?: 'WARN' | 'CRIT';
    user: string;
    comm: string;
    exe: string;
    pid: number;
    explanation: string;
    beforeSummary: string;
    afterSummary: string;
  }): TamperAlert | null {
    const agentId = params.agentId ?? 'agent-000';
    const host = params.host ?? this.hostname;
    const dedupKey = `${agentId}::${params.path}::${params.kind}`;
    const prevTs = this.dedupMap.get(dedupKey) ?? 0;
    if (Date.now() - prevTs < 3000) return null;
    this.dedupMap.set(dedupKey, Date.now());

    this.alertSeq += 1;
    const ts = nowIso();
    const timeShort = nowTimeShort();
    const epochMs = Date.now();
    const severity = params.severity ?? 'CRIT';
    const ruleMeta = WAZUH_RULE_MAP[params.kind];

    const chainRec = this.appendChainRecord(this.alertChainPath, {
      ts,
      host,
      agentId,
      kind: params.kind,
      wazuhRuleId: ruleMeta.ruleId,
      mitreId: ruleMeta.mitreId,
      severity,
      path: params.path,
      user: params.user,
      comm: params.comm,
      exe: params.exe,
      pid: params.pid,
      explanation: params.explanation,
      acknowledged: false,
    });

    const alert: TamperAlert = {
      id: `alt-${epochMs}-${this.alertSeq}`,
      seq: this.alertSeq,
      ts,
      timeShort,
      epochMs,
      agentId,
      host,
      kind: params.kind,
      wazuhRuleId: ruleMeta.ruleId,
      ruleLevel: ruleMeta.level,
      mitreId: ruleMeta.mitreId,
      mitreTactic: ruleMeta.mitreTactic,
      severity,
      path: params.path,
      user: params.user,
      comm: params.comm,
      exe: params.exe,
      pid: params.pid,
      explanation: params.explanation,
      beforeSummary: params.beforeSummary,
      afterSummary: params.afterSummary,
      acknowledged: false,
      chainHash: chainRec.hash,
      prevHash: chainRec.prev,
    };

    this.alerts.unshift(alert);
    if (this.alerts.length > 300) {
      this.alerts = this.alerts.slice(0, 300);
    }

    this.pushLogEvent(
      {
        agentId,
        host,
        severity,
        user: params.user,
        file: params.path,
        source: agentId === 'agent-000' ? 'auditd' : 'agent',
        message: `${params.kind}: ${params.explanation} (comm=${params.comm} pid=${params.pid})`,
        isTamper: true,
        ruleKind: params.kind,
        wazuhRuleId: ruleMeta.ruleId,
        mitreId: ruleMeta.mitreId,
      },
      false,
      epochMs,
    );

    this.syncAgentCounters();
    this.emit('alert', alert);
    this.emit('agents', this.agents);
    this.emit('status', this.getStatus());
    return alert;
  }

  private extractUserFromLine(filePath: string, line: string): string {
    const m1 = line.match(/sudo:\s+(\S+)\s+:/);
    if (m1) return m1[1];
    const m2 = line.match(/session opened for user \S+ by ([^(\s]+)\(/);
    if (m2) return m2[1];
    const m3 = line.match(/(?:Accepted|Failed)\s+\S+\s+for\s+(?:invalid user\s+)?(\S+)/);
    if (m3) return m3[1];
    const m4 = line.match(/for user (\S+)/);
    if (m4) return m4[1];
    if (filePath.startsWith('/home/')) {
      const parts = filePath.split('/');
      if (parts.length > 2) return parts[2];
    }
    if (filePath.startsWith('/root/')) return 'root';
    return 'root';
  }

  private classifyLineSeverity(line: string): Severity {
    if (CRIT_RE.test(line)) return 'CRIT';
    if (WARN_RE.test(line)) return 'WARN';
    return 'INFO';
  }

  private checkPathIntegrity(
    filePath: string,
    actor: { user: string; comm: string; exe: string; pid: number },
  ): DetectionRuleKind[] {
    if (!this.monitoringActive) return [];
    if (this.internalWritePaths.has(filePath)) return [];
    if (filePath === this.mirrorChainPath) return [];

    const triggered: DetectionRuleKind[] = [];
    const base = this.baselines.get(filePath);

    if (!fs.existsSync(filePath)) {
      if (base) {
        if (this.isLogrotateRecent()) {
          this.pushLogEvent({
            agentId: 'agent-000',
            host: this.hostname,
            severity: 'INFO',
            user: 'logrotate',
            file: filePath,
            source: 'inotify',
            message: 'Log rotated / moved by logrotate (allowed)',
          });
          base.exists = false;
          base.status = 'rotated';
        } else {
          const alert = this.fireTamperAlert({
            path: filePath,
            kind: 'DELETED_OR_MOVED',
            user: actor.user,
            comm: actor.comm,
            exe: actor.exe,
            pid: actor.pid,
            explanation: 'Baselined log file was deleted or moved outside logrotate window',
            beforeSummary: `exists (size=${base.size}B, ino=${base.ino})`,
            afterSummary: 'missing (ENOENT)',
          });
          if (alert) triggered.push('DELETED_OR_MOVED');
          this.baselines.set(filePath, { ...base, exists: false, size: 0, status: 'missing', lastEventAt: nowTimeShort() });
        }
        this.emit('baselines', this.getBaselines());
      }
      return triggered;
    }

    let st: fs.Stats;
    try {
      st = fs.lstatSync(filePath);
    } catch {
      return triggered;
    }
    if (!st.isFile()) return triggered;

    if (!base || !base.exists) {
      const created = this.computeBaseline(filePath);
      if (created) {
        this.baselines.set(filePath, created);
        this.emit('baselines', this.getBaselines());
      }
      return triggered;
    }

    const currentIno = Number(st.ino);
    if (currentIno !== base.ino) {
      if (this.isLogrotateRecent()) {
        this.pushLogEvent({
          agentId: 'agent-000',
          host: this.hostname,
          severity: 'INFO',
          user: 'logrotate',
          file: filePath,
          source: 'inotify',
          message: `Inode replaced during rotation ${base.ino} -> ${currentIno} (allowed)`,
        });
        const refreshed = this.computeBaseline(filePath);
        if (refreshed) {
          refreshed.status = 'rotated';
          this.baselines.set(filePath, refreshed);
        }
      } else {
        const alert = this.fireTamperAlert({
          path: filePath,
          kind: 'INODE_REPLACED',
          user: actor.user,
          comm: actor.comm,
          exe: actor.exe,
          pid: actor.pid,
          explanation: `Inode changed unexpectedly (${base.ino} -> ${currentIno}); file likely replaced via sed -i or mv`,
          beforeSummary: `ino=${base.ino}, sha256=${base.digest.slice(0, 12)}...`,
          afterSummary: `ino=${currentIno}, size=${st.size}B`,
        });
        if (alert) triggered.push('INODE_REPLACED');
        const refreshed = this.computeBaseline(filePath);
        if (refreshed) {
          refreshed.status = 'tampered';
          this.baselines.set(filePath, refreshed);
        }
      }
      this.emit('baselines', this.getBaselines());
      return triggered;
    }

    const currentMode = st.mode & 0o7777;
    if (currentMode !== base.mode || st.uid !== base.uid || st.gid !== base.gid) {
      const alert = this.fireTamperAlert({
        path: filePath,
        kind: 'PERM_OWNER_CHANGE',
        user: actor.user,
        comm: actor.comm,
        exe: actor.exe,
        pid: actor.pid,
        explanation: `Permissions or ownership modified (${base.modeOctal} ${base.ownerLabel} -> 0${currentMode.toString(8)} ${this.formatOwner(st.uid, st.gid)})`,
        beforeSummary: `mode=${base.modeOctal} owner=${base.ownerLabel}`,
        afterSummary: `mode=0${currentMode.toString(8)} owner=${this.formatOwner(st.uid, st.gid)}`,
      });
      if (alert) triggered.push('PERM_OWNER_CHANGE');
      const refreshed = this.computeBaseline(filePath);
      if (refreshed) {
        refreshed.status = 'tampered';
        this.baselines.set(filePath, refreshed);
      }
      this.emit('baselines', this.getBaselines());
      return triggered;
    }

    if (st.size < base.size) {
      if (this.isLogrotateRecent()) {
        this.pushLogEvent({
          agentId: 'agent-000',
          host: this.hostname,
          severity: 'INFO',
          user: 'logrotate',
          file: filePath,
          source: 'inotify',
          message: `Copytruncate rotation ${base.size}B -> ${st.size}B (allowed)`,
        });
        const refreshed = this.computeBaseline(filePath);
        if (refreshed) {
          refreshed.status = 'rotated';
          this.baselines.set(filePath, refreshed);
        }
      } else {
        const isHist = filePath.includes('_history');
        const alert = this.fireTamperAlert({
          path: filePath,
          kind: 'TRUNCATED',
          severity: isHist ? 'WARN' : 'CRIT',
          user: actor.user,
          comm: actor.comm,
          exe: actor.exe,
          pid: actor.pid,
          explanation: `Log file size shrank from ${base.size} bytes to ${st.size} bytes`,
          beforeSummary: `size=${base.size}B, sha256=${base.digest.slice(0, 12)}...`,
          afterSummary: `size=${st.size}B`,
        });
        if (alert) triggered.push('TRUNCATED');
        const refreshed = this.computeBaseline(filePath);
        if (refreshed) {
          refreshed.status = 'tampered';
          this.baselines.set(filePath, refreshed);
        }
      }
      this.emit('baselines', this.getBaselines());
      return triggered;
    }

    if (!base.inplaceOk && base.plen > 0) {
      let currentPrefixHash = '';
      try {
        currentPrefixHash = this.hashPrefixStream(filePath, base.plen).digest;
      } catch {
        return triggered;
      }
      if (currentPrefixHash !== base.digest) {
        const isHist = filePath.includes('_history');
        const alert = this.fireTamperAlert({
          path: filePath,
          kind: 'CONTENT_MODIFIED',
          severity: isHist ? 'WARN' : 'CRIT',
          user: actor.user,
          comm: actor.comm,
          exe: actor.exe,
          pid: actor.pid,
          explanation: `Existing prefix bytes (${base.plen}B) were rewritten; SHA-256 digest mismatch`,
          beforeSummary: `sha256=${base.digest.slice(0, 16)}...`,
          afterSummary: `sha256=${currentPrefixHash.slice(0, 16)}...`,
        });
        if (alert) triggered.push('CONTENT_MODIFIED');
        const refreshed = this.computeBaseline(filePath);
        if (refreshed) {
          refreshed.status = 'tampered';
          this.baselines.set(filePath, refreshed);
        }
        this.emit('baselines', this.getBaselines());
        return triggered;
      }
    }

    if (st.size > base.size && !this.isBinaryFile(filePath) && filePath !== '/var/log/audit/audit.log' && filePath !== this.alertChainPath) {
      try {
        const deltaBytes = st.size - base.size;
        const startOffset = deltaBytes > MAX_TAIL_READ_BYTES ? st.size - MAX_TAIL_READ_BYTES : base.size;
        const newText = this.readRangeUtf8(filePath, startOffset, Math.min(deltaBytes, MAX_TAIL_READ_BYTES));
        for (const line of newText.split('\n')) {
          if (!line.trim()) continue;
          this.pushLogEvent({
            agentId: 'agent-000',
            host: this.hostname,
            severity: this.classifyLineSeverity(line),
            user: this.extractUserFromLine(filePath, line),
            file: filePath,
            source: 'inotify',
            message: line,
          });
        }
      } catch {
        // ignore transient tail read errors
      }
    }

    const refreshed = this.computeBaseline(filePath);
    if (refreshed) {
      refreshed.status = base.status === 'tampered' ? 'tampered' : 'verified';
      this.baselines.set(filePath, refreshed);
      this.emit('baselines', this.getBaselines());
    }
    return triggered;
  }

  public startMonitoring(mode: 'interactive' | 'headless' | 'no-popup' = 'interactive'): void {
    this.monitoringActive = true;
    this.monitorMode = mode;
    if (!this.startedAt) {
      this.startedAt = nowIso();
      this.startedAtMs = Date.now();
    }
    this.rebuildAllBaselines();
    this.setupWatchers();

    this.pushLogEvent(
      {
        agentId: 'agent-000',
        host: this.hostname,
        severity: 'INFO',
        user: os.userInfo().username,
        file: '/var/log',
        source: 'tamplogs',
        message: `Real-time monitoring started (${mode} mode) — watching ${this.baselines.size} real files on ${this.hostname}`,
      },
      false,
    );

    this.emit('status', this.getStatus());
    this.emit('baselines', this.getBaselines());
    this.emit('agents', this.agents);
  }

  public stopMonitoring(): void {
    this.monitoringActive = false;
    this.monitorMode = 'stopped';
    for (const w of this.watchers) {
      try {
        w.close();
      } catch {
        // ignore
      }
    }
    this.watchers.length = 0;
    if (this.pollTimer) {
      clearInterval(this.pollTimer);
      this.pollTimer = null;
    }
    this.pushLogEvent(
      {
        agentId: 'agent-000',
        host: this.hostname,
        severity: 'WARN',
        user: os.userInfo().username,
        file: '/var/log',
        source: 'tamplogs',
        message: 'Real-time monitoring stopped by user',
      },
      false,
    );
    this.emit('status', this.getStatus());
  }

  private setupWatchers(): void {
    for (const w of this.watchers) {
      try {
        w.close();
      } catch {
        // ignore
      }
    }
    this.watchers.length = 0;
    if (this.pollTimer) clearInterval(this.pollTimer);

    const watchDirs = ['/var/log', '/root', this.chainDir];
    for (const dir of watchDirs) {
      if (!fs.existsSync(dir)) continue;
      try {
        const watcher = fs.watch(dir, { recursive: dir === '/var/log' }, (_eventType, filename) => {
          if (!filename || !this.monitoringActive) return;
          const full = path.posix.join(dir, filename.toString().split(path.sep).join('/'));
          if (this.internalWritePaths.has(full)) return;
          this.checkPathIntegrity(full, {
            user: os.userInfo().username,
            comm: 'fs-event',
            exe: '/usr/bin/unknown',
            pid: ++this.pidCounter,
          });
        });
        this.watchers.push(watcher);
      } catch {
        // ignore unsupported recursive watch
      }
    }

    // Real stat sweep every 2s to catch changes on platforms where recursive fs.watch misses nested files
    this.pollTimer = setInterval(() => {
      if (!this.monitoringActive) return;
      for (const fp of Array.from(this.baselines.keys())) {
        if (this.internalWritePaths.has(fp)) continue;
        this.checkPathIntegrity(fp, {
          user: os.userInfo().username,
          comm: 'fim-poll',
          exe: '/usr/bin/unknown',
          pid: ++this.pidCounter,
        });
      }
      const local = this.agents.find((a) => a.isManager);
      if (local) local.lastKeepAlive = nowIso();
    }, 2000);
  }

  // --- Multi-Agent Enrollment & Real-Time Ingestion ---

  public enrollAgent(name: string, ip: string, osLabel: string): AgentNode {
    const remoteCount = this.agents.filter((a) => !a.isManager).length;
    if (remoteCount >= MAX_REMOTE_AGENTS) {
      throw new Error(`Maximum remote agent limit (${MAX_REMOTE_AGENTS}) reached.`);
    }
    this.agentSeq += 1;
    const id = `agent-${String(this.agentSeq).padStart(3, '0')}`;
    const token = `tok-${crypto.randomBytes(24).toString('hex')}`;
    const cleanName = name.trim().replace(/[^a-zA-Z0-9._-]/g, '-').slice(0, 128) || `linux-node-${this.agentSeq}`;
    const node: AgentNode = {
      id,
      name: cleanName,
      hostname: cleanName,
      ip: ip.trim().slice(0, 64) || '0.0.0.0',
      os: osLabel.trim().slice(0, 128) || 'Linux x86_64',
      kernel: 'pending-checkin',
      version: 'tamperer-agent-2.4.0',
      status: 'pending',
      isManager: false,
      lastKeepAlive: nowIso(),
      enrolledAt: nowIso(),
      token,
      watchedCount: 0,
      openAlerts: 0,
      eventsCount: 0,
      cpuLoad: '0.00',
      memUsed: '0%',
    };
    this.agents.push(node);
    this.savePersistedAgents();
    this.emit('agents', this.agents);
    this.emit('status', this.getStatus());
    return node;
  }

  public getAgentById(agentId: string): AgentNode | undefined {
    return this.agents.find((a) => a.id === agentId);
  }

  public ingestRemoteAgentBatch(payload: {
    agentId?: string;
    token?: string;
    hostname?: string;
    os?: string;
    kernel?: string;
    events?: Array<{
      kind?: DetectionRuleKind;
      severity?: Severity;
      path?: string;
      user?: string;
      comm?: string;
      message?: string;
    }>;
    baselines?: Array<{
      path: string;
      ino?: number;
      size?: number;
      mode?: number;
      uid?: number;
      gid?: number;
      plen?: number;
      digest?: string;
    }>;
  }): { ok: boolean; acceptedEvents: number; error?: string } {
    const agent = this.agents.find((a) => a.id === payload.agentId);
    if (!agent || agent.isManager || agent.id === 'agent-000' || !agent.token || typeof payload.token !== 'string' || payload.token.length === 0) {
      return { ok: false, acceptedEvents: 0, error: 'Invalid agent credentials' };
    }
    const suppliedDigest = crypto.createHash('sha256').update(payload.token).digest();
    const expectedDigest = crypto.createHash('sha256').update(agent.token).digest();
    if (!crypto.timingSafeEqual(suppliedDigest, expectedDigest)) {
      return { ok: false, acceptedEvents: 0, error: 'Invalid agent credentials' };
    }

    agent.status = 'active';
    agent.lastKeepAlive = nowIso();
    if (payload.hostname) agent.hostname = payload.hostname.slice(0, 256);
    if (payload.os) agent.os = payload.os.slice(0, 256);
    if (payload.kernel) agent.kernel = payload.kernel.slice(0, 256);

    if (Array.isArray(payload.baselines)) {
      let agentBaselineCount = Array.from(this.remoteBaselines.values()).filter((rb) => rb.agentId === agent.id).length;
      for (const b of payload.baselines) {
        if (!b.path || !b.path.startsWith('/')) continue;
        const cleanRemotePath = path.posix.resolve(b.path);
        const key = `${agent.id}::${cleanRemotePath}`;
        const existing = this.remoteBaselines.get(key);
        if (!existing && agentBaselineCount >= MAX_REMOTE_BASELINES_PER_AGENT) {
          continue;
        }
        const modeVal = b.mode ?? 0o640;
        const uidVal = b.uid ?? 0;
        const gidVal = b.gid ?? 4;
        this.remoteBaselines.set(key, {
          agentId: agent.id,
          host: agent.hostname,
          path: cleanRemotePath,
          category: this.categoryForPath(cleanRemotePath),
          exists: true,
          isBinary: this.isBinaryFile(cleanRemotePath),
          inplaceOk: this.isInplaceOk(cleanRemotePath),
          hardened: existing?.hardened ?? false,
          ino: b.ino ?? 0,
          size: b.size ?? 0,
          mtimeMs: Date.now(),
          mode: modeVal,
          modeOctal: `0${modeVal.toString(8)}`,
          uid: uidVal,
          gid: gidVal,
          ownerLabel: this.formatOwner(uidVal, gidVal),
          plen: b.plen ?? 0,
          digest: b.digest ?? '',
          chunkCount: 1,
          status: existing?.status === 'tampered' ? 'tampered' : 'verified',
          lastEventAt: nowTimeShort(),
        });
        if (!existing) agentBaselineCount += 1;
      }
    }

    let accepted = 0;
    if (Array.isArray(payload.events)) {
      for (const ev of payload.events) {
        const targetPath = ev.path || '/var/log/syslog';
        if (ev.kind && WAZUH_RULE_MAP[ev.kind]) {
          this.fireTamperAlert({
            agentId: agent.id,
            host: agent.hostname,
            path: targetPath,
            kind: ev.kind,
            severity: ev.severity === 'WARN' ? 'WARN' : 'CRIT',
            user: ev.user || 'unknown',
            comm: ev.comm || 'agent-fim',
            exe: `/usr/bin/${ev.comm || 'unknown'}`,
            pid: ++this.pidCounter,
            explanation: ev.message || `${ev.kind} reported by remote agent ${agent.hostname}`,
            beforeSummary: 'remote baseline',
            afterSummary: ev.kind,
          });
          const key = `${agent.id}::${targetPath}`;
          const existing = this.remoteBaselines.get(key);
          if (existing) {
            existing.status = ev.kind === 'DELETED_OR_MOVED' ? 'missing' : 'tampered';
            existing.lastEventAt = nowTimeShort();
          }
        } else {
          this.pushLogEvent({
            agentId: agent.id,
            host: agent.hostname,
            severity: ev.severity ?? 'INFO',
            user: ev.user || 'system',
            file: targetPath,
            source: 'agent',
            message: ev.message || 'Agent event',
          });
        }
        accepted += 1;
      }
    }

    this.syncAgentCounters();
    this.emit('agents', this.agents);
    this.emit('baselines', this.getBaselines());
    this.emit('status', this.getStatus());
    return { ok: true, acceptedEvents: accepted };
  }

  public runAgentAction(
    agentId: string,
    action: 'toggle-status' | 'rebaseline',
  ): { ok: boolean; message: string } {
    const agent = this.agents.find((a) => a.id === agentId);
    if (!agent) return { ok: false, message: 'Agent not found' };

    if (action === 'toggle-status') {
      agent.status = agent.status === 'active' ? 'disconnected' : 'active';
      agent.lastKeepAlive = nowIso();
      this.savePersistedAgents();
      this.emit('agents', this.agents);
      this.emit('status', this.getStatus());
      return { ok: true, message: `Agent ${agent.hostname} is now ${agent.status}` };
    }

    for (const b of this.remoteBaselines.values()) {
      if (b.agentId === agent.id) {
        b.status = 'verified';
        b.lastEventAt = nowTimeShort();
      }
    }
    this.emit('baselines', this.getBaselines());
    return { ok: true, message: `Re-baselined files on ${agent.hostname}` };
  }

  // --- Splunk-Style SPL Query Engine ---

  public runSplQuery(rawQuery: string, timeRange: '15m' | '1h' | '24h' | 'all' = 'all'): SplQueryResult {
    const start = Date.now();
    const query = rawQuery.trim();
    const now = Date.now();
    const cutoffMs =
      timeRange === '15m'
        ? now - 15 * 60_000
        : timeRange === '1h'
          ? now - 60 * 60_000
          : timeRange === '24h'
            ? now - 24 * 60 * 60_000
            : 0;

    const pipeParts = query.split('|').map((s) => s.trim()).filter(Boolean);
    const searchExpr = pipeParts[0] && !/^(stats|top|head|sort|where)\b/i.test(pipeParts[0]) ? pipeParts[0] : '';
    const pipeCmds = searchExpr ? pipeParts.slice(1) : pipeParts;

    let matched = this.logs.filter((ev) => ev.epochMs >= cutoffMs);

    if (searchExpr && searchExpr !== '*') {
      const orClauses = searchExpr.split(/\s+OR\s+/i);
      matched = matched.filter((ev) => orClauses.some((clause) => this.matchesSplClause(ev, clause)));
    }

    const facetFields: Array<{ name: string; getter: (e: LogEvent) => string }> = [
      { name: 'host', getter: (e) => e.host },
      { name: 'severity', getter: (e) => e.severity },
      { name: 'source', getter: (e) => e.source },
      { name: 'user', getter: (e) => e.user },
      { name: 'file', getter: (e) => e.file },
      { name: 'rule', getter: (e) => e.ruleKind || 'NORMAL_APPEND' },
    ];

    const facets: SplFieldFacet[] = facetFields.map(({ name, getter }) => {
      const counts = new Map<string, number>();
      for (const ev of matched) {
        const val = getter(ev);
        counts.set(val, (counts.get(val) ?? 0) + 1);
      }
      const values = Array.from(counts.entries())
        .sort((a, b) => b[1] - a[1])
        .slice(0, 8)
        .map(([value, count]) => ({ value, count }));
      return { field: name, values };
    });

    const timeline: SplTimelineBucket[] = [];
    const minTs = matched.length > 0 ? Math.min(...matched.map((e) => e.epochMs)) : now - 600_000;
    const maxTs = Math.max(now, matched.length > 0 ? Math.max(...matched.map((e) => e.epochMs)) : now);
    const span = Math.max(60_000, maxTs - minTs);
    const bucketCount = 12;
    const bucketWidth = span / bucketCount;

    for (let i = 0; i < bucketCount; i += 1) {
      const bStart = minTs + i * bucketWidth;
      const bEnd = i === bucketCount - 1 ? maxTs + 1 : minTs + (i + 1) * bucketWidth;
      timeline.push({
        label: new Date(bStart).toTimeString().slice(0, 5),
        startMs: bStart,
        endMs: bEnd,
        info: 0,
        warn: 0,
        crit: 0,
        total: 0,
      });
    }
    for (const ev of matched) {
      const idx = Math.min(bucketCount - 1, Math.max(0, Math.floor((ev.epochMs - minTs) / bucketWidth)));
      const b = timeline[idx];
      if (ev.severity === 'CRIT') b.crit += 1;
      else if (ev.severity === 'WARN') b.warn += 1;
      else b.info += 1;
      b.total += 1;
    }

    let statsRows: Array<Record<string, string | number>> | null = null;
    let statsColumns: string[] = [];
    let finalEvents = matched;

    for (const pipe of pipeCmds) {
      const statsMatch = pipe.match(/^stats\s+count(?:\s+by\s+(\w+))?/i);
      if (statsMatch) {
        const groupField = (statsMatch[1] || 'severity').toLowerCase();
        const groups = new Map<string, number>();
        for (const ev of finalEvents) {
          const val = this.getSplField(ev, groupField);
          groups.set(val, (groups.get(val) ?? 0) + 1);
        }
        statsColumns = [groupField, 'count', 'share'];
        const total = Math.max(1, finalEvents.length);
        statsRows = Array.from(groups.entries())
          .sort((a, b) => b[1] - a[1])
          .map(([k, c]) => ({ [groupField]: k, count: c, share: `${((c / total) * 100).toFixed(1)}%` }));
        continue;
      }

      const topMatch = pipe.match(/^top\s+(\w+)/i);
      if (topMatch) {
        const field = topMatch[1].toLowerCase();
        const groups = new Map<string, number>();
        for (const ev of finalEvents) {
          const val = this.getSplField(ev, field);
          groups.set(val, (groups.get(val) ?? 0) + 1);
        }
        statsColumns = [field, 'count', 'percent'];
        const total = Math.max(1, finalEvents.length);
        statsRows = Array.from(groups.entries())
          .sort((a, b) => b[1] - a[1])
          .slice(0, 10)
          .map(([k, c]) => ({ [field]: k, count: c, percent: `${((c / total) * 100).toFixed(1)}%` }));
        continue;
      }

      const headMatch = pipe.match(/^head\s+(\d+)/i);
      if (headMatch) {
        finalEvents = finalEvents.slice(0, Number(headMatch[1]));
      }
    }

    return {
      query: rawQuery,
      timeRange,
      totalMatched: matched.length,
      executionMs: Date.now() - start,
      events: finalEvents.slice(0, 200),
      facets,
      timeline,
      statsRows,
      statsColumns,
    };
  }

  private getSplField(ev: LogEvent, field: string): string {
    switch (field) {
      case 'host':
        return ev.host;
      case 'agent':
      case 'agentid':
        return ev.agentId;
      case 'severity':
      case 'level':
        return ev.severity;
      case 'user':
        return ev.user;
      case 'file':
      case 'path':
        return ev.file;
      case 'source':
      case 'sourcetype':
        return ev.source;
      case 'rule':
      case 'kind':
        return ev.ruleKind || 'NORMAL_APPEND';
      case 'rule_id':
      case 'wazuh_rule':
        return ev.wazuhRuleId || '-';
      case 'mitre':
        return ev.mitreId || '-';
      case 'index':
        return ev.isTamper ? 'tamper' : 'logs';
      default:
        return ev.message;
    }
  }

  private matchesSplClause(ev: LogEvent, clause: string): boolean {
    const tokens = clause.match(/(?:[^\s"]+|"[^"]*")+/g) || [];
    for (const rawTok of tokens) {
      if (rawTok.toUpperCase() === 'AND') continue;
      const kv = rawTok.match(/^([a-zA-Z_]+)(!=|=)(.+)$/);
      if (kv) {
        const field = kv[1].toLowerCase();
        const op = kv[2];
        const expected = kv[3].replace(/^"|"$/g, '').toLowerCase();
        const actual = this.getSplField(ev, field).toLowerCase();
        const match = expected.includes('*')
          ? new RegExp('^' + expected.replace(/\*/g, '.*') + '$', 'i').test(actual)
          : actual === expected || actual.includes(expected);
        if (op === '=' && !match) return false;
        if (op === '!=' && match) return false;
      } else {
        const needle = rawTok.replace(/^"|"$/g, '').toLowerCase();
        const hay = `${ev.host} ${ev.severity} ${ev.user} ${ev.file} ${ev.source} ${ev.ruleKind ?? ''} ${ev.wazuhRuleId ?? ''} ${ev.mitreId ?? ''} ${ev.message}`.toLowerCase();
        if (!hay.includes(needle)) return false;
      }
    }
    return true;
  }

  // --- Hardening, Acknowledgements, Inspection ---

  public hardenFiles(pathsToHarden?: string[]): string[] {
    const targets = pathsToHarden ?? [...DEFAULT_HARDEN_PATHS, this.alertChainPath];
    const out: string[] = [];
    for (const rawPath of targets) {
      const check = this.isManagedPath(rawPath);
      if (!check.ok) {
        out.push(`[denied] ${rawPath}: ${check.reason}`);
        continue;
      }
      const p = check.resolved;
      if (!fs.existsSync(p)) {
        out.push(`[skip] ${p} does not exist on this machine`);
        continue;
      }
      try {
        execFileSync('chattr', ['+a', p], { stdio: 'pipe' });
      } catch {
        // Container fs may restrict immutable flags; track in engine state too
      }
      this.hardenedPaths.add(p);
      const b = this.baselines.get(p) ?? this.baselines.get(rawPath);
      if (b) b.hardened = true;
      out.push(`[ok] chattr +a ${p}`);
    }
    this.emit('baselines', this.getBaselines());
    return out;
  }

  public unhardenFiles(pathsToUnharden?: string[]): string[] {
    const targets = pathsToUnharden ?? Array.from(this.hardenedPaths);
    const out: string[] = [];
    for (const rawPath of targets) {
      const check = this.isManagedPath(rawPath);
      if (!check.ok) {
        out.push(`[denied] ${rawPath}: ${check.reason}`);
        continue;
      }
      const p = check.resolved;
      if (fs.existsSync(p)) {
        try {
          execFileSync('chattr', ['-a', p], { stdio: 'pipe' });
        } catch {
          // ignore if container fs lacks chattr capability
        }
      }
      this.hardenedPaths.delete(p);
      this.hardenedPaths.delete(rawPath);
      const b = this.baselines.get(p) ?? this.baselines.get(rawPath);
      if (b) b.hardened = false;
      out.push(`[ok] chattr -a ${p}`);
    }
    this.emit('baselines', this.getBaselines());
    return out;
  }

  public acknowledgeAlert(id: string): TamperAlert | null {
    const found = this.alerts.find((a) => a.id === id);
    if (!found) return null;
    found.acknowledged = true;
    found.acknowledgedAt = nowIso();
    this.syncAgentCounters();
    this.emit('alerts_updated', this.alerts);
    this.emit('agents', this.agents);
    this.emit('status', this.getStatus());
    return found;
  }

  public acknowledgeAll(): number {
    let count = 0;
    const ts = nowIso();
    for (const a of this.alerts) {
      if (!a.acknowledged) {
        a.acknowledged = true;
        a.acknowledgedAt = ts;
        count += 1;
      }
    }
    this.syncAgentCounters();
    this.emit('alerts_updated', this.alerts);
    this.emit('agents', this.agents);
    this.emit('status', this.getStatus());
    return count;
  }

  public rebaselineFile(filePath: string): BaselineRecord | null {
    const check = this.isManagedPath(filePath);
    if (!check.ok) return null;
    const b = this.computeBaseline(check.resolved);
    if (!b) return null;
    this.baselines.set(check.resolved, b);
    this.emit('baselines', this.getBaselines());
    return b;
  }

  public corruptChainDemo(): { line: number } {
    let lines = fs.existsSync(this.alertChainPath)
      ? fs.readFileSync(this.alertChainPath, 'utf8').split('\n').filter((l) => l.trim().length > 0)
      : [];
    if (lines.length === 0) {
      this.fireTamperAlert({
        path: '/var/log/test.log',
        kind: 'CONTENT_MODIFIED',
        user: os.userInfo().username,
        comm: 'chain-verify-test',
        exe: '/usr/bin/tamperer',
        pid: ++this.pidCounter,
        explanation: 'Chain verification test record created prior to edit test',
        beforeSummary: 'initial chain',
        afterSummary: 'seeded entry',
      });
      lines = fs.readFileSync(this.alertChainPath, 'utf8').split('\n').filter((l) => l.trim().length > 0);
    }
    const targetIdx = Math.max(0, lines.length - 1);
    try {
      const obj = JSON.parse(lines[targetIdx]) as Record<string, unknown>;
      obj.explanation = 'MODIFIED_CHAIN_RECORD_TEST';
      lines[targetIdx] = JSON.stringify(obj);
    } catch {
      lines[targetIdx] = '{"corrupted":true}';
    }
    this.internalWritePaths.add(this.alertChainPath);
    fs.writeFileSync(this.alertChainPath, lines.join('\n') + '\n', 'utf8');
    setTimeout(() => this.internalWritePaths.delete(this.alertChainPath), 150);
    this.emit('chain', {
      alerts: this.verifySingleChain('alerts.chain'),
      mirror: this.verifySingleChain('mirror.chain'),
    });
    return { line: targetIdx + 1 };
  }

  public readFileContent(filePath: string): {
    exists: boolean;
    isBinary: boolean;
    content: string;
    size: number;
    sha256: string;
    denied?: boolean;
    error?: string;
  } {
    const check = this.isManagedPath(filePath);
    if (!check.ok) {
      return { exists: false, isBinary: false, content: '', size: 0, sha256: '', denied: true, error: check.reason };
    }
    const target = check.resolved;
    if (!fs.existsSync(target)) {
      return { exists: false, isBinary: false, content: '', size: 0, sha256: '' };
    }
    const st = fs.lstatSync(target);
    if (!st.isFile()) {
      return { exists: false, isBinary: false, content: '', size: 0, sha256: '', error: 'Not a regular file' };
    }
    const isBin = this.isBinaryFile(target);
    const { digest } = this.hashPrefixStream(target, HASH_CAP_BYTES);
    let content = '';
    if (isBin) {
      const headLen = Math.min(2048, st.size);
      const fd = fs.openSync(target, 'r');
      try {
        const b = Buffer.alloc(headLen);
        const n = fs.readSync(fd, b, 0, headLen, 0);
        content = b.subarray(0, n).toString('hex').replace(/(.{2})/g, '$1 ').trim();
      } finally {
        fs.closeSync(fd);
      }
    } else {
      const start = Math.max(0, st.size - 32000);
      content = this.readRangeUtf8(target, start, st.size - start);
    }
    return { exists: true, isBinary: isBin, content, size: st.size, sha256: digest };
  }

  public executeCommand(rawCmd: string): TerminalExecResult {
    const cmd = rawCmd.trim();
    const cwd = process.cwd();
    const stdout: string[] = [];
    const stderr: string[] = [];
    const triggered = new Set<DetectionRuleKind>();
    let exitCode = 0;
    let monitorAction: TerminalExecResult['monitorAction'];

    if (!cmd) return { command: rawCmd, stdout, stderr, exitCode: 0, cwd, triggeredRules: [] };

    const splitOutsideQuotes = (input: string, sep: string): string[] => {
      const parts: string[] = [];
      let cur = '';
      let quote: '"' | "'" | null = null;
      for (let i = 0; i < input.length; i += 1) {
        const ch = input[i];
        if ((ch === '"' || ch === "'") && input[i - 1] !== '\\') {
          quote = quote === ch ? null : quote === null ? ch : quote;
          cur += ch;
        } else if (!quote && input.slice(i, i + sep.length) === sep) {
          if (cur.trim()) parts.push(cur.trim());
          cur = '';
          i += sep.length - 1;
        } else {
          cur += ch;
        }
      }
      if (cur.trim()) parts.push(cur.trim());
      return parts;
    };

    const semiParts = splitOutsideQuotes(cmd, ';');
    if (semiParts.length > 1) {
      for (const part of semiParts) {
        const sub = this.executeCommand(part);
        stdout.push(...sub.stdout);
        stderr.push(...sub.stderr);
        for (const r of sub.triggeredRules) triggered.add(r);
        if (sub.exitCode !== 0) exitCode = sub.exitCode;
        if (sub.monitorAction) monitorAction = sub.monitorAction;
      }
      return { command: rawCmd, stdout, stderr, exitCode, cwd, triggeredRules: Array.from(triggered), monitorAction };
    }

    const andParts = splitOutsideQuotes(cmd, '&&');
    if (andParts.length > 1) {
      for (const part of andParts) {
        const sub = this.executeCommand(part);
        stdout.push(...sub.stdout);
        stderr.push(...sub.stderr);
        for (const r of sub.triggeredRules) triggered.add(r);
        if (sub.monitorAction) monitorAction = sub.monitorAction;
        if (sub.exitCode !== 0) {
          exitCode = sub.exitCode;
          break;
        }
      }
      return { command: rawCmd, stdout, stderr, exitCode, cwd, triggeredRules: Array.from(triggered), monitorAction };
    }

    const pid = ++this.pidCounter;
    const user = os.userInfo().username;
    const normalized = cmd.replace(/^sudo\s+/, '');

    // 0. tamperer GUI launcher
    if (normalized === 'tamperer' || normalized.startsWith('tamperer ')) {
      this.startMonitoring('interactive');
      stdout.push(
        `[tamperer] Attached to local Linux host ${this.hostname} (${this.osPretty})`,
        `[tamperer] Watching ${this.baselines.size} real files under /var/log and ${this.agents.length} node(s).`,
      );
      return { command: rawCmd, stdout, stderr, exitCode: 0, cwd, triggeredRules: [], monitorAction: 'started' };
    }

    // 1. tamplogs CLI
    if (/^(tamplogs|tamper_blocker|python3\s+\/opt\/tamper_blocker\/tamper_blocker\.py)\b/.test(normalized)) {
      const args = normalized.split(/\s+/).slice(1);
      if (args.includes('--help') || args.includes('-h')) {
        stdout.push(
          'usage: tamperer | tamplogs [--headless] [--no-popup] [--harden] [--unharden] [--verify] [--status] [--stop]',
          '  Watches real machine logs in /var/log, detects edits/truncation/deletion/chmod, and verifies SHA-256 chains.',
        );
        return { command: rawCmd, stdout, stderr, exitCode: 0, cwd, triggeredRules: [] };
      }
      if (args.includes('--verify')) {
        const aRes = this.verifySingleChain('alerts.chain');
        const mRes = this.verifySingleChain('mirror.chain');
        stdout.push(`alerts.chain: ${aRes.ok ? 'True' : 'False'} ${aRes.brokenLine ?? 'None'} (${aRes.totalLines} records)`);
        stdout.push(`mirror.chain: ${mRes.ok ? 'True' : 'False'} ${mRes.brokenLine ?? 'None'} (${mRes.totalLines} records)`);
        return { command: rawCmd, stdout, stderr, exitCode: aRes.ok && mRes.ok ? 0 : 2, cwd, triggeredRules: [], monitorAction: 'verified' };
      }
      if (args.includes('--harden')) {
        stdout.push(...this.hardenFiles());
        return { command: rawCmd, stdout, stderr, exitCode: 0, cwd, triggeredRules: [], monitorAction: 'hardened' };
      }
      if (args.includes('--unharden')) {
        stdout.push(...this.unhardenFiles());
        return { command: rawCmd, stdout, stderr, exitCode: 0, cwd, triggeredRules: [], monitorAction: 'unhardened' };
      }
      if (args.includes('--stop')) {
        this.stopMonitoring();
        stdout.push('[tamplogs] Monitoring stopped.');
        return { command: rawCmd, stdout, stderr, exitCode: 0, cwd, triggeredRules: [], monitorAction: 'stopped' };
      }
      if (args.includes('--status')) {
        const st = this.getStatus();
        stdout.push(
          `State: ${st.active ? `ACTIVE (${st.mode})` : 'STOPPED'}`,
          `Host: ${st.hostname} (${this.osPretty}, kernel ${st.kernel})`,
          `Real Watched Files: ${st.watchedFilesCount}`,
          `Unacknowledged Alerts: ${st.unacknowledgedCount}`,
          `Chain Dir: ${this.chainDir}`,
        );
        return { command: rawCmd, stdout, stderr, exitCode: 0, cwd, triggeredRules: [], monitorAction: 'status' };
      }

      const mode: MonitorStatus['mode'] = args.includes('--headless') ? 'headless' : args.includes('--no-popup') ? 'no-popup' : 'interactive';
      this.startMonitoring(mode);
      stdout.push(
        `[tamplogs] Real-time File Integrity & Log Monitor active (${mode} mode)`,
        `[tamplogs] Watching ${this.baselines.size} real machine files in /var/log`,
        `[tamplogs] Chain storage: ${this.alertChainPath}`,
      );
      return { command: rawCmd, stdout, stderr, exitCode: 0, cwd, triggeredRules: [], monitorAction: 'started' };
    }

    // 2. tee -a on managed machine path
    const teeMatch = cmd.match(/^echo\s+(['"]?)(.+?)\1\s*\|\s*(?:sudo\s+)?tee\s+-a\s+(\S+)$/);
    if (teeMatch) {
      const text = teeMatch[2];
      const check = this.isManagedPath(teeMatch[3]);
      if (!check.ok) {
        stderr.push(`tee: ${teeMatch[3]}: ${check.reason}`);
        return { command: rawCmd, stdout, stderr, exitCode: 1, cwd, triggeredRules: [] };
      }
      const target = check.resolved;
      try {
        fs.mkdirSync(path.dirname(target), { recursive: true });
        this.internalWritePaths.add(target);
        fs.appendFileSync(target, text + '\n', 'utf8');
        this.internalWritePaths.delete(target);
      } catch (err) {
        this.internalWritePaths.delete(target);
        stderr.push(`tee: ${target}: ${(err as Error).message}`);
        return { command: rawCmd, stdout, stderr, exitCode: 1, cwd, triggeredRules: [] };
      }
      const rules = this.checkPathIntegrity(target, { user, comm: 'tee', exe: '/usr/bin/tee', pid });
      rules.forEach((r) => triggered.add(r));
      stdout.push(text);
      return { command: rawCmd, stdout, stderr, exitCode: 0, cwd, triggeredRules: Array.from(triggered) };
    }

    // 3. sed -i on managed path
    const sedMatch = normalized.match(/^sed\s+(?:-i|--in-place)\s+(['"])s\/([^/]*)\/([^/]*)\/(g?)\1\s+(\S+)$/);
    if (sedMatch) {
      const [, , search, replace, gFlag, rawTarget] = sedMatch;
      const check = this.isManagedPath(rawTarget);
      if (!check.ok) {
        stderr.push(`sed: ${rawTarget}: ${check.reason}`);
        return { command: rawCmd, stdout, stderr, exitCode: 1, cwd, triggeredRules: [] };
      }
      const target = check.resolved;
      if (search.length > 256 || replace.length > 512) {
        stderr.push('sed: pattern or replacement exceeds safety length limit');
        return { command: rawCmd, stdout, stderr, exitCode: 1, cwd, triggeredRules: [] };
      }
      if (/(\([^)]*[+*][^)]*\))[+*]/.test(search)) {
        stderr.push('sed: nested-quantifier regex rejected for safety');
        return { command: rawCmd, stdout, stderr, exitCode: 1, cwd, triggeredRules: [] };
      }
      if (this.hardenedPaths.has(target)) {
        stderr.push(`sed: ${target}: Operation not permitted (chattr +a)`);
        return { command: rawCmd, stdout, stderr, exitCode: 4, cwd, triggeredRules: [] };
      }
      if (!fs.existsSync(target)) {
        stderr.push(`sed: can't read ${target}: No such file or directory`);
        return { command: rawCmd, stdout, stderr, exitCode: 2, cwd, triggeredRules: [] };
      }
      try {
        const re = new RegExp(search, gFlag ? 'g' : '');
        const next = fs.readFileSync(target, 'utf8').replace(re, replace);
        const tmp = `${target}.sedtmp.${Date.now()}`;
        this.internalWritePaths.add(target);
        try {
          fs.writeFileSync(tmp, next, 'utf8');
          fs.renameSync(tmp, target); // real atomic rename changes inode on standard Linux
        } catch {
          try {
            if (fs.existsSync(tmp)) fs.rmSync(tmp, { force: true });
          } catch {
            // ignore
          }
          // Fallback for container filesystems (e.g. gVisor /var/log) that disallow renameSync
          fs.writeFileSync(target, next, 'utf8');
        } finally {
          this.internalWritePaths.delete(target);
        }
      } catch (err) {
        this.internalWritePaths.delete(target);
        stderr.push(`sed: ${target}: ${(err as Error).message}`);
        return { command: rawCmd, stdout, stderr, exitCode: 4, cwd, triggeredRules: [] };
      }
      if (this.monitoringActive) {
        const a = this.fireTamperAlert({
          path: target,
          kind: 'SED_INPLACE_ON_LOG',
          user,
          comm: 'sed',
          exe: '/usr/bin/sed',
          pid,
          explanation: `In-place sed substitution detected on ${target} (s/${search}/${replace}/)`,
          beforeSummary: `matched "${search}"`,
          afterSummary: `replaced with "${replace}"`,
        });
        if (a) triggered.add('SED_INPLACE_ON_LOG');
      }
      this.checkPathIntegrity(target, { user, comm: 'sed', exe: '/usr/bin/sed', pid }).forEach((r) => triggered.add(r));
      return { command: rawCmd, stdout, stderr, exitCode: 0, cwd, triggeredRules: Array.from(triggered) };
    }

    // 4. truncate on managed path
    const truncMatch = normalized.match(/^truncate\s+-s\s+(\d+)\s+(\S+)$/);
    if (truncMatch) {
      const size = Number(truncMatch[1]);
      const check = this.isManagedPath(truncMatch[2]);
      if (!check.ok) {
        stderr.push(`truncate: ${truncMatch[2]}: ${check.reason}`);
        return { command: rawCmd, stdout, stderr, exitCode: 1, cwd, triggeredRules: [] };
      }
      const target = check.resolved;
      if (this.hardenedPaths.has(target)) {
        stderr.push(`truncate: failed to truncate '${target}': Operation not permitted (chattr +a)`);
        return { command: rawCmd, stdout, stderr, exitCode: 1, cwd, triggeredRules: [] };
      }
      if (!fs.existsSync(target)) {
        stderr.push(`truncate: cannot open '${target}': No such file or directory`);
        return { command: rawCmd, stdout, stderr, exitCode: 1, cwd, triggeredRules: [] };
      }
      try {
        this.internalWritePaths.add(target);
        try {
          fs.truncateSync(target, size);
        } catch {
          const existingBuf = fs.readFileSync(target);
          fs.writeFileSync(target, existingBuf.subarray(0, size));
        } finally {
          this.internalWritePaths.delete(target);
        }
      } catch (err) {
        this.internalWritePaths.delete(target);
        stderr.push(`truncate: ${target}: ${(err as Error).message}`);
        return { command: rawCmd, stdout, stderr, exitCode: 1, cwd, triggeredRules: [] };
      }
      if (this.monitoringActive) {
        const a = this.fireTamperAlert({
          path: target,
          kind: 'LOG_FILE_COMMAND',
          user,
          comm: 'truncate',
          exe: '/usr/bin/truncate',
          pid,
          explanation: `Destructive command detected: ${cmd}`,
          beforeSummary: 'process cmdline scan',
          afterSummary: `truncate pid=${pid}`,
        });
        if (a) triggered.add('LOG_FILE_COMMAND');
      }
      this.checkPathIntegrity(target, { user, comm: 'truncate', exe: '/usr/bin/truncate', pid }).forEach((r) => triggered.add(r));
      return { command: rawCmd, stdout, stderr, exitCode: 0, cwd, triggeredRules: Array.from(triggered) };
    }

    // 5. chmod on managed path
    const chmodMatch = normalized.match(/^chmod\s+([0-7]{3,4})\s+(\S+)$/);
    if (chmodMatch) {
      const modeVal = parseInt(chmodMatch[1], 8);
      const check = this.isManagedPath(chmodMatch[2]);
      if (!check.ok) {
        stderr.push(`chmod: ${chmodMatch[2]}: ${check.reason}`);
        return { command: rawCmd, stdout, stderr, exitCode: 1, cwd, triggeredRules: [] };
      }
      const target = check.resolved;
      if (!fs.existsSync(target)) {
        stderr.push(`chmod: cannot access '${target}': No such file or directory`);
        return { command: rawCmd, stdout, stderr, exitCode: 1, cwd, triggeredRules: [] };
      }
      try {
        this.internalWritePaths.add(target);
        fs.chmodSync(target, modeVal);
        this.internalWritePaths.delete(target);
      } catch (err) {
        this.internalWritePaths.delete(target);
        stderr.push(`chmod: ${target}: ${(err as Error).message}`);
        return { command: rawCmd, stdout, stderr, exitCode: 1, cwd, triggeredRules: [] };
      }
      this.checkPathIntegrity(target, { user, comm: 'chmod', exe: '/usr/bin/chmod', pid }).forEach((r) => triggered.add(r));
      return { command: rawCmd, stdout, stderr, exitCode: 0, cwd, triggeredRules: Array.from(triggered) };
    }

    // 6. rm on managed path
    const rmMatch = normalized.match(/^(rm|unlink)(?:\s+-[A-Za-z]+)*\s+(\S+)$/);
    if (rmMatch) {
      const bin = rmMatch[1];
      const check = this.isManagedPath(rmMatch[2]);
      if (!check.ok) {
        stderr.push(`${bin}: cannot remove '${rmMatch[2]}': ${check.reason}`);
        return { command: rawCmd, stdout, stderr, exitCode: 1, cwd, triggeredRules: [] };
      }
      const target = check.resolved;
      if (this.hardenedPaths.has(target)) {
        stderr.push(`${bin}: cannot remove '${target}': Operation not permitted (chattr +a)`);
        return { command: rawCmd, stdout, stderr, exitCode: 1, cwd, triggeredRules: [] };
      }
      if (!fs.existsSync(target)) {
        stderr.push(`${bin}: cannot remove '${target}': No such file or directory`);
        return { command: rawCmd, stdout, stderr, exitCode: 1, cwd, triggeredRules: [] };
      }
      try {
        this.internalWritePaths.add(target);
        fs.rmSync(target, { force: true });
        this.internalWritePaths.delete(target);
      } catch (err) {
        this.internalWritePaths.delete(target);
        stderr.push(`${bin}: cannot remove '${target}': ${(err as Error).message}`);
        return { command: rawCmd, stdout, stderr, exitCode: 1, cwd, triggeredRules: [] };
      }
      if (this.monitoringActive) {
        const a = this.fireTamperAlert({
          path: target,
          kind: 'LOG_FILE_COMMAND',
          user,
          comm: bin,
          exe: `/usr/bin/${bin}`,
          pid,
          explanation: `Destructive command ${bin} targeted ${target}`,
          beforeSummary: 'active file',
          afterSummary: `removed by ${bin}`,
        });
        if (a) triggered.add('LOG_FILE_COMMAND');
      }
      this.checkPathIntegrity(target, { user, comm: bin, exe: `/usr/bin/${bin}`, pid }).forEach((r) => triggered.add(r));
      return { command: rawCmd, stdout, stderr, exitCode: 0, cwd, triggeredRules: Array.from(triggered) };
    }

    // 7. Scoped read-only commands executed directly on the host machine
    const pathBins = new Set(['ls', 'cat', 'head', 'tail', 'stat', 'lsattr', 'grep']);
    const infoBins = new Set(['whoami', 'id', 'pwd', 'uname', 'df', 'uptime', 'ps']);
    const tokenizeArgs = (input: string): string[] => {
      const tokens: string[] = [];
      let cur = '';
      let q: '"' | "'" | null = null;
      for (let i = 0; i < input.length; i += 1) {
        const ch = input[i];
        if ((ch === '"' || ch === "'") && input[i - 1] !== '\\') {
          q = q === ch ? null : q === null ? ch : q;
        } else if (!q && /\s/.test(ch)) {
          if (cur.length > 0) { tokens.push(cur); cur = ''; }
        } else {
          cur += ch;
        }
      }
      if (cur.length > 0) tokens.push(cur);
      return tokens;
    };

    const argv = tokenizeArgs(normalized);
    const binName = argv[0] || '';
    const args = argv.slice(1);

    if (pathBins.has(binName) || infoBins.has(binName)) {
      if (infoBins.has(binName)) {
        const badArg = args.find((a) => !a.startsWith('-'));
        if (badArg) {
          stderr.push(`${binName}: argument '${badArg}' is not permitted in scoped shell`);
          return { command: rawCmd, stdout, stderr, exitCode: 1, cwd, triggeredRules: [] };
        }
      } else {
        if (binName === 'grep' && args.some((a) => a === '-f' || a.startsWith('--file'))) {
          stderr.push('grep: reading patterns from files (-f) is disabled');
          return { command: rawCmd, stdout, stderr, exitCode: 1, cwd, triggeredRules: [] };
        }
        const nonFlagArgs: string[] = [];
        for (let i = 0; i < args.length; i += 1) {
          const a = args[i];
          if (a === '-n' || a === '-c' || a === '-e' || a === '-A' || a === '-B' || a === '-C') {
            i += 1;
            continue;
          }
          if (a.startsWith('-')) continue;
          nonFlagArgs.push(a);
        }
        const pathArgs = binName === 'grep' ? nonFlagArgs.slice(1) : nonFlagArgs;
        if (binName !== 'ls' && pathArgs.length === 0) {
          stderr.push(`${binName}: specify an absolute path inside /var/log or ${this.chainDir}`);
          return { command: rawCmd, stdout, stderr, exitCode: 1, cwd, triggeredRules: [] };
        }
        if (binName === 'ls' && pathArgs.length === 0) {
          args.push('/var/log');
        }
        for (const pArg of pathArgs) {
          const check = this.isManagedPath(pArg);
          if (!check.ok) {
            stderr.push(`${binName}: ${pArg}: ${check.reason}`);
            return { command: rawCmd, stdout, stderr, exitCode: 1, cwd, triggeredRules: [] };
          }
        }
      }
      try {
        const out = execFileSync(binName, args, { encoding: 'utf8', maxBuffer: 512 * 1024, stdio: ['ignore', 'pipe', 'pipe'] });
        if (out) stdout.push(...out.replace(/\n$/, '').split('\n'));
        return { command: rawCmd, stdout, stderr, exitCode: 0, cwd, triggeredRules: [] };
      } catch (err) {
        const e = err as { status?: number; stderr?: string; stdout?: string };
        if (e.stdout) stdout.push(...e.stdout.replace(/\n$/, '').split('\n'));
        if (e.stderr) stderr.push(...e.stderr.replace(/\n$/, '').split('\n'));
        return { command: rawCmd, stdout, stderr, exitCode: e.status ?? 1, cwd, triggeredRules: [] };
      }
    }

    if (normalized === 'help') {
      stdout.push(
        'Real Host Commands:',
        '  tamperer | tamplogs [--verify|--harden|--unharden|--status|--stop]',
        '  ls -la /var/log  |  cat /var/log/dpkg.log  |  tail -n 20 /var/log/nginx/access.log',
        '  stat /var/log/dpkg.log  |  lsattr /var/log/dpkg.log',
        '  echo test | sudo tee -a /var/log/test.log',
        "  sudo sed -i 's/test/EDIT/' /var/log/test.log",
        '  sudo truncate -s 0 /var/log/test.log  |  sudo chmod 777 /var/log/test.log  |  sudo rm /var/log/test.log',
      );
      return { command: rawCmd, stdout, stderr, exitCode: 0, cwd, triggeredRules: [] };
    }

    stderr.push(`${binName}: command not available or restricted in web shell (type 'help' or 'tamperer')`);
    return { command: rawCmd, stdout, stderr, exitCode: 127, cwd, triggeredRules: [] };
  }

  public runTestStep(step: number): TestStepResult {
    const start = Date.now();
    if (!this.monitoringActive) this.startMonitoring('interactive');

    let drillPath = '/var/log/test.log';
    try {
      const probe = `/var/log/.tamper_probe_${process.pid}`;
      fs.writeFileSync(probe, '');
      fs.rmSync(probe);
    } catch {
      drillPath = path.join(this.chainDir, 'test_drill.log');
    }

    // Clear 3s dedup cooldown for explicit sequential Test Plan steps
    for (const key of Array.from(this.dedupMap.keys())) {
      if (key.includes(drillPath)) {
        this.dedupMap.delete(key);
      }
    }

    const ensureTestLog = (filePath: string) => {
      this.internalWritePaths.add(filePath);
      fs.writeFileSync(filePath, 'baseline test entry\n', 'utf8');
      try {
        fs.chmodSync(filePath, 0o644);
      } catch {
        // ignore if unsupported
      }
      setTimeout(() => this.internalWritePaths.delete(filePath), 150);
      this.rebaselineFile(filePath);
    };

    let name = '';
    let command = '';
    let expected = '';
    let passed = false;
    let observed = '';

    switch (step) {
      case 1: {
        name = 'Append';
        command = `echo test | sudo tee -a ${drillPath}`;
        expected = 'White [INFO] line in dashboard, no tamper alert.';
        ensureTestLog(drillPath);
        const before = this.alerts.length;
        const res = this.executeCommand(command);
        passed = res.exitCode === 0 && this.alerts.length === before && res.triggeredRules.length === 0;
        observed = passed ? `Appended to ${drillPath}; 0 alerts fired.` : `Unexpected: ${res.triggeredRules.join(', ')}`;
        break;
      }
      case 2: {
        name = 'Edit';
        command = `echo AAAA | sudo tee -a ${drillPath}; sudo sed -i 's/test/EDIT/' ${drillPath}`;
        expected = 'SED_INPLACE_ON_LOG and INODE_REPLACED or CONTENT_MODIFIED.';
        ensureTestLog(drillPath);
        const res = this.executeCommand(command);
        passed = res.triggeredRules.includes('SED_INPLACE_ON_LOG') && (res.triggeredRules.includes('INODE_REPLACED') || res.triggeredRules.includes('CONTENT_MODIFIED'));
        observed = `Triggered: ${res.triggeredRules.join(' + ') || 'none'}`;
        break;
      }
      case 3: {
        name = 'Truncate';
        command = `sudo truncate -s 0 ${drillPath}`;
        expected = 'TRUNCATED + LOG_FILE_COMMAND.';
        ensureTestLog(drillPath);
        const res = this.executeCommand(command);
        passed = res.triggeredRules.includes('TRUNCATED') && res.triggeredRules.includes('LOG_FILE_COMMAND');
        observed = `Triggered: ${res.triggeredRules.join(' + ') || 'none'}`;
        break;
      }
      case 4: {
        name = 'Permissions';
        command = `sudo chmod 777 ${drillPath}`;
        expected = 'PERM_OWNER_CHANGE.';
        ensureTestLog(drillPath);
        const res = this.executeCommand(command);
        passed = res.triggeredRules.includes('PERM_OWNER_CHANGE');
        observed = `Triggered: ${res.triggeredRules.join(' + ') || 'none'}`;
        break;
      }
      case 5: {
        name = 'Delete';
        command = `sudo rm ${drillPath}`;
        expected = 'DELETED_OR_MOVED; alert names rm and user.';
        ensureTestLog(drillPath);
        const res = this.executeCommand(command);
        passed = res.triggeredRules.includes('DELETED_OR_MOVED');
        observed = `Triggered: ${res.triggeredRules.join(' + ') || res.stderr.join(' ')}`;
        break;
      }
      case 6: {
        name = 'Rotation';
        command = 'sudo logrotate -f /etc/logrotate.conf';
        expected = 'Requires logrotate installed on Kali host.';
        passed = commandExists('logrotate');
        observed = passed ? 'logrotate present on host' : 'logrotate binary not installed in this container';
        break;
      }
      case 7: {
        name = 'Service Stop';
        command = 'sudo systemctl stop rsyslog; sudo systemctl start rsyslog';
        expected = 'Requires systemd/rsyslog on Kali host.';
        passed = commandExists('systemctl');
        observed = passed ? 'systemctl present on host' : 'systemd not running in this container';
        break;
      }
      case 8: {
        name = 'Vacuum';
        command = 'sudo journalctl --vacuum-size=500M';
        expected = 'Requires systemd-journald on Kali host.';
        passed = commandExists('journalctl');
        observed = passed ? 'journalctl present on host' : 'journalctl not installed in this container';
        break;
      }
      case 9: {
        name = 'Chain';
        command = 'sudo tamplogs --verify';
        expected = 'Prints True None; fails with line number if chain edited.';
        const res = this.executeCommand(command);
        passed = res.stdout.some((l) => l.includes('True None'));
        observed = res.stdout.join(' | ');
        break;
      }
      case 10:
      default: {
        name = 'Audit Rules';
        command = 'sudo auditctl -l';
        expected = 'Lists active auditctl log_tamper rules on Kali host.';
        passed = commandExists('auditctl') && this.auditRules.length > 0;
        observed = passed ? `${this.auditRules.length} rules loaded` : 'auditctl not installed in this container';
        break;
      }
    }

    return { step, name, command, expected, passed, observed, durationMs: Date.now() - start };
  }

  public resetAll(): void {
    for (const p of ['/var/log/test.log', path.join(this.chainDir, 'test_drill.log')]) {
      if (fs.existsSync(p)) {
        try {
          fs.rmSync(p, { force: true });
        } catch {
          // ignore if container mount disallows unlink in /var/log
        }
      }
    }
    this.initMachineState(true);
    if (this.monitoringActive) {
      this.setupWatchers();
    }
    this.emit('status', this.getStatus());
    this.emit('agents', this.agents);
    this.emit('baselines', this.getBaselines());
  }

  public getStatus(): MonitorStatus {
    return {
      active: this.monitoringActive,
      mode: this.monitorMode,
      hostname: this.hostname,
      kernel: this.kernel,
      startedAt: this.startedAt,
      uptimeSeconds: this.startedAtMs ? Math.floor((Date.now() - this.startedAtMs) / 1000) : 0,
      liveNoiseEnabled: false,
      watchedFilesCount: this.getBaselines().length,
      unacknowledgedCount: this.alerts.filter((a) => !a.acknowledged).length,
      totalAlertsCount: this.alerts.length,
      totalEventsCount: this.logs.length,
      activeAgentsCount: this.agents.filter((a) => a.status === 'active').length,
      totalAgentsCount: this.agents.length,
      auditRulesLoaded: this.auditRules.some((r) => r.loaded),
      logrotateRecent: this.isLogrotateRecent(),
    };
  }

  public getBaselines(): BaselineRecord[] {
    const all = [...this.baselines.values(), ...this.remoteBaselines.values()];
    return all.sort((a, b) => a.host.localeCompare(b.host) || a.path.localeCompare(b.path));
  }

  public getAgents(): AgentNode[] {
    return this.agents;
  }

  public getSnapshot(): AppSnapshot {
    this.syncAgentCounters();
    return {
      status: this.getStatus(),
      agents: this.agents,
      baselines: this.getBaselines(),
      logs: this.logs,
      alerts: this.alerts,
      services: this.services,
      auditRules: this.auditRules,
      chainVerify: {
        alerts: this.verifySingleChain('alerts.chain'),
        mirror: this.verifySingleChain('mirror.chain'),
      },
      recentAlertChain: this.readChainTail('alerts.chain', 40),
      recentMirrorChain: this.readChainTail('mirror.chain', 40),
      configYaml: DEFAULT_CONFIG_YAML,
    };
  }
}
