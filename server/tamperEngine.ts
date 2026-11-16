import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import type {
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
  TamperAlert,
  TerminalExecResult,
  TestStepResult,
} from '../src/types/tamper.ts';
import { DEFAULT_CONFIG_YAML } from './kaliBundle.ts';

type SSEListener = (eventName: string, payload: unknown) => void;

const GENESIS_HASH = '0'.repeat(64);
const HASH_CAP_BYTES = 16 * 1024 * 1024;
const CHUNK_SIZE_BYTES = 1024 * 1024;

const CRIT_RE = /segfault|panic|BUG:|oom-kill|tamper/i;
const WARN_RE = /fail|denied|error|invalid|warn|refused/i;

const BINARY_BASENAMES = new Set(['wtmp', 'btmp', 'lastlog', 'utmp']);
const INPLACE_OK_BASENAMES = new Set(['lastlog']);
const TAIL_SKIP_PATHS = new Set(['/var/log/audit/audit.log', '/var/lib/tamper_blocker/alerts.chain', '/var/lib/tamper_blocker/mirror.chain']);

const INITIAL_HARDENED = new Set([
  '/var/log/auth.log',
  '/var/log/syslog',
  '/var/log/kern.log',
  '/var/log/dpkg.log',
  '/var/lib/tamper_blocker/alerts.chain',
]);

interface VirtualMeta {
  mode: number;
  uid: number;
  gid: number;
  virtualInoOffset: number;
}

function nowIso(): string {
  return new Date().toISOString().slice(0, 19);
}

function nowTimeShort(): string {
  const d = new Date();
  return d.toTimeString().slice(0, 8);
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

export class TamperEngine {
  private readonly sandboxRoot: string;
  private readonly listeners = new Set<SSEListener>();
  private readonly baselines = new Map<string, BaselineRecord>();
  private readonly virtualMeta = new Map<string, VirtualMeta>();
  private readonly hardenedPaths = new Set<string>(INITIAL_HARDENED);
  private readonly dedupMap = new Map<string, number>();
  private readonly watchers: fs.FSWatcher[] = [];

  private logs: LogEvent[] = [];
  private alerts: TamperAlert[] = [];
  private alertSeq = 0;
  private mirrorSeq = 0;
  private eventSeq = 0;
  private pidCounter = 4120;
  private inoSeq = 900100;

  private monitoringActive = false;
  private monitorMode: MonitorStatus['mode'] = 'stopped';
  private startedAt: string | null = null;
  private startedAtMs = 0;
  private liveNoiseEnabled = true;
  private logrotateSeenAt = 0;
  private internalWritePaths = new Set<string>();
  private noiseTimer: ReturnType<typeof setInterval> | null = null;

  private services: ServiceStatus[] = [
    { name: 'auditd', active: true, pid: 814, uptime: '4h 12m' },
    { name: 'rsyslog', active: true, pid: 902, uptime: '4h 12m' },
    { name: 'systemd-journald', active: true, pid: 412, uptime: '4h 12m' },
  ];

  private auditRules: AuditRuleEntry[] = [];

  constructor(workspaceDir: string = process.cwd()) {
    this.sandboxRoot = path.join(workspaceDir, '.tamper_sandbox');
    this.initSandbox(false);
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
        // ignore broken SSE client
      }
    }
  }

  private toRealPath(vPath: string): string {
    const clean = path.posix.normalize(vPath.startsWith('/') ? vPath : `/${vPath}`);
    const rel = clean.replace(/^\/+/, '');
    return path.join(this.sandboxRoot, rel);
  }

  private toVirtualPath(realPath: string): string {
    const rel = path.relative(this.sandboxRoot, realPath).split(path.sep).join('/');
    return `/${rel}`;
  }

  private defaultVirtualMeta(vPath: string): VirtualMeta {
    if (vPath.startsWith('/home/kali/')) {
      return { mode: 0o600, uid: 1000, gid: 1000, virtualInoOffset: 0 };
    }
    if (vPath === '/root/.bash_history') {
      return { mode: 0o600, uid: 0, gid: 0, virtualInoOffset: 0 };
    }
    if (vPath === '/var/log/wtmp' || vPath === '/var/log/lastlog') {
      return { mode: 0o664, uid: 0, gid: 43, virtualInoOffset: 0 };
    }
    if (vPath === '/var/log/btmp') {
      return { mode: 0o660, uid: 0, gid: 43, virtualInoOffset: 0 };
    }
    return { mode: 0o640, uid: 0, gid: 4, virtualInoOffset: 0 };
  }

  private getVirtualMeta(vPath: string): VirtualMeta {
    let meta = this.virtualMeta.get(vPath);
    if (!meta) {
      meta = this.defaultVirtualMeta(vPath);
      this.virtualMeta.set(vPath, meta);
    }
    return meta;
  }

  private formatOwner(uid: number, gid: number): string {
    const u = uid === 0 ? 'root' : uid === 1000 ? 'kali' : uid === 33 ? 'www-data' : `uid:${uid}`;
    const g = gid === 0 ? 'root' : gid === 4 ? 'adm' : gid === 43 ? 'utmp' : gid === 1000 ? 'kali' : `gid:${gid}`;
    return `${u}:${g}`;
  }

  private categoryForPath(vPath: string): BaselineRecord['category'] {
    if (vPath.includes('_history')) return 'history';
    if (vPath.startsWith('/var/lib/tamper_blocker/')) return 'chain';
    if (vPath.startsWith('/var/log/audit/')) return 'audit';
    if (vPath.startsWith('/var/log/journal/')) return 'journal';
    if (BINARY_BASENAMES.has(path.posix.basename(vPath))) return 'binary';
    if (vPath.startsWith('/var/log/dpkg.log') || vPath.startsWith('/var/log/apt/')) return 'package';
    if (vPath.startsWith('/var/log/apache2/') || vPath.startsWith('/var/log/nginx/')) return 'web';
    return 'system';
  }

  private isInplaceOk(vPath: string): boolean {
    const base = path.posix.basename(vPath);
    return INPLACE_OK_BASENAMES.has(base) || vPath.startsWith('/var/log/journal/');
  }

  private isBinaryFile(vPath: string): boolean {
    const base = path.posix.basename(vPath);
    return BINARY_BASENAMES.has(base) || base.endsWith('.journal');
  }

  private resetAuditRules(): void {
    this.auditRules = [
      { rule: '-a never,exit -F arch=b64 -F dir=/var/log/audit -F perm=wa', kind: 'never', target: '/var/log/audit', loaded: true },
      { rule: '-a never,exit -F arch=b32 -F dir=/var/log/audit -F perm=wa', kind: 'never', target: '/var/log/audit', loaded: true },
      { rule: '-a always,exit -F arch=b64 -F dir=/var/log -F perm=wa -k log_tamper', kind: 'always', target: '/var/log', key: 'log_tamper', loaded: true },
      { rule: '-a always,exit -F arch=b32 -F dir=/var/log -F perm=wa -k log_tamper', kind: 'always', target: '/var/log', key: 'log_tamper', loaded: true },
      { rule: '-a always,exit -F arch=b64 -F path=/home/kali/.bash_history -F perm=wa -k log_tamper', kind: 'always', target: '/home/kali/.bash_history', key: 'log_tamper', loaded: true },
      { rule: '-a always,exit -F arch=b64 -F path=/home/kali/.zsh_history -F perm=wa -k log_tamper', kind: 'always', target: '/home/kali/.zsh_history', key: 'log_tamper', loaded: true },
      { rule: '-a always,exit -F arch=b64 -F path=/root/.bash_history -F perm=wa -k log_tamper', kind: 'always', target: '/root/.bash_history', key: 'log_tamper', loaded: true },
    ];
  }

  public initSandbox(wipeExisting: boolean): void {
    if (wipeExisting && fs.existsSync(this.sandboxRoot)) {
      fs.rmSync(this.sandboxRoot, { recursive: true, force: true });
    }

    const dirs = [
      '/var/log',
      '/var/log/apt',
      '/var/log/apache2',
      '/var/log/nginx',
      '/var/log/audit',
      '/var/log/journal',
      '/var/lib/logrotate',
      '/var/lib/tamper_blocker',
      '/etc/audit/rules.d',
      '/opt/tamper_blocker',
      '/root',
      '/home/kali',
    ];
    for (const d of dirs) {
      fs.mkdirSync(this.toRealPath(d), { recursive: true });
    }

    const seedFiles: Array<[string, string | Buffer]> = [
      [
        '/var/log/auth.log',
        [
          '2026-11-16T05:10:02.114Z kali-sec sshd[1042]: Accepted publickey for kali from 10.14.2.19 port 51822 ssh2',
          '2026-11-16T05:12:18.401Z kali-sec sudo: kali : TTY=pts/0 ; PWD=/home/kali ; USER=root ; COMMAND=/usr/bin/systemctl status auditd',
          '2026-11-16T05:14:09.822Z kali-sec sshd[1190]: Failed password for invalid user admin from 192.168.56.77 port 44102 ssh2',
          '2026-11-16T05:15:31.019Z kali-sec pam_unix(sudo:session): session opened for user root by kali(uid=1000)',
        ].join('\n') + '\n',
      ],
      [
        '/var/log/syslog',
        [
          '2026-11-16T05:09:44.012Z kali-sec systemd[1]: Started OpenBSD Secure Shell server.',
          '2026-11-16T05:11:05.330Z kali-sec NetworkManager[621]: <info>  [1763269865.3301] device (eth0): state change: ip-config -> activated',
          '2026-11-16T05:13:00.002Z kali-sec CRON[1124]: (root) CMD (command -v debian-sa1 > /dev/null && debian-sa1 1 1)',
          '2026-11-16T05:16:12.509Z kali-sec rsyslogd: [origin software="rsyslogd" swVersion="8.2408.0"] rsyslogd was HUPed',
        ].join('\n') + '\n',
      ],
      [
        '/var/log/kern.log',
        [
          '2026-11-16T05:08:01.001Z kali-sec kernel: [    0.000000] Linux version 6.11.2-kali1-amd64 (devel@kali.org)',
          '2026-11-16T05:08:04.221Z kali-sec kernel: [    3.218940] EXT4-fs (sda1): mounted filesystem 8c9a12e4-19f3 with ordered data mode.',
          '2026-11-16T05:14:40.910Z kali-sec kernel: [  399.840120] [UFW BLOCK] IN=eth0 OUT= SRC=185.220.101.44 DST=10.14.2.10 PROTO=TCP SPT=51203 DPT=22 SYN',
        ].join('\n') + '\n',
      ],
      [
        '/var/log/dpkg.log',
        [
          '2026-11-16 04:52:10 startup archives unpack',
          '2026-11-16 04:52:14 install auditd:amd64 <none> 1:4.1.2-1',
          '2026-11-16 04:52:16 status installed auditd:amd64 1:4.1.2-1',
          '2026-11-16 04:52:20 status installed audispd-plugins:amd64 1:4.1.2-1',
        ].join('\n') + '\n',
      ],
      [
        '/var/log/apt/history.log',
        [
          'Start-Date: 2026-11-16  04:52:09',
          'Commandline: apt install -y auditd python3-pip python3-tk python3-yaml audispd-plugins libnotify-bin',
          'Requested-By: kali (1000)',
          'Install: auditd:amd64 (1:4.1.2-1), audispd-plugins:amd64 (1:4.1.2-1)',
          'End-Date: 2026-11-16  04:52:21',
        ].join('\n') + '\n',
      ],
      [
        '/var/log/apache2/access.log',
        [
          '10.14.2.19 - - [16/Nov/2026:05:11:44 +0000] "GET /status HTTP/1.1" 200 412 "-" "curl/8.9.1"',
          '192.168.56.77 - - [16/Nov/2026:05:14:18 +0000] "GET /.env HTTP/1.1" 404 196 "-" "python-requests/2.32.3"',
        ].join('\n') + '\n',
      ],
      [
        '/var/log/apache2/error.log',
        '[Sat Nov 16 05:14:18.104219 2026] [core:warn] [pid 988] AH00128: File does not exist: /var/www/html/.env\n',
      ],
      [
        '/var/log/nginx/error.log',
        '2026/11/16 05:13:22 [warn] 941#941: *14 limiting requests, excess: 5.100 by zone "api_limit", client: 192.168.56.77\n',
      ],
      [
        '/var/log/audit/audit.log',
        [
          'type=SYSCALL msg=audit(1763269920.104:410): arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c a1=55f1a20 a2=441 a3=1b6 items=1 ppid=1042 pid=1210 auid=1000 uid=0 gid=0 euid=0 comm="tee" exe="/usr/bin/tee" key="log_tamper"',
          'type=PATH msg=audit(1763269920.104:410): item=0 name="/var/log/auth.log" inode=900101 dev=08:01 mode=0100640 ouid=0 ogid=4 rdev=00:00',
        ].join('\n') + '\n',
      ],
      [
        '/var/log/test.log',
        '2026-11-16T05:15:00.000Z kali-sec test: baseline test.log entry\n',
      ],
      [
        '/var/log/wtmp',
        Buffer.from('WTMP\x00\x07\x00\x00kali\x00\x00\x00\x00pts/0\x00\x00\x0010.14.2.19\x00\x00\x00\x00\x00\x00', 'binary'),
      ],
      [
        '/var/log/btmp',
        Buffer.from('BTMP\x00\x06\x00\x00admin\x00\x00\x00ssh:notty\x00192.168.56.77\x00\x00', 'binary'),
      ],
      [
        '/var/log/lastlog',
        Buffer.from('LASTLOG\x00\x00\x00kali\x00pts/0\x0010.14.2.19\x00\x00\x00\x00', 'binary'),
      ],
      [
        '/var/log/journal/system.journal',
        Buffer.from('LPKSHHRH\x00\x00\x00\x00system.journal.active\x00\x01\x02\x03\x04\x05\x06\x07', 'binary'),
      ],
      [
        '/root/.bash_history',
        [
          'systemctl status auditd',
          'auditctl -l',
          'journalctl -n 20',
        ].join('\n') + '\n',
      ],
      [
        '/home/kali/.bash_history',
        [
          'whoami',
          'sudo apt update',
          'tail -n 20 /var/log/auth.log',
          'sudo tamplogs --verify',
        ].join('\n') + '\n',
      ],
      [
        '/home/kali/.zsh_history',
        [
          ': 1763269500:0;ip addr show',
          ': 1763269610:0;sudo systemctl status rsyslog',
        ].join('\n') + '\n',
      ],
      [
        '/var/lib/logrotate/status',
        'logrotate state -- version 2\n"/var/log/syslog" 2026-11-15-0:0:1\n"/var/log/auth.log" 2026-11-15-0:0:1\n',
      ],
      [
        '/etc/audit/rules.d/log_tamper.rules',
        [
          '-a never,exit -F arch=b64 -F dir=/var/log/audit -F perm=wa',
          '-a never,exit -F arch=b32 -F dir=/var/log/audit -F perm=wa',
          '-a always,exit -F arch=b64 -F dir=/var/log -F perm=wa -k log_tamper',
          '-a always,exit -F arch=b32 -F dir=/var/log -F perm=wa -k log_tamper',
        ].join('\n') + '\n',
      ],
      ['/opt/tamper_blocker/config.yaml', DEFAULT_CONFIG_YAML],
      ['/var/lib/tamper_blocker/alerts.chain', ''],
      ['/var/lib/tamper_blocker/mirror.chain', ''],
    ];

    for (const [vPath, content] of seedFiles) {
      const real = this.toRealPath(vPath);
      if (wipeExisting || !fs.existsSync(real)) {
        fs.writeFileSync(real, content);
      }
      this.getVirtualMeta(vPath);
    }

    this.hardenedPaths.clear();
    for (const hp of INITIAL_HARDENED) {
      this.hardenedPaths.add(hp);
    }
    this.logs = [];
    this.alerts = [];
    this.alertSeq = 0;
    this.mirrorSeq = 0;
    this.eventSeq = 0;
    this.dedupMap.clear();
    this.logrotateSeenAt = 0;
    this.services = [
      { name: 'auditd', active: true, pid: 814, uptime: '4h 12m' },
      { name: 'rsyslog', active: true, pid: 902, uptime: '4h 12m' },
      { name: 'systemd-journald', active: true, pid: 412, uptime: '4h 12m' },
    ];
    this.resetAuditRules();
    this.rebuildAllBaselines();
    this.seedInitialEvents();
  }

  private seedInitialEvents(): void {
    const initialSeeds: Array<{ file: string; user: string; severity: Severity; source: LogEvent['source']; message: string }> = [
      {
        file: '/var/log/auth.log',
        user: 'kali',
        severity: 'INFO',
        source: 'inotify',
        message: 'Accepted publickey for kali from 10.14.2.19 port 51822 ssh2',
      },
      {
        file: '/var/log/auth.log',
        user: 'admin',
        severity: 'WARN',
        source: 'inotify',
        message: 'Failed password for invalid user admin from 192.168.56.77 port 44102 ssh2',
      },
      {
        file: '/var/log/syslog',
        user: 'system',
        severity: 'INFO',
        source: 'inotify',
        message: 'NetworkManager[621]: device (eth0): state change: ip-config -> activated',
      },
      {
        file: '/var/log/kern.log',
        user: 'system',
        severity: 'INFO',
        source: 'inotify',
        message: '[UFW BLOCK] IN=eth0 OUT= SRC=185.220.101.44 DST=10.14.2.10 PROTO=TCP DPT=22',
      },
      {
        file: '/var/log/dpkg.log',
        user: 'root',
        severity: 'INFO',
        source: 'inotify',
        message: 'status installed auditd:amd64 1:4.1.2-1',
      },
      {
        file: '/var/log/apt/history.log',
        user: 'kali',
        severity: 'INFO',
        source: 'inotify',
        message: 'Commandline: apt install -y auditd python3-pip python3-tk python3-yaml',
      },
      {
        file: '/var/log/apache2/access.log',
        user: 'www-data',
        severity: 'INFO',
        source: 'inotify',
        message: '10.14.2.19 "GET /status HTTP/1.1" 200 412',
      },
      {
        file: '/var/log/nginx/error.log',
        user: 'www-data',
        severity: 'WARN',
        source: 'inotify',
        message: 'limiting requests, excess: 5.100 by zone "api_limit", client: 192.168.56.77',
      },
      {
        file: 'journald/systemd',
        user: 'system',
        severity: 'INFO',
        source: 'journald',
        message: 'Started Tamper Blocker baseline watcher on Kali host kali-sec.',
      },
      {
        file: '/home/kali/.bash_history',
        user: 'kali',
        severity: 'INFO',
        source: 'inotify',
        message: 'sudo tamplogs --verify',
      },
    ];

    for (const item of initialSeeds) {
      this.pushLogEvent({
        severity: item.severity,
        user: item.user,
        file: item.file,
        source: item.source,
        message: item.message,
      }, false);
    }
  }

  private computeBaseline(vPath: string): BaselineRecord | null {
    const real = this.toRealPath(vPath);
    if (!fs.existsSync(real)) return null;
    const st = fs.lstatSync(real);
    if (!st.isFile()) return null;

    const inplaceOk = this.isInplaceOk(vPath);
    const meta = this.getVirtualMeta(vPath);
    const buf = fs.readFileSync(real);
    const plen = inplaceOk ? 0 : Math.min(buf.length, HASH_CAP_BYTES);
    const digest = inplaceOk ? '' : sha256Hex(buf.subarray(0, plen));

    let chunkCount = 0;
    if (!inplaceOk && buf.length > 0) {
      chunkCount = Math.ceil(buf.length / CHUNK_SIZE_BYTES);
    }

    const ino = Number(st.ino) + meta.virtualInoOffset;

    return {
      path: vPath,
      category: this.categoryForPath(vPath),
      exists: true,
      isBinary: this.isBinaryFile(vPath),
      inplaceOk,
      hardened: this.hardenedPaths.has(vPath),
      ino,
      size: st.size,
      mtimeMs: st.mtimeMs,
      mode: meta.mode,
      modeOctal: `0${meta.mode.toString(8)}`,
      uid: meta.uid,
      gid: meta.gid,
      ownerLabel: this.formatOwner(meta.uid, meta.gid),
      plen,
      digest,
      chunkCount,
      status: 'verified',
      lastEventAt: nowTimeShort(),
    };
  }

  private walkFiles(dirReal: string, out: string[]): void {
    if (!fs.existsSync(dirReal)) return;
    for (const entry of fs.readdirSync(dirReal, { withFileTypes: true })) {
      const full = path.join(dirReal, entry.name);
      if (entry.isDirectory()) {
        this.walkFiles(full, out);
      } else if (entry.isFile()) {
        out.push(this.toVirtualPath(full));
      }
    }
  }

  private rebuildAllBaselines(): void {
    this.baselines.clear();
    const candidates: string[] = [];
    this.walkFiles(this.toRealPath('/var/log'), candidates);
    for (const dir of ['/root', '/home/kali']) {
      const realDir = this.toRealPath(dir);
      if (fs.existsSync(realDir)) {
        for (const f of fs.readdirSync(realDir)) {
          if (/^\.[A-Za-z0-9]+_history$/.test(f)) {
            candidates.push(`${dir}/${f}`);
          }
        }
      }
    }
    candidates.push('/var/lib/tamper_blocker/alerts.chain');

    for (const vp of candidates) {
      const b = this.computeBaseline(vp);
      if (b) {
        this.baselines.set(vp, b);
      }
    }
  }

  private appendChainRecord(chainFile: '/var/lib/tamper_blocker/alerts.chain' | '/var/lib/tamper_blocker/mirror.chain', payload: Record<string, unknown>): ChainRecord {
    const real = this.toRealPath(chainFile);
    this.internalWritePaths.add(chainFile);
    let prev = GENESIS_HASH;
    let seq = 0;

    if (fs.existsSync(real)) {
      const rawLines = fs.readFileSync(real, 'utf8').split('\n').filter((l) => l.trim().length > 0);
      seq = rawLines.length;
      if (rawLines.length > 0) {
        try {
          const lastObj = JSON.parse(rawLines[rawLines.length - 1]) as { hash?: string };
          if (lastObj.hash) prev = lastObj.hash;
        } catch {
          // leave prev as genesis if corrupted
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
    fs.appendFileSync(real, JSON.stringify(fullRecord) + '\n', 'utf8');

    // Keep baseline synced for alerts.chain when written by Tamper Blocker itself
    if (chainFile === '/var/lib/tamper_blocker/alerts.chain') {
      const updated = this.computeBaseline(chainFile);
      if (updated) this.baselines.set(chainFile, updated);
    }

    setTimeout(() => {
      this.internalWritePaths.delete(chainFile);
    }, 150);

    return fullRecord;
  }

  public verifySingleChain(chainName: 'alerts.chain' | 'mirror.chain'): ChainVerifyResult {
    const vPath = `/var/lib/tamper_blocker/${chainName}`;
    const real = this.toRealPath(vPath);
    if (!fs.existsSync(real)) {
      return {
        chain: chainName,
        ok: true,
        brokenLine: null,
        totalLines: 0,
        headHash: GENESIS_HASH,
      };
    }

    const rawLines = fs.readFileSync(real, 'utf8').split('\n').filter((l) => l.trim().length > 0);
    let prev = GENESIS_HASH;
    for (let i = 0; i < rawLines.length; i += 1) {
      const lineNum = i + 1;
      let parsed: Record<string, unknown>;
      try {
        parsed = JSON.parse(rawLines[i]) as Record<string, unknown>;
      } catch {
        return {
          chain: chainName,
          ok: false,
          brokenLine: lineNum,
          totalLines: rawLines.length,
          reason: `Malformed JSON at line ${lineNum}`,
          headHash: prev,
        };
      }
      const recordedHash = parsed.hash;
      if (typeof recordedHash !== 'string' || parsed.prev !== prev) {
        return {
          chain: chainName,
          ok: false,
          brokenLine: lineNum,
          totalLines: rawLines.length,
          reason: `Previous hash mismatch at line ${lineNum}`,
          headHash: prev,
        };
      }
      const withoutHash: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(parsed)) {
        if (k !== 'hash') withoutHash[k] = v;
      }
      const expected = sha256Hex(prev + canonicalJson(withoutHash));
      if (expected !== recordedHash) {
        return {
          chain: chainName,
          ok: false,
          brokenLine: lineNum,
          totalLines: rawLines.length,
          reason: `SHA-256 digest mismatch at line ${lineNum} (record modified)`,
          headHash: prev,
        };
      }
      prev = recordedHash;
    }

    return {
      chain: chainName,
      ok: true,
      brokenLine: null,
      totalLines: rawLines.length,
      headHash: prev,
    };
  }

  public readChainTail(chainName: 'alerts.chain' | 'mirror.chain', limit = 40): ChainRecord[] {
    const real = this.toRealPath(`/var/lib/tamper_blocker/${chainName}`);
    if (!fs.existsSync(real)) return [];
    const lines = fs.readFileSync(real, 'utf8').split('\n').filter((l) => l.trim().length > 0);
    return lines.slice(-limit).reverse().map((line, idx) => {
      try {
        return JSON.parse(line) as ChainRecord;
      } catch {
        return {
          seq: lines.length - idx,
          ts: nowIso(),
          prev: 'INVALID_JSON',
          hash: 'CORRUPTED_LINE',
          line,
        };
      }
    });
  }

  private pushLogEvent(
    input: Omit<LogEvent, 'id' | 'ts' | 'timeShort'>,
    writeMirror = true,
  ): LogEvent {
    this.eventSeq += 1;
    const ev: LogEvent = {
      id: `ev-${Date.now()}-${this.eventSeq}`,
      ts: nowIso(),
      timeShort: nowTimeShort(),
      ...input,
    };
    this.logs.unshift(ev);
    if (this.logs.length > 500) {
      this.logs = this.logs.slice(0, 500);
    }
    if (writeMirror && !ev.isTamper) {
      this.mirrorSeq += 1;
      this.appendChainRecord('/var/lib/tamper_blocker/mirror.chain', {
        ts: ev.ts,
        severity: ev.severity,
        user: ev.user,
        file: ev.file,
        line: ev.message,
      });
    }
    this.emit('log', ev);
    return ev;
  }

  private isLogrotateRecent(): boolean {
    if (this.logrotateSeenAt > 0 && Date.now() - this.logrotateSeenAt < 60_000) {
      return true;
    }
    const statusReal = this.toRealPath('/var/lib/logrotate/status');
    if (fs.existsSync(statusReal)) {
      const st = fs.statSync(statusReal);
      if (Date.now() - st.mtimeMs < 60_000 && this.logrotateSeenAt > 0) {
        return true;
      }
    }
    return false;
  }

  private appendAuditRecord(user: string, comm: string, exe: string, pid: number, targetPath: string): void {
    const auditVPath = '/var/log/audit/audit.log';
    const real = this.toRealPath(auditVPath);
    const epoch = (Date.now() / 1000).toFixed(3);
    const msgId = Math.floor(420 + Math.random() * 9000);
    const uid = user === 'kali' ? 1000 : 0;
    const lines = [
      `type=SYSCALL msg=audit(${epoch}:${msgId}): arch=c000003e syscall=257 success=yes exit=3 pid=${pid} auid=${uid} uid=0 comm="${comm}" exe="${exe}" key="log_tamper"`,
      `type=PATH msg=audit(${epoch}:${msgId}): item=0 name="${targetPath}" inode=${this.inoSeq} mode=0100640 ouid=0 ogid=4`,
    ];
    this.internalWritePaths.add(auditVPath);
    fs.appendFileSync(real, lines.join('\n') + '\n', 'utf8');
    const b = this.computeBaseline(auditVPath);
    if (b) this.baselines.set(auditVPath, b);
    setTimeout(() => this.internalWritePaths.delete(auditVPath), 120);
  }

  private fireTamperAlert(params: {
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
    const dedupKey = `${params.path}::${params.kind}`;
    const prevTs = this.dedupMap.get(dedupKey) ?? 0;
    if (Date.now() - prevTs < 3000) {
      return null;
    }
    this.dedupMap.set(dedupKey, Date.now());

    this.alertSeq += 1;
    const ts = nowIso();
    const timeShort = nowTimeShort();
    const severity = params.severity ?? 'CRIT';

    const chainRec = this.appendChainRecord('/var/lib/tamper_blocker/alerts.chain', {
      ts,
      kind: params.kind,
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
      id: `alt-${Date.now()}-${this.alertSeq}`,
      seq: this.alertSeq,
      ts,
      timeShort,
      kind: params.kind,
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
    if (this.alerts.length > 200) {
      this.alerts = this.alerts.slice(0, 200);
    }

    this.pushLogEvent(
      {
        severity,
        user: params.user,
        file: params.path,
        source: 'auditd',
        message: `${params.kind}: ${params.explanation} (comm=${params.comm} pid=${params.pid})`,
        isTamper: true,
        ruleKind: params.kind,
      },
      false,
    );

    this.emit('alert', alert);
    this.emit('status', this.getStatus());
    return alert;
  }

  private extractUserFromLine(vPath: string, line: string): string {
    const m1 = line.match(/sudo:\s+(\S+)\s+:/);
    if (m1) return m1[1];
    const m2 = line.match(/session opened for user \S+ by ([^(\s]+)\(/);
    if (m2) return m2[1];
    const m3 = line.match(/(?:Accepted|Failed)\s+\S+\s+for\s+(?:invalid user\s+)?(\S+)/);
    if (m3) return m3[1];
    const m4 = line.match(/for user (\S+)/);
    if (m4) return m4[1];
    if (vPath.startsWith('/home/')) {
      const parts = vPath.split('/');
      if (parts.length > 2) return parts[2];
    }
    if (vPath.startsWith('/root/')) return 'root';
    return 'system';
  }

  private classifyLineSeverity(line: string): Severity {
    if (CRIT_RE.test(line)) return 'CRIT';
    if (WARN_RE.test(line)) return 'WARN';
    return 'INFO';
  }

  private checkPathIntegrity(
    vPath: string,
    actor: { user: string; comm: string; exe: string; pid: number },
  ): DetectionRuleKind[] {
    if (!this.monitoringActive) return [];
    if (this.internalWritePaths.has(vPath)) return [];

    const triggered: DetectionRuleKind[] = [];
    const base = this.baselines.get(vPath);
    const real = this.toRealPath(vPath);

    if (!fs.existsSync(real)) {
      if (base) {
        if (this.isLogrotateRecent()) {
          this.pushLogEvent({
            severity: 'INFO',
            user: 'logrotate',
            file: vPath,
            source: 'inotify',
            message: 'Log rotated / moved by logrotate (allowed)',
          });
          base.exists = false;
          base.status = 'rotated';
        } else {
          const alert = this.fireTamperAlert({
            path: vPath,
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
          this.baselines.set(vPath, {
            ...base,
            exists: false,
            size: 0,
            status: 'missing',
            lastEventAt: nowTimeShort(),
          });
        }
        this.emit('baselines', this.getBaselines());
      }
      return triggered;
    }

    const st = fs.lstatSync(real);
    if (!st.isFile()) return triggered;

    if (!base || !base.exists) {
      const created = this.computeBaseline(vPath);
      if (created) {
        this.baselines.set(vPath, created);
        this.emit('baselines', this.getBaselines());
      }
      return triggered;
    }

    const meta = this.getVirtualMeta(vPath);
    const currentIno = Number(st.ino) + meta.virtualInoOffset;

    if (currentIno !== base.ino) {
      if (this.isLogrotateRecent()) {
        this.pushLogEvent({
          severity: 'INFO',
          user: 'logrotate',
          file: vPath,
          source: 'inotify',
          message: `Inode replaced during rotation ${base.ino} -> ${currentIno} (allowed)`,
        });
        const refreshed = this.computeBaseline(vPath);
        if (refreshed) {
          refreshed.status = 'rotated';
          this.baselines.set(vPath, refreshed);
        }
      } else {
        const alert = this.fireTamperAlert({
          path: vPath,
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
        const refreshed = this.computeBaseline(vPath);
        if (refreshed) {
          refreshed.status = 'tampered';
          this.baselines.set(vPath, refreshed);
        }
      }
      this.emit('baselines', this.getBaselines());
      return triggered;
    }

    if (meta.mode !== base.mode || meta.uid !== base.uid || meta.gid !== base.gid) {
      const alert = this.fireTamperAlert({
        path: vPath,
        kind: 'PERM_OWNER_CHANGE',
        user: actor.user,
        comm: actor.comm,
        exe: actor.exe,
        pid: actor.pid,
        explanation: `Permissions or ownership modified (${base.modeOctal} ${base.ownerLabel} -> 0${meta.mode.toString(8)} ${this.formatOwner(meta.uid, meta.gid)})`,
        beforeSummary: `mode=${base.modeOctal} owner=${base.ownerLabel}`,
        afterSummary: `mode=0${meta.mode.toString(8)} owner=${this.formatOwner(meta.uid, meta.gid)}`,
      });
      if (alert) triggered.push('PERM_OWNER_CHANGE');
      const refreshed = this.computeBaseline(vPath);
      if (refreshed) {
        refreshed.status = 'tampered';
        this.baselines.set(vPath, refreshed);
      }
      this.emit('baselines', this.getBaselines());
      return triggered;
    }

    if (st.size < base.size) {
      if (this.isLogrotateRecent()) {
        this.pushLogEvent({
          severity: 'INFO',
          user: 'logrotate',
          file: vPath,
          source: 'inotify',
          message: `Copytruncate rotation ${base.size}B -> ${st.size}B (allowed)`,
        });
        const refreshed = this.computeBaseline(vPath);
        if (refreshed) {
          refreshed.status = 'rotated';
          this.baselines.set(vPath, refreshed);
        }
      } else {
        const isHist = vPath.includes('_history');
        const alert = this.fireTamperAlert({
          path: vPath,
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
        const refreshed = this.computeBaseline(vPath);
        if (refreshed) {
          refreshed.status = 'tampered';
          this.baselines.set(vPath, refreshed);
        }
      }
      this.emit('baselines', this.getBaselines());
      return triggered;
    }

    const buf = fs.readFileSync(real);
    if (!base.inplaceOk && base.plen > 0) {
      const currentPrefixHash = sha256Hex(buf.subarray(0, base.plen));
      if (currentPrefixHash !== base.digest) {
        const isHist = vPath.includes('_history');
        const alert = this.fireTamperAlert({
          path: vPath,
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
        const refreshed = this.computeBaseline(vPath);
        if (refreshed) {
          refreshed.status = 'tampered';
          this.baselines.set(vPath, refreshed);
        }
        this.emit('baselines', this.getBaselines());
        return triggered;
      }
    }

    // Safe append!
    if (st.size > base.size && !this.isBinaryFile(vPath) && !TAIL_SKIP_PATHS.has(vPath)) {
      const newText = buf.subarray(base.size).toString('utf8');
      for (const line of newText.split('\n')) {
        if (!line.trim()) continue;
        this.pushLogEvent({
          severity: this.classifyLineSeverity(line),
          user: this.extractUserFromLine(vPath, line),
          file: vPath,
          source: 'inotify',
          message: line,
        });
      }
    }

    const refreshed = this.computeBaseline(vPath);
    if (refreshed) {
      refreshed.status = base.status === 'tampered' ? 'tampered' : 'verified';
      this.baselines.set(vPath, refreshed);
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
    this.startNoiseLoop();

    this.pushLogEvent({
      severity: 'INFO',
      user: 'root',
      file: '/opt/tamper_blocker',
      source: 'tamplogs',
      message: `tamplogs started (${mode} mode) — watching ${this.baselines.size} files across /var/log, journald & shell histories`,
    }, false);

    this.emit('status', this.getStatus());
    this.emit('baselines', this.getBaselines());
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
    if (this.noiseTimer) {
      clearInterval(this.noiseTimer);
      this.noiseTimer = null;
    }
    this.pushLogEvent({
      severity: 'WARN',
      user: 'root',
      file: '/opt/tamper_blocker',
      source: 'tamplogs',
      message: 'tamplogs real-time monitoring stopped by user',
    }, false);
    this.emit('status', this.getStatus());
  }

  public setLiveNoise(enabled: boolean): void {
    this.liveNoiseEnabled = enabled;
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

    const watchDirs = ['/var/log', '/root', '/home/kali', '/var/lib/tamper_blocker'];
    for (const dir of watchDirs) {
      const real = this.toRealPath(dir);
      if (!fs.existsSync(real)) continue;
      try {
        const watcher = fs.watch(real, { recursive: dir === '/var/log' }, (_eventType, filename) => {
          if (!filename || !this.monitoringActive) return;
          const vPath = path.posix.join(dir, filename.toString().split(path.sep).join('/'));
          if (this.internalWritePaths.has(vPath)) return;
          this.checkPathIntegrity(vPath, {
            user: 'external',
            comm: 'fs-modify',
            exe: '/usr/bin/unknown',
            pid: ++this.pidCounter,
          });
        });
        this.watchers.push(watcher);
      } catch {
        // recursive watch fallback ignored on unsupported fs
      }
    }
  }

  private startNoiseLoop(): void {
    if (this.noiseTimer) clearInterval(this.noiseTimer);
    const templates: Array<{ file: string; line: string; source: LogEvent['source'] }> = [
      {
        file: '/var/log/syslog',
        source: 'inotify',
        line: 'systemd[1]: Starting Cleanup of Temporary Directories...',
      },
      {
        file: '/var/log/auth.log',
        source: 'inotify',
        line: 'sshd[2140]: Connection closed by authenticating user kali 10.14.2.19 port 51914 [preauth]',
      },
      {
        file: '/var/log/kern.log',
        source: 'inotify',
        line: '[UFW BLOCK] IN=eth0 OUT= SRC=45.155.205.91 DST=10.14.2.10 PROTO=TCP DPT=445 SYN',
      },
      {
        file: '/var/log/apache2/access.log',
        source: 'inotify',
        line: '10.14.2.19 - kali [16/Nov/2026] "GET /healthz HTTP/1.1" 200 128 "-" "Mozilla/5.0"',
      },
      {
        file: 'journald/NetworkManager',
        source: 'journald',
        line: 'policy: set "Wired connection 1" (eth0) as default for IPv4 routing and DNS',
      },
    ];
    let idx = 0;

    this.noiseTimer = setInterval(() => {
      if (!this.monitoringActive || !this.liveNoiseEnabled) return;
      const sample = templates[idx % templates.length];
      idx += 1;

      if (sample.source === 'journald') {
        const jSvc = this.services.find((s) => s.name === 'systemd-journald');
        if (jSvc && !jSvc.active) return;
        this.pushLogEvent({
          severity: 'INFO',
          user: 'system',
          file: sample.file,
          source: 'journald',
          message: sample.line,
        });
        return;
      }

      const rsyslogSvc = this.services.find((s) => s.name === 'rsyslog');
      if (rsyslogSvc && !rsyslogSvc.active) return;

      const real = this.toRealPath(sample.file);
      if (!fs.existsSync(real)) return;
      const tsPrefix = new Date().toISOString();
      const fullLine = `${tsPrefix} kali-sec ${sample.line}\n`;
      this.internalWritePaths.add(sample.file);
      fs.appendFileSync(real, fullLine, 'utf8');
      setTimeout(() => this.internalWritePaths.delete(sample.file), 120);

      // Process as safe append manually right away so mirror.chain & baseline stay exact
      const base = this.baselines.get(sample.file);
      if (base) {
        this.pushLogEvent({
          severity: this.classifyLineSeverity(fullLine),
          user: this.extractUserFromLine(sample.file, fullLine),
          file: sample.file,
          source: 'inotify',
          message: fullLine.trim(),
        });
        const refreshed = this.computeBaseline(sample.file);
        if (refreshed) {
          refreshed.status = base.status === 'tampered' ? 'tampered' : 'verified';
          this.baselines.set(sample.file, refreshed);
          this.emit('baselines', this.getBaselines());
        }
      }
    }, 4500);
  }

  public hardenFiles(pathsToHarden?: string[]): string[] {
    const targets = pathsToHarden ?? Array.from(INITIAL_HARDENED);
    const out: string[] = [];
    for (const p of targets) {
      if (fs.existsSync(this.toRealPath(p))) {
        this.hardenedPaths.add(p);
        const b = this.baselines.get(p);
        if (b) b.hardened = true;
        out.push(`[ok] chattr +a ${p}`);
      } else {
        out.push(`[skip] ${p} does not exist`);
      }
    }
    this.emit('baselines', this.getBaselines());
    return out;
  }

  public unhardenFiles(pathsToUnharden?: string[]): string[] {
    const targets = pathsToUnharden ?? Array.from(this.hardenedPaths);
    const out: string[] = [];
    for (const p of targets) {
      this.hardenedPaths.delete(p);
      const b = this.baselines.get(p);
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
    this.emit('alerts_updated', this.alerts);
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
    this.emit('alerts_updated', this.alerts);
    this.emit('status', this.getStatus());
    return count;
  }

  public rebaselineFile(vPath: string): BaselineRecord | null {
    const b = this.computeBaseline(vPath);
    if (!b) return null;
    this.baselines.set(vPath, b);
    this.pushLogEvent({
      severity: 'INFO',
      user: 'root',
      file: vPath,
      source: 'tamplogs',
      message: `Manual re-baseline completed (size=${b.size}B sha256=${b.digest.slice(0, 12)}...)`,
    }, false);
    this.emit('baselines', this.getBaselines());
    return b;
  }

  public corruptChainDemo(): { line: number } {
    const real = this.toRealPath('/var/lib/tamper_blocker/alerts.chain');
    let lines = fs.existsSync(real)
      ? fs.readFileSync(real, 'utf8').split('\n').filter((l) => l.trim().length > 0)
      : [];
    if (lines.length === 0) {
      this.fireTamperAlert({
        path: '/var/log/test.log',
        kind: 'CONTENT_MODIFIED',
        user: 'kali',
        comm: 'demo-seed',
        exe: '/usr/bin/tamper',
        pid: ++this.pidCounter,
        explanation: 'Seeded alert entry prior to chain tamper demonstration',
        beforeSummary: 'sha256=demo0000',
        afterSummary: 'sha256=demo1111',
      });
      lines = fs.readFileSync(real, 'utf8').split('\n').filter((l) => l.trim().length > 0);
    }
    const targetIdx = Math.max(0, lines.length - 1);
    try {
      const obj = JSON.parse(lines[targetIdx]) as Record<string, unknown>;
      obj.explanation = 'TAMPERED_CHAIN_PAYLOAD_BY_ATTACKER';
      lines[targetIdx] = JSON.stringify(obj);
    } catch {
      lines[targetIdx] = '{"corrupted":true}';
    }
    this.internalWritePaths.add('/var/lib/tamper_blocker/alerts.chain');
    fs.writeFileSync(real, lines.join('\n') + '\n', 'utf8');
    setTimeout(() => this.internalWritePaths.delete('/var/lib/tamper_blocker/alerts.chain'), 150);
    this.emit('chain', {
      alerts: this.verifySingleChain('alerts.chain'),
      mirror: this.verifySingleChain('mirror.chain'),
    });
    return { line: targetIdx + 1 };
  }

  public readFileContent(vPath: string): { exists: boolean; isBinary: boolean; content: string; size: number; sha256: string } {
    const real = this.toRealPath(vPath);
    if (!fs.existsSync(real)) {
      return { exists: false, isBinary: false, content: '', size: 0, sha256: '' };
    }
    const buf = fs.readFileSync(real);
    const isBin = this.isBinaryFile(vPath);
    const content = isBin
      ? buf.subarray(0, 2048).toString('hex').replace(/(.{2})/g, '$1 ').trim()
      : buf.toString('utf8').slice(-32000);
    return {
      exists: true,
      isBinary: isBin,
      content,
      size: buf.length,
      sha256: sha256Hex(buf),
    };
  }

  public executeCommand(rawCmd: string): TerminalExecResult {
    const cmd = rawCmd.trim();
    const cwd = '/home/kali';
    const stdout: string[] = [];
    const stderr: string[] = [];
    const triggered = new Set<DetectionRuleKind>();
    let exitCode = 0;
    let monitorAction: TerminalExecResult['monitorAction'];

    if (!cmd) {
      return { command: rawCmd, stdout, stderr, exitCode: 0, cwd, triggeredRules: [] };
    }

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

    // Handle chained commands separated by ; or &&
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
    const isSudo = /\bsudo\b/.test(cmd);
    const user = isSudo ? 'kali' : 'kali';

    // 1. tamplogs / tamper_blocker CLI
    const normalized = cmd.replace(/^sudo\s+/, '');
    if (/^(tamplogs|tamper_blocker|python3\s+\/opt\/tamper_blocker\/tamper_blocker\.py)\b/.test(normalized)) {
      const args = normalized.split(/\s+/).slice(1);
      if (args.includes('--help') || args.includes('-h')) {
        stdout.push(
          'usage: tamplogs [--headless] [--no-popup] [--harden] [--unharden] [--verify] [--status] [--stop]',
          '',
          'Tamper Blocker — Real-Time Kali Linux Log Integrity Monitor',
          '  (no flags)    Start real-time monitoring + live stream + persistent tamper popups',
          '  --headless    Start daemon monitoring without desktop popups',
          '  --no-popup    Start monitoring with desktop popups suppressed',
          '  --verify      Verify SHA-256 hash integrity of alerts.chain & mirror.chain',
          '  --harden      Apply chattr +a append-only protection to core logs & alert chain',
          '  --unharden    Remove chattr -a before logrotate runs',
          '  --status      Show watched files, auditd rules, and active services',
          '  --stop        Stop active monitoring',
        );
        return { command: rawCmd, stdout, stderr, exitCode: 0, cwd, triggeredRules: [] };
      }
      if (args.includes('--verify')) {
        const aRes = this.verifySingleChain('alerts.chain');
        const mRes = this.verifySingleChain('mirror.chain');
        stdout.push(`alerts.chain: ${aRes.ok ? 'True' : 'False'} ${aRes.brokenLine ?? 'None'} (${aRes.totalLines} records)`);
        stdout.push(`mirror.chain: ${mRes.ok ? 'True' : 'False'} ${mRes.brokenLine ?? 'None'} (${mRes.totalLines} records)`);
        if (!aRes.ok) stdout.push(`  [!] alerts.chain failure: ${aRes.reason}`);
        if (!mRes.ok) stdout.push(`  [!] mirror.chain failure: ${mRes.reason}`);
        return {
          command: rawCmd,
          stdout,
          stderr,
          exitCode: aRes.ok && mRes.ok ? 0 : 2,
          cwd,
          triggeredRules: [],
          monitorAction: 'verified',
        };
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
          `Host: ${st.hostname} (${st.kernel})`,
          `Watched Files: ${st.watchedFilesCount}`,
          `Audit Rules Loaded: ${st.auditRulesLoaded}`,
          `Unacknowledged Tamper Alerts: ${st.unacknowledgedCount}`,
          `Services: ${this.services.map((s) => `${s.name}=${s.active ? 'active' : 'inactive'}`).join(', ')}`,
        );
        return { command: rawCmd, stdout, stderr, exitCode: 0, cwd, triggeredRules: [], monitorAction: 'status' };
      }

      const mode: MonitorStatus['mode'] = args.includes('--headless')
        ? 'headless'
        : args.includes('--no-popup')
          ? 'no-popup'
          : 'interactive';
      this.startMonitoring(mode);
      stdout.push(
        `[tamplogs] Real-time File Integrity & Log-Tamper Monitor started (${mode} mode)`,
        `[tamplogs] Watching ${this.baselines.size} paths (/var/log/**, journald, shell histories, alerts.chain)`,
        `[tamplogs] auditd key=log_tamper rules verified: ${this.auditRules.filter((r) => r.loaded).length} active`,
        `[tamplogs] SHA-256 chain files: /var/lib/tamper_blocker/alerts.chain, /var/lib/tamper_blocker/mirror.chain`,
        `[tamplogs] Streaming live events to Dashboard & Terminal. Type 'tamplogs --verify' anytime to audit chains.`,
      );
      return { command: rawCmd, stdout, stderr, exitCode: 0, cwd, triggeredRules: [], monitorAction: 'started' };
    }

    // 2. Pipe append: echo "..." | sudo tee -a /var/log/file
    const teeMatch = cmd.match(/^echo\s+(['"]?)(.+?)\1\s*\|\s*(?:sudo\s+)?tee\s+-a\s+(\S+)$/);
    if (teeMatch) {
      const text = teeMatch[2];
      const target = teeMatch[3];
      const real = this.toRealPath(target);
      fs.mkdirSync(path.dirname(real), { recursive: true });
      this.internalWritePaths.add(target);
      fs.appendFileSync(real, text + '\n', 'utf8');
      this.appendAuditRecord(user, 'tee', '/usr/bin/tee', pid, target);
      setTimeout(() => this.internalWritePaths.delete(target), 120);
      this.internalWritePaths.delete(target); // check immediately
      const rules = this.checkPathIntegrity(target, { user, comm: 'tee', exe: '/usr/bin/tee', pid });
      rules.forEach((r) => triggered.add(r));
      stdout.push(text);
      return { command: rawCmd, stdout, stderr, exitCode: 0, cwd, triggeredRules: Array.from(triggered) };
    }

    // 3. Shell redirect overwrite: echo "..." > /var/log/file or > /var/log/file
    const redirectMatch = cmd.match(/^(?:echo\s+(['"]?)(.*?)\1\s*)?>\s*(\S+)$/);
    if (redirectMatch) {
      const text = redirectMatch[2] ?? '';
      const target = redirectMatch[3];
      if (this.hardenedPaths.has(target)) {
        stderr.push(`bash: ${target}: Operation not permitted (chattr +a append-only)`);
        return { command: rawCmd, stdout, stderr, exitCode: 1, cwd, triggeredRules: [] };
      }
      const real = this.toRealPath(target);
      fs.mkdirSync(path.dirname(real), { recursive: true });
      this.internalWritePaths.add(target);
      fs.writeFileSync(real, text ? text + '\n' : '', 'utf8');
      this.appendAuditRecord(user, 'bash', '/usr/bin/bash', pid, target);
      this.internalWritePaths.delete(target);

      if (this.monitoringActive) {
        const a = this.fireTamperAlert({
          path: target,
          kind: 'SHELL_REDIRECT_OR_HISTORY_WIPE',
          user,
          comm: 'bash',
          exe: '/usr/bin/bash',
          pid,
          explanation: `Shell output redirection (>) overwrote target ${target}`,
          beforeSummary: 'append-only stream',
          afterSummary: `overwritten via shell > (${text.length} bytes)`,
        });
        if (a) triggered.add('SHELL_REDIRECT_OR_HISTORY_WIPE');
      }
      this.checkPathIntegrity(target, { user, comm: 'bash', exe: '/usr/bin/bash', pid }).forEach((r) => triggered.add(r));
      return { command: rawCmd, stdout, stderr, exitCode: 0, cwd, triggeredRules: Array.from(triggered) };
    }

    // 4. sed -i 's/old/new/[g]' /var/log/file
    const sedMatch = normalized.match(/^sed\s+(?:-i|--in-place)\s+(['"])s\/([^/]*)\/([^/]*)\/(g?)\1\s+(\S+)$/);
    if (sedMatch) {
      const search = sedMatch[2];
      const replace = sedMatch[3];
      const globalFlag = sedMatch[4] === 'g';
      const target = sedMatch[5];
      if (this.hardenedPaths.has(target)) {
        stderr.push(`sed: couldn't open temporary file ${target}: Operation not permitted (chattr +a)`);
        return { command: rawCmd, stdout, stderr, exitCode: 4, cwd, triggeredRules: [] };
      }
      const real = this.toRealPath(target);
      if (!fs.existsSync(real)) {
        stderr.push(`sed: can't read ${target}: No such file or directory`);
        return { command: rawCmd, stdout, stderr, exitCode: 2, cwd, triggeredRules: [] };
      }
      const current = fs.readFileSync(real, 'utf8');
      const regex = new RegExp(search, globalFlag ? 'g' : '');
      const next = current.replace(regex, replace);
      this.internalWritePaths.add(target);
      fs.writeFileSync(real, next, 'utf8');
      // sed -i creates a new inode via temp file + rename
      const meta = this.getVirtualMeta(target);
      meta.virtualInoOffset += 1;
      this.appendAuditRecord(user, 'sed', '/usr/bin/sed', pid, target);
      this.internalWritePaths.delete(target);

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

    // 5. truncate -s <size> <path>
    const truncMatch = normalized.match(/^truncate\s+-s\s+(\d+)\s+(\S+)$/);
    if (truncMatch) {
      const size = Number(truncMatch[1]);
      const target = truncMatch[2];
      if (this.hardenedPaths.has(target)) {
        stderr.push(`truncate: failed to truncate '${target}' at ${size} bytes: Operation not permitted (chattr +a)`);
        return { command: rawCmd, stdout, stderr, exitCode: 1, cwd, triggeredRules: [] };
      }
      const real = this.toRealPath(target);
      if (!fs.existsSync(real)) {
        stderr.push(`truncate: cannot open '${target}': No such file or directory`);
        return { command: rawCmd, stdout, stderr, exitCode: 1, cwd, triggeredRules: [] };
      }
      this.internalWritePaths.add(target);
      fs.truncateSync(real, size);
      this.appendAuditRecord(user, 'truncate', '/usr/bin/truncate', pid, target);
      this.internalWritePaths.delete(target);

      if (this.monitoringActive) {
        const a = this.fireTamperAlert({
          path: target,
          kind: 'LOG_FILE_COMMAND',
          user,
          comm: 'truncate',
          exe: '/usr/bin/truncate',
          pid,
          explanation: `Destructive process detected: ${cmd}`,
          beforeSummary: 'process cmdline scan',
          afterSummary: `truncate pid=${pid}`,
        });
        if (a) triggered.add('LOG_FILE_COMMAND');
      }
      this.checkPathIntegrity(target, { user, comm: 'truncate', exe: '/usr/bin/truncate', pid }).forEach((r) => triggered.add(r));
      return { command: rawCmd, stdout, stderr, exitCode: 0, cwd, triggeredRules: Array.from(triggered) };
    }

    // 6. chmod <octal> <path>
    const chmodMatch = normalized.match(/^chmod\s+([0-7]{3,4})\s+(\S+)$/);
    if (chmodMatch) {
      const modeVal = parseInt(chmodMatch[1], 8);
      const target = chmodMatch[2];
      if (!fs.existsSync(this.toRealPath(target))) {
        stderr.push(`chmod: cannot access '${target}': No such file or directory`);
        return { command: rawCmd, stdout, stderr, exitCode: 1, cwd, triggeredRules: [] };
      }
      const meta = this.getVirtualMeta(target);
      meta.mode = modeVal;
      this.appendAuditRecord(user, 'chmod', '/usr/bin/chmod', pid, target);
      this.checkPathIntegrity(target, { user, comm: 'chmod', exe: '/usr/bin/chmod', pid }).forEach((r) => triggered.add(r));
      return { command: rawCmd, stdout, stderr, exitCode: 0, cwd, triggeredRules: Array.from(triggered) };
    }

    // 7. chown <user[:group]> <path>
    const chownMatch = normalized.match(/^chown\s+(\S+)\s+(\S+)$/);
    if (chownMatch) {
      const ownerSpec = chownMatch[1];
      const target = chownMatch[2];
      if (!fs.existsSync(this.toRealPath(target))) {
        stderr.push(`chown: cannot access '${target}': No such file or directory`);
        return { command: rawCmd, stdout, stderr, exitCode: 1, cwd, triggeredRules: [] };
      }
      const meta = this.getVirtualMeta(target);
      const [uName, gName] = ownerSpec.split(':');
      if (uName === 'kali') meta.uid = 1000;
      else if (uName === 'root') meta.uid = 0;
      else if (uName === 'www-data') meta.uid = 33;
      if (gName === 'kali') meta.gid = 1000;
      else if (gName === 'root') meta.gid = 0;
      else if (gName === 'adm') meta.gid = 4;
      this.appendAuditRecord(user, 'chown', '/usr/bin/chown', pid, target);
      this.checkPathIntegrity(target, { user, comm: 'chown', exe: '/usr/bin/chown', pid }).forEach((r) => triggered.add(r));
      return { command: rawCmd, stdout, stderr, exitCode: 0, cwd, triggeredRules: Array.from(triggered) };
    }

    // 8. rm / shred / unlink / wipe <path>
    const rmMatch = normalized.match(/^(rm|shred|unlink|wipe|srm)(?:\s+-[A-Za-z]+)*\s+(\S+)$/);
    if (rmMatch) {
      const bin = rmMatch[1];
      const target = rmMatch[2];
      if (this.hardenedPaths.has(target)) {
        stderr.push(`${bin}: cannot remove '${target}': Operation not permitted (chattr +a)`);
        return { command: rawCmd, stdout, stderr, exitCode: 1, cwd, triggeredRules: [] };
      }
      const real = this.toRealPath(target);
      if (!fs.existsSync(real)) {
        stderr.push(`${bin}: cannot remove '${target}': No such file or directory`);
        return { command: rawCmd, stdout, stderr, exitCode: 1, cwd, triggeredRules: [] };
      }
      this.internalWritePaths.add(target);
      fs.rmSync(real, { force: true });
      this.appendAuditRecord(user, bin, `/usr/bin/${bin}`, pid, target);
      this.internalWritePaths.delete(target);

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

    // 9. mv <src> <dst>
    const mvMatch = normalized.match(/^mv\s+(\S+)\s+(\S+)$/);
    if (mvMatch) {
      const src = mvMatch[1];
      const dst = mvMatch[2];
      if (this.hardenedPaths.has(src)) {
        stderr.push(`mv: cannot move '${src}': Operation not permitted (chattr +a)`);
        return { command: rawCmd, stdout, stderr, exitCode: 1, cwd, triggeredRules: [] };
      }
      const srcReal = this.toRealPath(src);
      const dstReal = this.toRealPath(dst);
      if (!fs.existsSync(srcReal)) {
        stderr.push(`mv: cannot stat '${src}': No such file or directory`);
        return { command: rawCmd, stdout, stderr, exitCode: 1, cwd, triggeredRules: [] };
      }
      fs.mkdirSync(path.dirname(dstReal), { recursive: true });
      this.internalWritePaths.add(src);
      this.internalWritePaths.add(dst);
      fs.renameSync(srcReal, dstReal);
      this.appendAuditRecord(user, 'mv', '/usr/bin/mv', pid, src);
      this.internalWritePaths.delete(src);
      this.internalWritePaths.delete(dst);

      if (this.monitoringActive) {
        const a = this.fireTamperAlert({
          path: src,
          kind: 'LOG_FILE_COMMAND',
          user,
          comm: 'mv',
          exe: '/usr/bin/mv',
          pid,
          explanation: `mv relocated log file ${src} -> ${dst}`,
          beforeSummary: src,
          afterSummary: dst,
        });
        if (a) triggered.add('LOG_FILE_COMMAND');
      }
      this.checkPathIntegrity(src, { user, comm: 'mv', exe: '/usr/bin/mv', pid }).forEach((r) => triggered.add(r));
      this.checkPathIntegrity(dst, { user, comm: 'mv', exe: '/usr/bin/mv', pid }).forEach((r) => triggered.add(r));
      return { command: rawCmd, stdout, stderr, exitCode: 0, cwd, triggeredRules: Array.from(triggered) };
    }

    // 10. dd / cp /dev/null overwrite
    const ddMatch = normalized.match(/^dd\s+.*if=\/dev\/(?:null|zero).*of=(\S+)/) || normalized.match(/^cp\s+\/dev\/null\s+(\S+)$/);
    if (ddMatch) {
      const target = ddMatch[1];
      const comm = normalized.startsWith('dd') ? 'dd' : 'cp';
      if (this.hardenedPaths.has(target)) {
        stderr.push(`${comm}: failed to open '${target}': Operation not permitted (chattr +a)`);
        return { command: rawCmd, stdout, stderr, exitCode: 1, cwd, triggeredRules: [] };
      }
      const real = this.toRealPath(target);
      this.internalWritePaths.add(target);
      fs.writeFileSync(real, '', 'utf8');
      this.appendAuditRecord(user, comm, `/usr/bin/${comm}`, pid, target);
      this.internalWritePaths.delete(target);

      if (this.monitoringActive) {
        const a = this.fireTamperAlert({
          path: target,
          kind: 'LOG_OVERWRITE',
          user,
          comm,
          exe: `/usr/bin/${comm}`,
          pid,
          explanation: `${comm} overwrote log file ${target} from /dev/null or /dev/zero`,
          beforeSummary: 'active log',
          afterSummary: 'zeroed by /dev/null',
        });
        if (a) triggered.add('LOG_OVERWRITE');
      }
      this.checkPathIntegrity(target, { user, comm, exe: `/usr/bin/${comm}`, pid }).forEach((r) => triggered.add(r));
      stdout.push(`0+0 records in`, `0+0 records out`);
      return { command: rawCmd, stdout, stderr, exitCode: 0, cwd, triggeredRules: Array.from(triggered) };
    }

    // 11. logrotate -f /etc/logrotate.conf
    if (/^logrotate\b/.test(normalized)) {
      this.logrotateSeenAt = Date.now();
      const statusReal = this.toRealPath('/var/lib/logrotate/status');
      this.internalWritePaths.add('/var/lib/logrotate/status');
      fs.writeFileSync(
        statusReal,
        `logrotate state -- version 2\n"/var/log/syslog" ${nowIso()}\n"/var/log/auth.log" ${nowIso()}\n`,
        'utf8',
      );
      this.internalWritePaths.delete('/var/lib/logrotate/status');

      // Rotate /var/log/apache2/access.log as an authentic demonstration (skip hardened files)
      const rotateTarget = '/var/log/apache2/access.log';
      const targetReal = this.toRealPath(rotateTarget);
      if (fs.existsSync(targetReal) && !this.hardenedPaths.has(rotateTarget)) {
        const rotatedReal = this.toRealPath(`${rotateTarget}.1`);
        this.internalWritePaths.add(rotateTarget);
        this.internalWritePaths.add(`${rotateTarget}.1`);
        fs.copyFileSync(targetReal, rotatedReal);
        fs.writeFileSync(targetReal, '', 'utf8');
        const meta = this.getVirtualMeta(rotateTarget);
        meta.virtualInoOffset += 1;
        this.internalWritePaths.delete(rotateTarget);
        this.internalWritePaths.delete(`${rotateTarget}.1`);
        this.checkPathIntegrity(rotateTarget, { user: 'root', comm: 'logrotate', exe: '/usr/sbin/logrotate', pid });
      } else {
        this.pushLogEvent({
          severity: 'INFO',
          user: 'logrotate',
          file: '/etc/logrotate.conf',
          source: 'service',
          message: 'logrotate run completed (whitelisted for 60s)',
        });
      }
      stdout.push('logrotate: rotated non-hardened logs cleanly (60s whitelist active).');
      return { command: rawCmd, stdout, stderr, exitCode: 0, cwd, triggeredRules: [] };
    }

    // 12. systemctl stop|start|status|restart <service>
    const svcMatch = normalized.match(/^systemctl\s+(stop|start|restart|status|disable|mask|is-active)\s+(auditd|rsyslog|systemd-journald|tamper-blocker)(?:\.service)?$/);
    if (svcMatch) {
      const action = svcMatch[1];
      const svcName = svcMatch[2];
      if (svcName === 'tamper-blocker') {
        stdout.push(this.monitoringActive ? 'active' : 'inactive');
        return { command: rawCmd, stdout, stderr, exitCode: this.monitoringActive ? 0 : 3, cwd, triggeredRules: [] };
      }
      const svc = this.services.find((s) => s.name === svcName);
      if (!svc) {
        stderr.push(`Unit ${svcName}.service could not be found.`);
        return { command: rawCmd, stdout, stderr, exitCode: 4, cwd, triggeredRules: [] };
      }
      if (action === 'is-active' || action === 'status') {
        stdout.push(svc.active ? `active (running) pid=${svc.pid}` : 'inactive (dead)');
        return { command: rawCmd, stdout, stderr, exitCode: svc.active ? 0 : 3, cwd, triggeredRules: [] };
      }
      if (action === 'stop' || action === 'disable' || action === 'mask') {
        const wasActive = svc.active;
        svc.active = false;
        if (wasActive && this.monitoringActive) {
          const a = this.fireTamperAlert({
            path: `service:${svc.name}`,
            kind: 'LOGGING_SERVICE_STOPPED',
            user,
            comm: 'systemctl',
            exe: '/usr/bin/systemctl',
            pid,
            explanation: `Logging service ${svc.name} transitioned active -> inactive (${action})`,
            beforeSummary: `${svc.name}=active`,
            afterSummary: `${svc.name}=inactive`,
          });
          if (a) triggered.add('LOGGING_SERVICE_STOPPED');
        }
        this.emit('services', this.services);
      } else {
        svc.active = true;
        svc.pid = ++this.pidCounter;
        this.pushLogEvent({
          severity: 'INFO',
          user: 'root',
          file: `service:${svc.name}`,
          source: 'service',
          message: `${svc.name} started (pid=${svc.pid})`,
        });
        this.emit('services', this.services);
      }
      return { command: rawCmd, stdout, stderr, exitCode: 0, cwd, triggeredRules: Array.from(triggered) };
    }

    // 13. journalctl --vacuum* or journalctl -n N
    if (/^journalctl\b/.test(normalized)) {
      if (/--vacuum/.test(normalized)) {
        if (this.monitoringActive) {
          const a = this.fireTamperAlert({
            path: '/var/log/journal',
            kind: 'JOURNAL_VACUUM',
            user,
            comm: 'journalctl',
            exe: '/usr/bin/journalctl',
            pid,
            explanation: `journald vacuum command executed: ${cmd}`,
            beforeSummary: 'journal intact',
            afterSummary: 'Vacuuming executed',
          });
          if (a) triggered.add('JOURNAL_VACUUM');
        }
        stdout.push('Vacuuming done, freed 0B of archived journals from /var/log/journal.');
        return { command: rawCmd, stdout, stderr, exitCode: 0, cwd, triggeredRules: Array.from(triggered) };
      }
      const recent = this.logs.slice(0, 15).reverse();
      for (const l of recent) {
        stdout.push(`${l.ts} kali-sec ${l.source}[0]: [${l.severity}] ${l.file}: ${l.message}`);
      }
      return { command: rawCmd, stdout, stderr, exitCode: 0, cwd, triggeredRules: [] };
    }

    // 14. auditctl
    if (/^auditctl\b/.test(normalized)) {
      if (normalized.includes(' -l')) {
        for (const r of this.auditRules) {
          if (r.loaded) stdout.push(r.rule);
        }
        return { command: rawCmd, stdout, stderr, exitCode: 0, cwd, triggeredRules: [] };
      }
      if (/(-D|-e\s*0|-d|-W)/.test(normalized)) {
        for (const r of this.auditRules) {
          if (r.kind === 'always') r.loaded = false;
        }
        if (this.monitoringActive) {
          const a1 = this.fireTamperAlert({
            path: '/etc/audit',
            kind: 'AUDIT_RULES_CHANGED',
            user,
            comm: 'auditctl',
            exe: '/usr/sbin/auditctl',
            pid,
            explanation: `Audit rule modification command detected: ${cmd}`,
            beforeSummary: '7 rules active',
            afterSummary: 'always rules cleared',
          });
          if (a1) triggered.add('AUDIT_RULES_CHANGED');

          const a2 = this.fireTamperAlert({
            path: '/etc/audit',
            kind: 'AUDIT_RULES_REMOVED',
            user: 'system',
            comm: 'tamper_blocker',
            exe: '/opt/tamper_blocker/monitor.py',
            pid,
            explanation: 'auditctl -l missing log_tamper rules; auto-restoring ruleset',
            beforeSummary: 'log_tamper rules missing',
            afterSummary: 'rules re-applied via auditctl',
          });
          if (a2) triggered.add('AUDIT_RULES_REMOVED');
        }
        // Auto-reapply as per Section 5
        for (const r of this.auditRules) r.loaded = true;
        this.emit('audit_rules', this.auditRules);
        stdout.push('Audit rules modified — Tamper Blocker detected removal and re-applied log_tamper rules.');
        return { command: rawCmd, stdout, stderr, exitCode: 0, cwd, triggeredRules: Array.from(triggered) };
      }
    }

    // 15. ausearch
    if (/^ausearch\b/.test(normalized)) {
      const real = this.toRealPath('/var/log/audit/audit.log');
      if (fs.existsSync(real)) {
        const lines = fs.readFileSync(real, 'utf8').split('\n').filter(Boolean).slice(-12);
        stdout.push('----', ...lines);
      }
      return { command: rawCmd, stdout, stderr, exitCode: 0, cwd, triggeredRules: [] };
    }

    // 16. history -c or unset HISTFILE
    if (normalized === 'history -c' || normalized === 'unset HISTFILE') {
      const target = '/home/kali/.bash_history';
      if (this.monitoringActive) {
        const a = this.fireTamperAlert({
          path: target,
          kind: 'SHELL_REDIRECT_OR_HISTORY_WIPE',
          severity: 'WARN',
          user,
          comm: 'bash',
          exe: '/usr/bin/bash',
          pid,
          explanation: `Shell history wipe detected (${normalized})`,
          beforeSummary: 'history intact',
          afterSummary: normalized,
        });
        if (a) triggered.add('SHELL_REDIRECT_OR_HISTORY_WIPE');
      }
      if (normalized === 'history -c' && !this.hardenedPaths.has(target)) {
        const real = this.toRealPath(target);
        this.internalWritePaths.add(target);
        fs.writeFileSync(real, '', 'utf8');
        this.internalWritePaths.delete(target);
        this.checkPathIntegrity(target, { user, comm: 'bash', exe: '/usr/bin/bash', pid }).forEach((r) => triggered.add(r));
      }
      return { command: rawCmd, stdout, stderr, exitCode: 0, cwd, triggeredRules: Array.from(triggered) };
    }

    // 17. Read-only inspection commands (ls, cat, tail, head, stat, lsattr, pgrep, whoami, id, pwd, help)
    if (normalized === 'whoami') {
      stdout.push('kali');
      return { command: rawCmd, stdout, stderr, exitCode: 0, cwd, triggeredRules: [] };
    }
    if (normalized === 'id') {
      stdout.push('uid=1000(kali) gid=1000(kali) groups=1000(kali),4(adm),27(sudo)');
      return { command: rawCmd, stdout, stderr, exitCode: 0, cwd, triggeredRules: [] };
    }
    if (normalized === 'pwd') {
      stdout.push(cwd);
      return { command: rawCmd, stdout, stderr, exitCode: 0, cwd, triggeredRules: [] };
    }
    if (normalized === 'help') {
      stdout.push(
        'Available commands:',
        '  tamplogs [--headless|--no-popup|--verify|--harden|--unharden|--status|--stop]',
        '  echo "msg" | sudo tee -a /var/log/test.log      (safe append)',
        '  sudo sed -i "s/old/new/" /var/log/test.log      (tamper edit)',
        '  sudo truncate -s 0 /var/log/test.log            (tamper truncate)',
        '  sudo chmod 777 /var/log/test.log                (tamper permissions)',
        '  sudo rm /var/log/test.log                       (tamper delete)',
        '  sudo logrotate -f /etc/logrotate.conf           (legitimate rotation)',
        '  sudo systemctl stop|start rsyslog               (service tamper)',
        '  sudo journalctl --vacuum-size=500M              (journal vacuum)',
        '  sudo auditctl -l / sudo ausearch -k log_tamper  (audit inspection)',
        '  ls, cat, tail, head, stat, lsattr, clear',
      );
      return { command: rawCmd, stdout, stderr, exitCode: 0, cwd, triggeredRules: [] };
    }
    if (/^pgrep\b/.test(normalized)) {
      const target = normalized.split(/\s+/).pop() ?? '';
      const svc = this.services.find((s) => s.name.includes(target));
      if (svc && svc.active) {
        stdout.push(String(svc.pid));
        return { command: rawCmd, stdout, stderr, exitCode: 0, cwd, triggeredRules: [] };
      }
      return { command: rawCmd, stdout, stderr, exitCode: 1, cwd, triggeredRules: [] };
    }
    if (/^lsattr\b/.test(normalized)) {
      const target = normalized.split(/\s+/).pop() ?? '/var/log/auth.log';
      if (fs.existsSync(this.toRealPath(target))) {
        const flag = this.hardenedPaths.has(target) ? '-----a--------e-------' : '--------------e-------';
        stdout.push(`${flag} ${target}`);
        return { command: rawCmd, stdout, stderr, exitCode: 0, cwd, triggeredRules: [] };
      }
      stderr.push(`lsattr: No such file or directory while trying to stat ${target}`);
      return { command: rawCmd, stdout, stderr, exitCode: 1, cwd, triggeredRules: [] };
    }
    if (/^ls\b/.test(normalized)) {
      const target = normalized.split(/\s+/).filter((a) => !a.startsWith('-'))[1] ?? '/var/log';
      const real = this.toRealPath(target);
      if (!fs.existsSync(real)) {
        stderr.push(`ls: cannot access '${target}': No such file or directory`);
        return { command: rawCmd, stdout, stderr, exitCode: 2, cwd, triggeredRules: [] };
      }
      const stat = fs.statSync(real);
      if (stat.isDirectory()) {
        const entries = fs.readdirSync(real, { withFileTypes: true }).map((e) => (e.isDirectory() ? `${e.name}/` : e.name));
        stdout.push(entries.join('  '));
      } else {
        stdout.push(target);
      }
      return { command: rawCmd, stdout, stderr, exitCode: 0, cwd, triggeredRules: [] };
    }
    const readMatch = normalized.match(/^(cat|head|tail)(?:\s+-n\s+(\d+))?\s+(\S+)$/);
    if (readMatch) {
      const op = readMatch[1];
      const count = Number(readMatch[2] ?? (op === 'cat' ? 200 : 15));
      const target = readMatch[3];
      const real = this.toRealPath(target);
      if (!fs.existsSync(real)) {
        stderr.push(`${op}: ${target}: No such file or directory`);
        return { command: rawCmd, stdout, stderr, exitCode: 1, cwd, triggeredRules: [] };
      }
      const lines = fs.readFileSync(real, 'utf8').split('\n');
      if (lines[lines.length - 1] === '') lines.pop();
      const slice = op === 'tail' ? lines.slice(-count) : lines.slice(0, count);
      stdout.push(...slice);
      return { command: rawCmd, stdout, stderr, exitCode: 0, cwd, triggeredRules: [] };
    }
    if (/^stat\b/.test(normalized)) {
      const target = normalized.split(/\s+/).pop() ?? '';
      const b = this.computeBaseline(target);
      if (!b) {
        stderr.push(`stat: cannot statx '${target}': No such file or directory`);
        return { command: rawCmd, stdout, stderr, exitCode: 1, cwd, triggeredRules: [] };
      }
      stdout.push(
        `  File: ${b.path}`,
        `  Size: ${b.size}\tInode: ${b.ino}\tAccess: (${b.modeOctal})\tOwner: (${b.ownerLabel})`,
        `  SHA256 Prefix (${b.plen}B): ${b.digest || '(inplace_ok)'}`,
      );
      return { command: rawCmd, stdout, stderr, exitCode: 0, cwd, triggeredRules: [] };
    }

    stderr.push(`bash: ${normalized.split(/\s+/)[0]}: command not found (type 'help' or 'tamplogs --help')`);
    return { command: rawCmd, stdout, stderr, exitCode: 127, cwd, triggeredRules: [] };
  }

  public runTestStep(step: number): TestStepResult {
    const start = Date.now();
    if (!this.monitoringActive) {
      this.startMonitoring('interactive');
    }

    const ensureTestLog = () => {
      const real = this.toRealPath('/var/log/test.log');
      if (!fs.existsSync(real)) {
        this.internalWritePaths.add('/var/log/test.log');
        fs.writeFileSync(real, 'baseline test entry\n', 'utf8');
        this.internalWritePaths.delete('/var/log/test.log');
        this.rebaselineFile('/var/log/test.log');
      }
    };

    let name = '';
    let command = '';
    let expected = '';
    let passed = false;
    let observed = '';

    switch (step) {
      case 1: {
        name = 'Append';
        command = 'echo test | sudo tee -a /var/log/test.log';
        expected = 'White [INFO] line in dashboard, no tamper alert.';
        ensureTestLog();
        const beforeAlerts = this.alerts.length;
        const res = this.executeCommand(command);
        const afterAlerts = this.alerts.length;
        passed = res.exitCode === 0 && afterAlerts === beforeAlerts && res.triggeredRules.length === 0;
        observed = passed ? 'Appended cleanly; logged [INFO], 0 alerts fired.' : `Unexpected alerts: ${res.triggeredRules.join(', ')}`;
        break;
      }
      case 2: {
        name = 'Edit';
        command = "echo AAAA | sudo tee -a /var/log/test.log; sudo sed -i 's/test/EDIT/' /var/log/test.log";
        expected = 'SED_INPLACE_ON_LOG and INODE_REPLACED or CONTENT_MODIFIED.';
        ensureTestLog();
        const res = this.executeCommand(command);
        passed = res.triggeredRules.includes('SED_INPLACE_ON_LOG') &&
          (res.triggeredRules.includes('INODE_REPLACED') || res.triggeredRules.includes('CONTENT_MODIFIED'));
        observed = `Triggered: ${res.triggeredRules.join(' + ') || 'none'}`;
        break;
      }
      case 3: {
        name = 'Truncate';
        command = 'sudo truncate -s 0 /var/log/test.log';
        expected = 'TRUNCATED + LOG_FILE_COMMAND.';
        ensureTestLog();
        const res = this.executeCommand(command);
        passed = res.triggeredRules.includes('TRUNCATED') && res.triggeredRules.includes('LOG_FILE_COMMAND');
        observed = `Triggered: ${res.triggeredRules.join(' + ') || 'none'}`;
        break;
      }
      case 4: {
        name = 'Permissions';
        command = 'sudo chmod 777 /var/log/test.log';
        expected = 'PERM_OWNER_CHANGE.';
        ensureTestLog();
        const res = this.executeCommand(command);
        passed = res.triggeredRules.includes('PERM_OWNER_CHANGE');
        observed = `Triggered: ${res.triggeredRules.join(' + ') || 'none'}`;
        break;
      }
      case 5: {
        name = 'Delete';
        command = 'sudo rm /var/log/test.log';
        expected = 'DELETED_OR_MOVED; alert names rm and user.';
        ensureTestLog();
        const res = this.executeCommand(command);
        passed = res.triggeredRules.includes('DELETED_OR_MOVED');
        observed = `Triggered: ${res.triggeredRules.join(' + ') || 'none'}`;
        break;
      }
      case 6: {
        name = 'Rotation';
        command = 'sudo logrotate -f /etc/logrotate.conf';
        expected = 'Only [INFO] lines marked allowed (0 tamper alerts).';
        const beforeAlerts = this.alerts.length;
        const res = this.executeCommand(command);
        const afterAlerts = this.alerts.length;
        passed = res.exitCode === 0 && afterAlerts === beforeAlerts;
        observed = passed ? 'logrotate whitelisted for 60s; 0 tamper alerts.' : `Alerts fired: ${afterAlerts - beforeAlerts}`;
        break;
      }
      case 7: {
        name = 'Service Stop';
        command = 'sudo systemctl stop rsyslog; sudo systemctl start rsyslog';
        expected = 'LOGGING_SERVICE_STOPPED.';
        const res = this.executeCommand(command);
        passed = res.triggeredRules.includes('LOGGING_SERVICE_STOPPED');
        observed = `Triggered: ${res.triggeredRules.join(' + ') || 'none'}`;
        break;
      }
      case 8: {
        name = 'Vacuum';
        command = 'sudo journalctl --vacuum-size=500M';
        expected = 'JOURNAL_VACUUM.';
        const res = this.executeCommand(command);
        passed = res.triggeredRules.includes('JOURNAL_VACUUM');
        observed = `Triggered: ${res.triggeredRules.join(' + ') || 'none'}`;
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
        command = 'sudo auditctl -l; sudo ausearch -k log_tamper -i -c tee --start recent';
        expected = 'never and always rules listed; SYSCALL record with comm=tee.';
        const res = this.executeCommand(command);
        const out = res.stdout.join('\n');
        passed = out.includes('never,exit') && out.includes('log_tamper') && out.includes('comm="tee"');
        observed = passed ? 'never + always rules active & SYSCALL tee record verified.' : 'Missing expected audit rule or record.';
        break;
      }
    }

    return {
      step,
      name,
      command,
      expected,
      passed,
      observed,
      durationMs: Date.now() - start,
    };
  }

  public getStatus(): MonitorStatus {
    return {
      active: this.monitoringActive,
      mode: this.monitorMode,
      hostname: 'kali-sec',
      kernel: '6.11.2-kali1-amd64',
      startedAt: this.startedAt,
      uptimeSeconds: this.startedAtMs ? Math.floor((Date.now() - this.startedAtMs) / 1000) : 0,
      liveNoiseEnabled: this.liveNoiseEnabled,
      watchedFilesCount: this.baselines.size,
      unacknowledgedCount: this.alerts.filter((a) => !a.acknowledged).length,
      totalAlertsCount: this.alerts.length,
      totalEventsCount: this.logs.length,
      auditRulesLoaded: this.auditRules.every((r) => r.loaded),
      logrotateRecent: this.isLogrotateRecent(),
    };
  }

  public getBaselines(): BaselineRecord[] {
    return Array.from(this.baselines.values()).sort((a, b) => a.path.localeCompare(b.path));
  }

  public getSnapshot(): AppSnapshot {
    return {
      status: this.getStatus(),
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
