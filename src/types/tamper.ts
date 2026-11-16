export type Severity = 'INFO' | 'WARN' | 'CRIT';

export type DetectionRuleKind =
  | 'TRUNCATED'
  | 'CONTENT_MODIFIED'
  | 'DELETED_OR_MOVED'
  | 'INODE_REPLACED'
  | 'PERM_OWNER_CHANGE'
  | 'LOG_FILE_COMMAND'
  | 'SED_INPLACE_ON_LOG'
  | 'SHELL_REDIRECT_OR_HISTORY_WIPE'
  | 'LOG_OVERWRITE'
  | 'JOURNAL_VACUUM'
  | 'AUDIT_RULES_CHANGED'
  | 'LOGGING_SERVICE_STOPPED'
  | 'AUDIT_RULES_REMOVED';

export interface LogEvent {
  id: string;
  ts: string;
  timeShort: string;
  severity: Severity;
  user: string;
  file: string;
  source: 'inotify' | 'journald' | 'proc' | 'auditd' | 'service' | 'tamplogs';
  message: string;
  isTamper?: boolean;
  ruleKind?: DetectionRuleKind;
}

export interface TamperAlert {
  id: string;
  seq: number;
  ts: string;
  timeShort: string;
  kind: DetectionRuleKind;
  severity: 'WARN' | 'CRIT';
  path: string;
  user: string;
  comm: string;
  exe: string;
  pid: number;
  explanation: string;
  beforeSummary: string;
  afterSummary: string;
  acknowledged: boolean;
  acknowledgedAt?: string;
  chainHash: string;
  prevHash: string;
}

export interface BaselineRecord {
  path: string;
  category: 'system' | 'package' | 'web' | 'audit' | 'binary' | 'journal' | 'history' | 'chain';
  exists: boolean;
  isBinary: boolean;
  inplaceOk: boolean;
  hardened: boolean;
  ino: number;
  size: number;
  mtimeMs: number;
  mode: number;
  modeOctal: string;
  uid: number;
  gid: number;
  ownerLabel: string;
  plen: number;
  digest: string;
  chunkCount: number;
  status: 'verified' | 'tampered' | 'missing' | 'rotated';
  lastEventAt?: string;
}

export interface ServiceStatus {
  name: 'auditd' | 'rsyslog' | 'systemd-journald';
  active: boolean;
  pid: number;
  uptime: string;
}

export interface AuditRuleEntry {
  rule: string;
  kind: 'never' | 'always';
  target: string;
  key?: string;
  loaded: boolean;
}

export interface ChainRecord {
  seq: number;
  ts: string;
  prev: string;
  hash: string;
  kind?: string;
  path?: string;
  user?: string;
  file?: string;
  line?: string;
  severity?: string;
}

export interface ChainVerifyResult {
  chain: 'alerts.chain' | 'mirror.chain';
  ok: boolean;
  brokenLine: number | null;
  totalLines: number;
  reason?: string;
  headHash: string;
}

export interface MonitorStatus {
  active: boolean;
  mode: 'interactive' | 'headless' | 'no-popup' | 'stopped';
  hostname: string;
  kernel: string;
  startedAt: string | null;
  uptimeSeconds: number;
  liveNoiseEnabled: boolean;
  watchedFilesCount: number;
  unacknowledgedCount: number;
  totalAlertsCount: number;
  totalEventsCount: number;
  auditRulesLoaded: boolean;
  logrotateRecent: boolean;
}

export interface TerminalExecResult {
  command: string;
  stdout: string[];
  stderr: string[];
  exitCode: number;
  cwd: string;
  triggeredRules: DetectionRuleKind[];
  monitorAction?: 'started' | 'stopped' | 'verified' | 'hardened' | 'unhardened' | 'status';
}

export interface TestStepResult {
  step: number;
  name: string;
  command: string;
  expected: string;
  passed: boolean;
  observed: string;
  durationMs: number;
}

export interface AppSnapshot {
  status: MonitorStatus;
  baselines: BaselineRecord[];
  logs: LogEvent[];
  alerts: TamperAlert[];
  services: ServiceStatus[];
  auditRules: AuditRuleEntry[];
  chainVerify: {
    alerts: ChainVerifyResult;
    mirror: ChainVerifyResult;
  };
  recentAlertChain: ChainRecord[];
  recentMirrorChain: ChainRecord[];
  configYaml: string;
}

export interface KaliBundleFile {
  name: string;
  installPath: string;
  language: 'python' | 'yaml' | 'ini' | 'bash';
  description: string;
  content: string;
}
