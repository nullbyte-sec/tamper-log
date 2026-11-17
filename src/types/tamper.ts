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

export interface WazuhRuleMeta {
  ruleId: string;
  level: number;
  mitreId: string;
  mitreTactic: string;
  description: string;
}

export interface AgentNode {
  id: string;
  name: string;
  hostname: string;
  ip: string;
  os: string;
  kernel: string;
  version: string;
  status: 'active' | 'disconnected' | 'pending';
  isManager: boolean;
  lastKeepAlive: string;
  enrolledAt: string;
  token: string;
  watchedCount: number;
  openAlerts: number;
  eventsCount: number;
  cpuLoad: string;
  memUsed: string;
}

export interface LogEvent {
  id: string;
  ts: string;
  timeShort: string;
  epochMs: number;
  agentId: string;
  host: string;
  severity: Severity;
  user: string;
  file: string;
  source: 'inotify' | 'journald' | 'proc' | 'auditd' | 'service' | 'tamplogs' | 'agent';
  message: string;
  isTamper?: boolean;
  ruleKind?: DetectionRuleKind;
  wazuhRuleId?: string;
  mitreId?: string;
}

export interface TriggerInfo {
  pid: number;
  ppid: number;
  uid: number;
  exe: string;
  argv: string[];
  cwd: string;
  tty: string;
  timestamp: string;
  source: 'auditd';
  confidence: 'correlated';
  matches: number;
}

export type TriggerUnavailableReason =
  | 'auditd_missing'
  | 'auditd_not_running'
  | 'rules_not_installed'
  | 'no_event_in_window'
  | 'insufficient_privileges';

export interface TamperAlert {
  id: string;
  seq: number;
  ts: string;
  timeShort: string;
  epochMs: number;
  agentId: string;
  host: string;
  kind: DetectionRuleKind;
  wazuhRuleId: string;
  ruleLevel: number;
  mitreId: string;
  mitreTactic: string;
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
  trigger?: TriggerInfo;
  triggerPending?: boolean;
  triggerUnavailable?: TriggerUnavailableReason;
}

export interface BaselineRecord {
  agentId: string;
  host: string;
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
  host?: string;
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
  activeAgentsCount: number;
  totalAgentsCount: number;
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

export interface SplFieldFacet {
  field: string;
  values: Array<{ value: string; count: number }>;
}

export interface SplTimelineBucket {
  label: string;
  startMs: number;
  endMs: number;
  info: number;
  warn: number;
  crit: number;
  total: number;
}

export interface SplQueryResult {
  query: string;
  timeRange: string;
  totalMatched: number;
  executionMs: number;
  events: LogEvent[];
  facets: SplFieldFacet[];
  timeline: SplTimelineBucket[];
  statsRows: Array<Record<string, string | number>> | null;
  statsColumns: string[];
}

export interface AppSnapshot {
  status: MonitorStatus;
  agents: AgentNode[];
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
  capabilities?: {
    terminalEnabled: boolean;
    demoActionsEnabled: boolean;
  };
}

export interface KaliBundleFile {
  name: string;
  installPath: string;
  language: 'python' | 'yaml' | 'ini' | 'bash' | 'desktop';
  description: string;
  content: string;
}
