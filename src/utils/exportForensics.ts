import type { LogEvent, TamperAlert } from '../types/tamper';

function csvEscape(val: unknown): string {
  const str = val === null || val === undefined ? '' : String(val);
  if (/[",\r\n]/.test(str)) {
    return `"${str.replace(/"/g, '""')}"`;
  }
  return str;
}

function triggerDownload(filename: string, content: string, mimeType: string): void {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

function fileTimestamp(): string {
  return new Date().toISOString().slice(0, 19).replace(/:/g, '-');
}

export function exportAlertsToCsv(alerts: TamperAlert[], scopeLabel = 'all'): void {
  const headers = [
    'seq',
    'id',
    'timestamp',
    'host',
    'agent_id',
    'severity',
    'rule_kind',
    'wazuh_rule_id',
    'rule_level',
    'mitre_id',
    'mitre_tactic',
    'path',
    'user',
    'comm',
    'exe',
    'pid',
    'explanation',
    'before_summary',
    'after_summary',
    'acknowledged',
    'acknowledged_at',
    'prev_hash',
    'chain_hash',
  ];

  const rows = alerts.map((a) =>
    [
      a.seq,
      a.id,
      a.ts,
      a.host,
      a.agentId,
      a.severity,
      a.kind,
      a.wazuhRuleId,
      a.ruleLevel,
      a.mitreId,
      a.mitreTactic,
      a.path,
      a.user,
      a.comm,
      a.exe,
      a.pid,
      a.explanation,
      a.beforeSummary,
      a.afterSummary,
      a.acknowledged,
      a.acknowledgedAt ?? '',
      a.prevHash,
      a.chainHash,
    ]
      .map(csvEscape)
      .join(','),
  );

  const csv = [headers.join(','), ...rows].join('\n');
  triggerDownload(`tamperer-alerts-${scopeLabel}-${fileTimestamp()}.csv`, csv, 'text/csv;charset=utf-8');
}

export function exportAlertsToJson(alerts: TamperAlert[], scopeLabel = 'all'): void {
  const payload = {
    exportedAt: new Date().toISOString(),
    exportType: 'forensic_alerts',
    scope: scopeLabel,
    count: alerts.length,
    alerts,
  };
  triggerDownload(
    `tamperer-alerts-${scopeLabel}-${fileTimestamp()}.json`,
    JSON.stringify(payload, null, 2),
    'application/json;charset=utf-8',
  );
}

export function exportLogsToCsv(logs: LogEvent[], scopeLabel = 'all'): void {
  const headers = [
    'id',
    'timestamp',
    'epoch_ms',
    'host',
    'agent_id',
    'severity',
    'source',
    'user',
    'file',
    'is_tamper',
    'rule_kind',
    'wazuh_rule_id',
    'mitre_id',
    'message',
  ];

  const rows = logs.map((l) =>
    [
      l.id,
      l.ts,
      l.epochMs,
      l.host,
      l.agentId,
      l.severity,
      l.source,
      l.user,
      l.file,
      Boolean(l.isTamper),
      l.ruleKind ?? '',
      l.wazuhRuleId ?? '',
      l.mitreId ?? '',
      l.message,
    ]
      .map(csvEscape)
      .join(','),
  );

  const csv = [headers.join(','), ...rows].join('\n');
  triggerDownload(`tamperer-logs-${scopeLabel}-${fileTimestamp()}.csv`, csv, 'text/csv;charset=utf-8');
}

export function exportLogsToJson(logs: LogEvent[], scopeLabel = 'all'): void {
  const payload = {
    exportedAt: new Date().toISOString(),
    exportType: 'forensic_logs',
    scope: scopeLabel,
    count: logs.length,
    logs,
  };
  triggerDownload(
    `tamperer-logs-${scopeLabel}-${fileTimestamp()}.json`,
    JSON.stringify(payload, null, 2),
    'application/json;charset=utf-8',
  );
}
