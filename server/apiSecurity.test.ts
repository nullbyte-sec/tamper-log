import assert from 'node:assert/strict';
import test from 'node:test';
import { createManagementGate, validAgentCredentials } from './apiSecurity.ts';
const lookup = (id: string) => id === 'agent-001' ? { id, token: 'secret' } : id === 'agent-000' ? { id, token: 'local-host', isManager: true } : undefined;
test('remote ingestion requires an exact nonempty token and registered remote identity', () => {
  for (const body of [null, [], {}, { agentId: 'agent-001' }, { agentId: 'agent-001', token: '' }, { agentId: 'agent-001', token: 'wrong' }, { agentId: 'missing', token: 'secret' }, { agentId: 'agent-000', token: 'local-host' }]) {
    assert.equal(validAgentCredentials(body, lookup), false);
  }
  assert.equal(validAgentCredentials({ agentId: 'agent-001', token: 'secret' }, lookup), true);
});
const password = 'a'.repeat(48);
function check(method: string, path: string, headers: Record<string, string>) {
  let status = 200; let passed = false;
  const res: any = { setHeader() {}, status(n: number) { status = n; return this; }, json() {} };
  createManagementGate(password, 'http://127.0.0.1:3000')({ method, path, headers } as any, res, () => { passed = true; });
  return { status, passed };
}
const host = '127.0.0.1:3000';
const authorization = `Basic ${Buffer.from(`admin:${password}`).toString('base64')}`;
test('management, assets and stream require authentication', () => {
  for (const path of ['/', '/api/state', '/api/stream', '/api/terminal/exec', '/api/agents/install.sh']) {
    assert.equal(check('GET', path, { host }).status, 401);
    assert.equal(check('GET', path, { host, authorization }).passed, true);
  }
});
test('Host and cross-origin validation apply even with valid credentials', () => {
  assert.equal(check('POST', '/api/monitor/start', { host, authorization, origin: 'https://evil.invalid' }).status, 403);
  assert.equal(check('GET', '/api/state', { host: 'evil.invalid', authorization }).status, 403);
  assert.equal(check('GET', '/', { host, authorization, 'sec-fetch-site': 'cross-site' }).status, 403);
});
test('only the exact POST ingestion path bypasses management login; route still requires agent authentication', () => {
  assert.equal(check('POST', '/api/agents/ingest', { host }).passed, true);
  assert.equal(check('POST', '/api/agents/ingest/', { host }).status, 401);
  assert.equal(check('GET', '/api/agents/ingest', { host }).status, 401);
});
test('startup rejects missing management secret', () => {
  assert.throws(() => createManagementGate('', 'http://127.0.0.1:3000'));
});
test('management gate rate-limits repeated failed Basic Auth attempts from the same IP', () => {
  const gate = createManagementGate(password, 'http://127.0.0.1:3000');
  for (let i = 0; i < 30; i += 1) {
    let status = 200;
    const res: any = { setHeader() {}, status(n: number) { status = n; return this; }, json() {} };
    gate({ method: 'GET', path: '/api/state', ip: '10.0.0.5', headers: { host } } as any, res, () => {});
    assert.equal(status, 401);
  }
  let limitedStatus = 200;
  const res429: any = { setHeader() {}, status(n: number) { limitedStatus = n; return this; }, json() {} };
  gate({ method: 'GET', path: '/api/state', ip: '10.0.0.5', headers: { host } } as any, res429, () => {});
  assert.equal(limitedStatus, 429);
});

import os from 'node:os';
import fs from 'node:fs';
import path from 'node:path';
import { TamperEngine } from './tamperEngine.ts';
import { TriggerCorrelator, parseAuditTimestamp } from './triggerCorrelator.ts';

test('TamperEngine enforces path containment and engine-level token verification', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tamper-test-'));
  try {
    const engine = new TamperEngine(tmpDir);
    assert.equal(engine.isManagedPath('/etc/shadow').ok, false);
    assert.equal(engine.isManagedPath('/var/log/../etc/passwd').ok, false);
    assert.equal(engine.readFileContent('/etc/passwd').denied, true);

    const agent = engine.enrollAgent('kali-remote', '10.10.10.20', 'Kali');
    // Omitted or empty token must be rejected inside engine as well
    assert.equal(engine.ingestRemoteAgentBatch({ agentId: agent.id }).ok, false);
    assert.equal(engine.ingestRemoteAgentBatch({ agentId: agent.id, token: '' }).ok, false);
    assert.equal(engine.ingestRemoteAgentBatch({ agentId: agent.id, token: 'wrong' }).ok, false);
    assert.equal(engine.ingestRemoteAgentBatch({ agentId: 'agent-000', token: 'local-host' }).ok, false);
    assert.equal(engine.ingestRemoteAgentBatch({ agentId: agent.id, token: agent.token, events: [] }).ok, true);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('TriggerCorrelator parses audit milliseconds accurately and correlates SYSCALL+PATH write events without EXECVE', () => {
  assert.equal(parseAuditTimestamp('audit(1700000000.123:42)'), 1700000000123);
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tamper-corr-'));
  try {
    const engine = new TamperEngine(tmpDir);
    const correlator = new TriggerCorrelator(engine);
    const epochSec = Math.floor(Date.now() / 1000);
    correlator.ingestLine(`type=SYSCALL msg=audit(${epochSec}.250:99): arch=c000003e syscall=257 success=yes pid=4321 ppid=1000 uid=1000 comm="tee" exe="/usr/bin/tee" tty=pts0`);
    correlator.ingestLine(`type=CWD msg=audit(${epochSec}.250:99): cwd="/home/kali"`);
    correlator.ingestLine(`type=PATH msg=audit(${epochSec}.250:99): item=0 name="/var/log/test.log"`);
    correlator.ingestLine(`type=EOE msg=audit(${epochSec}.250:99):`);
    correlator.flushPending();
    const trigger = correlator.correlateTrigger('/var/log/test.log', epochSec * 1000 + 800);
    assert.ok(trigger);
    assert.equal(trigger.pid, 4321);
    assert.equal(trigger.exe, '/usr/bin/tee');
    assert.equal(trigger.uid, 1000);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
