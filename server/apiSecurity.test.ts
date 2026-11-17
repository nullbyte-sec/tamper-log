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
