import assert from 'node:assert/strict';
import test from 'node:test';
import { TamperEngine } from './tamperEngine.ts';

function fixture(token: unknown = 'valid-token', id = 'agent-001', isManager = false) {
  // Avoid the constructor: tests must not scan logs, install rules or touch chain files.
  const engine: any = Object.create(TamperEngine.prototype);
  const agent: any = { id, token, isManager, status: 'disconnected', hostname: 'original', lastKeepAlive: 'unchanged' };
  const calls: string[] = [];
  engine.agents = [agent];
  engine.syncAgentCounters = () => calls.push('counters');
  engine.emit = () => calls.push('emit');
  engine.getBaselines = () => [];
  engine.getStatus = () => ({});
  return { engine, agent, calls };
}
const invalid: unknown[] = [
  null, undefined, [], {},
  { agentId: 'agent-001' },
  ...['', null, 42, false, {}, [], 'wrong', 'x'.repeat(513)].map(token => ({ agentId: 'agent-001', token })),
  { agentId: 'unknown', token: 'valid-token' },
  { agentId: 1, token: 'valid-token' },
  { agentId: '../agent-001', token: 'valid-token' },
];
for (const [index, payload] of invalid.entries()) {
  test(`reject invalid credentials ${index} before state mutation`, () => {
    const { engine, agent, calls } = fixture();
    const before = structuredClone(agent);
    const input = payload && typeof payload === 'object' && !Array.isArray(payload)
      ? { ...payload, hostname: 'must-not-change', events: [{}], baselines: [{}] } : payload;
    assert.deepEqual(engine.ingestRemoteAgentBatch(input), { ok: false, acceptedEvents: 0, error: 'Invalid agent credentials' });
    assert.deepEqual(agent, before);
    assert.deepEqual(calls, []);
  });
}
for (const [index, stored] of [undefined, null, '', 42, {}, 'x'.repeat(513)].entries()) {
  test(`reject invalid stored token ${index}`, () => {
    const { engine, agent, calls } = fixture(null);
    agent.token = stored;
    const before = structuredClone(agent);
    assert.equal(engine.ingestRemoteAgentBatch({ agentId: 'agent-001', token: 'valid-token' }).ok, false);
    assert.deepEqual(agent, before);
    assert.deepEqual(calls, []);
  });
}
for (const [id, isManager] of [['agent-000', false], ['agent-001', true]] as const) {
  test(`reject manager impersonation ${id}`, () => {
    const { engine, agent, calls } = fixture('valid-token', id, isManager);
    const before = structuredClone(agent);
    assert.equal(engine.ingestRemoteAgentBatch({ agentId: id, token: 'valid-token' }).ok, false);
    assert.deepEqual(agent, before);
    assert.deepEqual(calls, []);
  });
}
test('valid remote credentials accept an empty heartbeat batch', () => {
  const { engine, agent, calls } = fixture();
  assert.deepEqual(engine.ingestRemoteAgentBatch({ agentId: 'agent-001', token: 'valid-token', events: [], baselines: [] }), { ok: true, acceptedEvents: 0 });
  assert.equal(agent.status, 'active');
  assert.notEqual(agent.lastKeepAlive, 'unchanged');
  assert.ok(calls.length > 0);
});
