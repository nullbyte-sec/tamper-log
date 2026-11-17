import 'dotenv/config';
import express from 'express';
import path from 'node:path';
import { createServer as createViteServer } from 'vite';
import { buildKaliTarGz, KALI_BUNDLE_FILES } from './server/kaliBundle.ts';
import { TamperEngine, WAZUH_RULE_MAP } from './server/tamperEngine.ts';
import { TriggerCorrelator } from './server/triggerCorrelator.ts';
import { createManagementGate, validAgentCredentials } from './server/apiSecurity.ts';

const PORT = Number(process.env.PORT || 3000);
const isProduction = process.env.NODE_ENV === 'production';

function parseValidHttpUrl(raw?: string): URL | null {
  if (!raw || raw === 'MY_APP_URL') return null;
  try {
    const parsed = new URL(raw);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:' ? parsed : null;
  } catch {
    return null;
  }
}

const validAppUrl = parseValidHttpUrl(process.env.APP_URL);
const isAiStudioPreview = !isProduction && validAppUrl !== null;
const HOST = process.env.TAMPERER_BIND_HOST || (validAppUrl ? '0.0.0.0' : '127.0.0.1');

async function bootstrap() {
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', false);
  const origin = process.env.TAMPERER_PUBLIC_ORIGIN || validAppUrl?.origin || `http://127.0.0.1:${PORT}`;
  const adminPassword = process.env.TAMPERER_ADMIN_PASSWORD || '';
  if (isProduction || adminPassword) {
    app.use(createManagementGate(adminPassword, origin));
  } else {
    console.warn(
      `[tamperer] WARNING: TAMPERER_ADMIN_PASSWORD is not set; starting dev server without HTTP Basic Auth (bind=${HOST}:${PORT}). Set TAMPERER_ADMIN_PASSWORD (32-512 chars) for authenticated mode.`,
    );
    app.use((_req, res, next) => {
      res.setHeader('Cache-Control', 'no-store');
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('Referrer-Policy', 'no-referrer');
      if (!isAiStudioPreview) {
        res.setHeader('X-Frame-Options', 'DENY');
      }
      next();
    });
  }
  app.use(express.json({ limit: '2mb', strict: true }));
  const engine = new TamperEngine(process.cwd());
  const correlator = new TriggerCorrelator(engine);
  correlator.start();

  const buildSnapshot = () => ({
    ...engine.getSnapshot(),
    capabilities: {
      terminalEnabled: process.env.TAMPERER_ENABLE_TERMINAL === '1',
      demoActionsEnabled: process.env.TAMPERER_ENABLE_DEMO_ACTIONS === '1',
    },
  });

  app.get('/api/state', (_req, res) => res.json(buildSnapshot()));
  app.get('/api/stream', (req, res) => {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders();
    res.write(`event: status\ndata: ${JSON.stringify(engine.getStatus())}\n\n`);
    const unsubscribe = engine.subscribe((eventName, payload) => {
      res.write(`event: ${eventName}\ndata: ${JSON.stringify(payload)}\n\n`);
    });
    const heartbeat = setInterval(() => res.write(': heartbeat\n\n'), 15000);
    req.on('close', () => { clearInterval(heartbeat); unsubscribe(); res.end(); });
  });
  app.get('/api/agents', (_req, res) => res.json({ agents: engine.getAgents() }));
  app.post('/api/agents/enroll', (req, res) => {
    const name = typeof req.body?.name === 'string' ? req.body.name : '';
    const ip = typeof req.body?.ip === 'string' ? req.body.ip : '';
    const os = typeof req.body?.os === 'string' ? req.body.os : '';
    try {
      const agent = engine.enrollAgent(name, ip, os);
      res.json({ agent, snapshot: buildSnapshot() });
    } catch (err) {
      res.status(429).json({ error: (err as Error).message });
    }
  });
  app.post('/api/agents/ingest', (req, res) => {
    if (!validAgentCredentials(req.body, (id) => engine.getAgentById(id))) {
      res.status(401).json({ ok: false, acceptedEvents: 0, error: 'Invalid agent credentials' });
      return;
    }
    const body = req.body;
    const bounded = (v: unknown, max: number) => typeof v === 'string' && v.length <= max;
    const eventsValid = body.events === undefined || (Array.isArray(body.events) && body.events.length <= 1000 && body.events.every((e: any) =>
      e && typeof e === 'object' && !Array.isArray(e) && typeof e.kind === 'string' && Object.hasOwn(WAZUH_RULE_MAP, e.kind) &&
      (e.severity === undefined || ['INFO', 'WARN', 'CRIT'].includes(e.severity)) &&
      ['path', 'user', 'comm', 'message'].every((k) => e[k] === undefined || bounded(e[k], k === 'message' ? 8192 : 2048))));
    const baselinesValid = body.baselines === undefined || (Array.isArray(body.baselines) && body.baselines.length <= 5000 && body.baselines.every((b: any) =>
      b && typeof b === 'object' && !Array.isArray(b) && bounded(b.path, 2048) && b.path.startsWith('/') &&
      ['ino', 'size', 'mode', 'uid', 'gid', 'plen'].every((k) => b[k] === undefined || (Number.isSafeInteger(b[k]) && b[k] >= 0)) &&
      (b.digest === undefined || (typeof b.digest === 'string' && /^(?:[a-fA-F0-9]{64})?$/.test(b.digest)))));
    if (!eventsValid || !baselinesValid || !['hostname', 'os', 'kernel'].every((k) => body[k] === undefined || bounded(body[k], 512))) {
      res.status(400).json({ ok: false, acceptedEvents: 0, error: 'Invalid agent payload' });
      return;
    }
    const result = engine.ingestRemoteAgentBatch(body);
    res.status(result.ok ? 200 : 401).json(result.ok ? result : { ok: false, acceptedEvents: 0, error: 'Invalid agent credentials' });
  });
  app.post('/api/agents/:id/action', (req, res) => {
    const action = req.body?.action;
    if (!['toggle-status', 'rebaseline'].includes(action)) { res.status(400).json({ error: 'Invalid agent action' }); return; }
    const result = engine.runAgentAction(req.params.id, action);
    if (!result.ok) { res.status(404).json({ error: 'Agent not found' }); return; }
    res.json({ ...result, snapshot: buildSnapshot() });
  });
  // Disabled until installer inputs, transport and credential storage are hardened.
  app.get(['/api/agents/agent.py', '/api/agents/install.sh'], (_req, res) => {
    res.status(410).json({ error: 'Agent downloads temporarily disabled during security hardening. Use tamperer-agent.py from the verified Kali bundle with TAMPERER_AGENT_ID and TAMPERER_TOKEN env vars.' });
  });
  app.post('/api/spl/query', (req, res) => {
    const query = typeof req.body?.query === 'string' ? req.body.query : '*';
    const timeRange = ['15m', '1h', '24h'].includes(req.body?.timeRange) ? req.body.timeRange : 'all';
    res.json(engine.runSplQuery(query, timeRange));
  });
  app.post('/api/terminal/exec', (req, res) => {
    if (process.env.TAMPERER_ENABLE_TERMINAL !== '1') {
      res.status(403).json({ error: 'Terminal execution is disabled. Set TAMPERER_ENABLE_TERMINAL=1 in server env to enable host shell commands.' });
      return;
    }
    const command = typeof req.body?.command === 'string' ? req.body.command : '';
    res.json({ result: engine.executeCommand(command), snapshot: buildSnapshot() });
  });
  app.post('/api/monitor/start', (req, res) => {
    const mode = req.body?.mode === 'headless' || req.body?.mode === 'no-popup' ? req.body.mode : 'interactive';
    engine.startMonitoring(mode); res.json(buildSnapshot());
  });
  app.post('/api/monitor/stop', (_req, res) => { engine.stopMonitoring(); res.json(buildSnapshot()); });
  app.post('/api/monitor/noise', (_req, res) => res.json({ status: engine.getStatus() }));
  app.post('/api/alerts/:id/ack', (req, res) => {
    const alert = engine.acknowledgeAlert(req.params.id);
    if (!alert) { res.status(404).json({ error: 'Alert not found' }); return; }
    res.json({ alert, snapshot: buildSnapshot() });
  });
  app.post('/api/alerts/ack-all', (_req, res) => res.json({ acknowledged: engine.acknowledgeAll(), snapshot: buildSnapshot() }));
  app.post('/api/files/harden', (req, res) => {
    const paths = Array.isArray(req.body?.paths) ? req.body.paths.filter((p: unknown): p is string => typeof p === 'string') : undefined;
    res.json({ output: engine.hardenFiles(paths), snapshot: buildSnapshot() });
  });
  app.post('/api/files/unharden', (req, res) => {
    const paths = Array.isArray(req.body?.paths) ? req.body.paths.filter((p: unknown): p is string => typeof p === 'string') : undefined;
    res.json({ output: engine.unhardenFiles(paths), snapshot: buildSnapshot() });
  });
  app.post('/api/files/rebaseline', (req, res) => {
    const target = typeof req.body?.path === 'string' ? req.body.path : '';
    const check = engine.isManagedPath(target);
    if (!check.ok) { res.status(403).json({ error: check.reason || 'Path not permitted' }); return; }
    const baseline = engine.rebaselineFile(target);
    if (!baseline) { res.status(404).json({ error: 'File not found' }); return; }
    res.json({ baseline, snapshot: buildSnapshot() });
  });
  app.get('/api/files/content', (req, res) => {
    const target = typeof req.query.path === 'string' ? req.query.path : '';
    if (!target) { res.status(400).json({ error: 'Missing path query parameter' }); return; }
    const result = engine.readFileContent(target);
    if (result.denied) { res.status(403).json({ error: result.error || 'Path not permitted' }); return; }
    res.json(result);
  });
  app.post('/api/chains/verify', (_req, res) => res.json({
    alerts: engine.verifySingleChain('alerts.chain'), mirror: engine.verifySingleChain('mirror.chain'),
    recentAlertChain: engine.readChainTail('alerts.chain', 40), recentMirrorChain: engine.readChainTail('mirror.chain', 40),
  }));
  app.use(['/api/chains/corrupt-demo', '/api/test-plan/run', '/api/sandbox/reset'], (_req, res, next) => {
    if (process.env.TAMPERER_ENABLE_DEMO_ACTIONS !== '1') {
      res.status(403).json({ error: 'Destructive demo actions are disabled. Set TAMPERER_ENABLE_DEMO_ACTIONS=1 in server env to run test drills or resets.' });
      return;
    }
    next();
  });
  app.post('/api/chains/corrupt-demo', (_req, res) => res.json({ corruptedLine: engine.corruptChainDemo().line, snapshot: buildSnapshot() }));
  app.post('/api/test-plan/run', (req, res) => {
    const step = Number(req.body?.step);
    if (!Number.isInteger(step) || step < 1 || step > 10) { res.status(400).json({ error: 'Step must be an integer between 1 and 10' }); return; }
    res.json({ result: engine.runTestStep(step), snapshot: buildSnapshot() });
  });
  app.post('/api/sandbox/reset', (_req, res) => { engine.resetAll(); res.json(buildSnapshot()); });
  app.get('/api/bundle/files', (_req, res) => res.json({ files: KALI_BUNDLE_FILES }));
  app.get('/api/bundle/download', (_req, res) => {
    res.setHeader('Content-Type', 'application/gzip');
    res.setHeader('Content-Disposition', 'attachment; filename="tamperer_kali_suite.tar.gz"');
    res.send(buildKaliTarGz());
  });
  if (!isProduction) {
    const vite = await createViteServer({ server: { middlewareMode: true }, appType: 'spa' });
    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distDir));
    app.get('*', (_req, res) => res.sendFile(path.join(distDir, 'index.html')));
  }
  const server = app.listen(PORT, HOST, () => console.log(`Tamperer server running on ${origin} (bind ${HOST}:${PORT})`));
  server.on('error', (err) => { console.error('HTTP listener failed:', err); process.exit(1); });
}
bootstrap().catch((err) => { console.error('Failed to start Tamperer server:', err); process.exit(1); });
