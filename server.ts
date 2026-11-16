import express from 'express';
import path from 'node:path';
import { createServer as createViteServer } from 'vite';
import { buildKaliTarGz, KALI_BUNDLE_FILES } from './server/kaliBundle.ts';
import { TamperEngine } from './server/tamperEngine.ts';

const PORT = Number(process.env.PORT || 3000);
const isProduction = process.env.NODE_ENV === 'production';

async function bootstrap() {
  const app = express();
  app.use(express.json({ limit: '1mb' }));

  const engine = new TamperEngine(process.cwd());

  // Snapshot & Health
  app.get('/api/state', (_req, res) => {
    res.json(engine.getSnapshot());
  });

  // Real-time SSE stream
  app.get('/api/stream', (req, res) => {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders();

    res.write(`event: status\ndata: ${JSON.stringify(engine.getStatus())}\n\n`);

    const unsubscribe = engine.subscribe((eventName, payload) => {
      res.write(`event: ${eventName}\ndata: ${JSON.stringify(payload)}\n\n`);
    });

    const heartbeat = setInterval(() => {
      res.write(`: heartbeat\n\n`);
    }, 15000);

    req.on('close', () => {
      clearInterval(heartbeat);
      unsubscribe();
      res.end();
    });
  });

  // Terminal command execution
  app.post('/api/terminal/exec', (req, res) => {
    const command = typeof req.body?.command === 'string' ? req.body.command : '';
    const result = engine.executeCommand(command);
    res.json({
      result,
      snapshot: engine.getSnapshot(),
    });
  });

  // Monitor controls
  app.post('/api/monitor/start', (req, res) => {
    const mode = req.body?.mode === 'headless' || req.body?.mode === 'no-popup' ? req.body.mode : 'interactive';
    engine.startMonitoring(mode);
    res.json(engine.getSnapshot());
  });

  app.post('/api/monitor/stop', (_req, res) => {
    engine.stopMonitoring();
    res.json(engine.getSnapshot());
  });

  app.post('/api/monitor/noise', (req, res) => {
    engine.setLiveNoise(Boolean(req.body?.enabled));
    res.json({ status: engine.getStatus() });
  });

  // Alert acknowledgements
  app.post('/api/alerts/:id/ack', (req, res) => {
    const updated = engine.acknowledgeAlert(req.params.id);
    if (!updated) {
      res.status(404).json({ error: 'Alert not found' });
      return;
    }
    res.json({ alert: updated, snapshot: engine.getSnapshot() });
  });

  app.post('/api/alerts/ack-all', (_req, res) => {
    const count = engine.acknowledgeAll();
    res.json({ acknowledged: count, snapshot: engine.getSnapshot() });
  });

  // File integrity actions
  app.post('/api/files/harden', (req, res) => {
    const paths = Array.isArray(req.body?.paths) ? (req.body.paths as string[]) : undefined;
    const output = engine.hardenFiles(paths);
    res.json({ output, snapshot: engine.getSnapshot() });
  });

  app.post('/api/files/unharden', (req, res) => {
    const paths = Array.isArray(req.body?.paths) ? (req.body.paths as string[]) : undefined;
    const output = engine.unhardenFiles(paths);
    res.json({ output, snapshot: engine.getSnapshot() });
  });

  app.post('/api/files/rebaseline', (req, res) => {
    const targetPath = typeof req.body?.path === 'string' ? req.body.path : '';
    const baseline = engine.rebaselineFile(targetPath);
    if (!baseline) {
      res.status(404).json({ error: 'File not found in sandbox' });
      return;
    }
    res.json({ baseline, snapshot: engine.getSnapshot() });
  });

  app.get('/api/files/content', (req, res) => {
    const targetPath = typeof req.query.path === 'string' ? req.query.path : '';
    if (!targetPath) {
      res.status(400).json({ error: 'Missing path query parameter' });
      return;
    }
    res.json(engine.readFileContent(targetPath));
  });

  // Hash chains verification & demo tamper
  app.post('/api/chains/verify', (_req, res) => {
    res.json({
      alerts: engine.verifySingleChain('alerts.chain'),
      mirror: engine.verifySingleChain('mirror.chain'),
      recentAlertChain: engine.readChainTail('alerts.chain', 40),
      recentMirrorChain: engine.readChainTail('mirror.chain', 40),
    });
  });

  app.post('/api/chains/corrupt-demo', (_req, res) => {
    const info = engine.corruptChainDemo();
    res.json({
      corruptedLine: info.line,
      snapshot: engine.getSnapshot(),
    });
  });

  // Section 12 Safe Test Plan runner
  app.post('/api/test-plan/run', (req, res) => {
    const step = Number(req.body?.step);
    if (!Number.isInteger(step) || step < 1 || step > 10) {
      res.status(400).json({ error: 'Step must be an integer between 1 and 10' });
      return;
    }
    const result = engine.runTestStep(step);
    res.json({
      result,
      snapshot: engine.getSnapshot(),
    });
  });

  // Reset sandbox cleanly
  app.post('/api/sandbox/reset', (_req, res) => {
    const wasActive = engine.getStatus().active;
    engine.initSandbox(true);
    if (wasActive) {
      engine.startMonitoring('interactive');
    }
    res.json(engine.getSnapshot());
  });

  // Kali Linux Python 3.14 project export bundle
  app.get('/api/bundle/files', (_req, res) => {
    res.json({ files: KALI_BUNDLE_FILES });
  });

  app.get('/api/bundle/download', (_req, res) => {
    const archive = buildKaliTarGz();
    res.setHeader('Content-Type', 'application/gzip');
    res.setHeader('Content-Disposition', 'attachment; filename="tamper_blocker_kali.tar.gz"');
    res.send(archive);
  });

  if (!isProduction) {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distDir));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distDir, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Tamper Blocker server running on http://0.0.0.0:${PORT}`);
  });
}

bootstrap().catch((err) => {
  console.error('Failed to start Tamper Blocker server:', err);
  process.exit(1);
});
