import express from 'express';
import path from 'node:path';
import { createServer as createViteServer } from 'vite';
import { buildAgentPythonScript, buildKaliTarGz, KALI_BUNDLE_FILES } from './server/kaliBundle.ts';
import { TamperEngine } from './server/tamperEngine.ts';
import { TriggerCorrelator } from './server/triggerCorrelator.ts';

const PORT = Number(process.env.PORT || 3000);
const isProduction = process.env.NODE_ENV === 'production';

async function bootstrap() {
  const app = express();
  app.use(express.json({ limit: '2mb' }));

  const engine = new TamperEngine(process.cwd());

  // Trigger capture: correlate auditd events to tamper alerts
  const correlator = new TriggerCorrelator(engine);
  correlator.start();

  app.get('/api/state', (_req, res) => {
    res.json(engine.getSnapshot());
  });

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

  // Multi-Agent Fleet Endpoints (Wazuh-style)
  app.get('/api/agents', (_req, res) => {
    res.json({ agents: engine.getAgents() });
  });

  app.post('/api/agents/enroll', (req, res) => {
    const name = typeof req.body?.name === 'string' ? req.body.name : '';
    const ip = typeof req.body?.ip === 'string' ? req.body.ip : '';
    const os = typeof req.body?.os === 'string' ? req.body.os : '';
    const agent = engine.enrollAgent(name, ip, os);
    res.json({ agent, snapshot: engine.getSnapshot() });
  });

  app.post('/api/agents/ingest', (req, res) => {
    const result = engine.ingestRemoteAgentBatch(req.body ?? {});
    if (!result.ok) {
      res.status(401).json(result);
      return;
    }
    res.json(result);
  });

  app.post('/api/agents/:id/action', (req, res) => {
    const action = req.body?.action;
    if (!['toggle-status', 'rebaseline'].includes(action)) {
      res.status(400).json({ error: 'Invalid agent action' });
      return;
    }
    const result = engine.runAgentAction(req.params.id, action);
    if (!result.ok) {
      res.status(404).json({ error: 'Agent not found' });
      return;
    }
    res.json({ ...result, snapshot: engine.getSnapshot() });
  });

  app.get('/api/agents/agent.py', (req, res) => {
    const agentId = typeof req.query.agentId === 'string' ? req.query.agentId : 'agent-custom';
    const agent = engine.getAgentById(agentId);
    const token = typeof req.query.token === 'string' ? req.query.token : agent?.token ?? 'REPLACE_TOKEN';
    const hostProto = req.headers['x-forwarded-proto'] || req.protocol || 'http';
    const hostHeader = req.headers['x-forwarded-host'] || req.headers.host || '127.0.0.1:3000';
    const managerUrl = `${hostProto}://${hostHeader}`;
    res.setHeader('Content-Type', 'text/x-python; charset=utf-8');
    res.send(buildAgentPythonScript(managerUrl, agentId, token));
  });

  app.get('/api/agents/install.sh', (req, res) => {
    const agentId = typeof req.query.agentId === 'string' ? req.query.agentId : 'agent-custom';
    const agent = engine.getAgentById(agentId);
    const token = typeof req.query.token === 'string' ? req.query.token : agent?.token ?? 'REPLACE_TOKEN';
    const hostProto = req.headers['x-forwarded-proto'] || req.protocol || 'http';
    const hostHeader = req.headers['x-forwarded-host'] || req.headers.host || '127.0.0.1:3000';
    const managerUrl = `${hostProto}://${hostHeader}`;
    const script = `#!/usr/bin/env bash
set -euo pipefail
sudo mkdir -p /opt/tamperer-agent
curl -sSL "${managerUrl}/api/agents/agent.py?agentId=${encodeURIComponent(agentId)}&token=${encodeURIComponent(token)}" | sudo tee /opt/tamperer-agent/tamperer-agent.py >/dev/null
sudo chmod +x /opt/tamperer-agent/tamperer-agent.py
cat <<'EOF' | sudo tee /etc/systemd/system/tamperer-agent.service >/dev/null
[Unit]
Description=Tamperer Remote Linux Log & FIM Agent
After=network-online.target

[Service]
Type=simple
Environment="TAMPERER_MANAGER=${managerUrl}"
Environment="TAMPERER_AGENT_ID=${agentId}"
Environment="TAMPERER_TOKEN=${token}"
ExecStart=/usr/bin/python3 /opt/tamperer-agent/tamperer-agent.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable --now tamperer-agent.service
echo "Tamperer Agent (${agentId}) installed and streaming to ${managerUrl}."
`;
    res.setHeader('Content-Type', 'text/x-shellscript; charset=utf-8');
    res.send(script);
  });

  // Splunk-Style SPL Search Endpoint
  app.post('/api/spl/query', (req, res) => {
    const query = typeof req.body?.query === 'string' ? req.body.query : '*';
    const timeRange = req.body?.timeRange === '15m' || req.body?.timeRange === '1h' || req.body?.timeRange === '24h' ? req.body.timeRange : 'all';
    res.json(engine.runSplQuery(query, timeRange));
  });

  // Terminal Execution
  app.post('/api/terminal/exec', (req, res) => {
    const command = typeof req.body?.command === 'string' ? req.body.command : '';
    const result = engine.executeCommand(command);
    res.json({ result, snapshot: engine.getSnapshot() });
  });

  // Monitor Controls
  app.post('/api/monitor/start', (req, res) => {
    const mode = req.body?.mode === 'headless' || req.body?.mode === 'no-popup' ? req.body.mode : 'interactive';
    engine.startMonitoring(mode);
    res.json(engine.getSnapshot());
  });

  app.post('/api/monitor/stop', (_req, res) => {
    engine.stopMonitoring();
    res.json(engine.getSnapshot());
  });

  app.post('/api/monitor/noise', (_req, res) => {
    res.json({ status: engine.getStatus() });
  });

  // Alerts
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

  // File Integrity
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

  // Hash Chains
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
    res.json({ corruptedLine: info.line, snapshot: engine.getSnapshot() });
  });

  // Section 12 Safe Test Plan
  app.post('/api/test-plan/run', (req, res) => {
    const step = Number(req.body?.step);
    if (!Number.isInteger(step) || step < 1 || step > 10) {
      res.status(400).json({ error: 'Step must be an integer between 1 and 10' });
      return;
    }
    const result = engine.runTestStep(step);
    res.json({ result, snapshot: engine.getSnapshot() });
  });

  app.post('/api/sandbox/reset', (_req, res) => {
    engine.resetAll();
    res.json(engine.getSnapshot());
  });

  // Kali Bundle
  app.get('/api/bundle/files', (_req, res) => {
    res.json({ files: KALI_BUNDLE_FILES });
  });

  app.get('/api/bundle/download', (_req, res) => {
    const archive = buildKaliTarGz();
    res.setHeader('Content-Type', 'application/gzip');
    res.setHeader('Content-Disposition', 'attachment; filename="tamperer_kali_suite.tar.gz"');
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
    console.log(`Tamperer server running on http://0.0.0.0:${PORT}`);
  });
}

bootstrap().catch((err) => {
  console.error('Failed to start Tamperer server:', err);
  process.exit(1);
});
