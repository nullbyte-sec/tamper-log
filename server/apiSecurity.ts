import crypto from 'node:crypto';
import type { RequestHandler } from 'express';

type AgentIdentity = { id: string; token?: string; isManager?: boolean };
type LookupAgent = (id: string) => AgentIdentity | undefined;

function equalSecret(a: string, b: string): boolean {
  const digest = (s: string) => crypto.createHash('sha256').update(s).digest();
  return crypto.timingSafeEqual(digest(a), digest(b));
}

export function validAgentCredentials(body: unknown, lookup: LookupAgent): boolean {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return false;
  const { agentId, token } = body as Record<string, unknown>;
  if (typeof agentId !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(agentId)) return false;
  if (typeof token !== 'string' || token.length === 0 || token.length > 512) return false;
  const agent = lookup(agentId);
  const matches = equalSecret(token, agent?.token || 'invalid-agent-credential');
  return Boolean(agent && !agent.isManager && agent.id !== 'agent-000' && agent.token && matches);
}

export function createManagementGate(password: string, publicOrigin: string): RequestHandler {
  if (password.length < 32 || password.length > 512) {
    throw new Error('Set TAMPERER_ADMIN_PASSWORD to a random secret of 32-512 characters before starting.');
  }
  const url = new URL(publicOrigin);
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash || url.pathname !== '/') {
    throw new Error('TAMPERER_PUBLIC_ORIGIN must be an http(s) origin without credentials, path, query or fragment.');
  }
  return (req, res, next) => {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('X-Frame-Options', 'DENY');
    if (req.headers.host?.toLowerCase() !== url.host.toLowerCase()) {
      res.status(403).json({ error: 'Unrecognized Host' });
      return;
    }
    if ((req.headers.origin && req.headers.origin !== url.origin) || req.headers['sec-fetch-site'] === 'cross-site') {
      res.status(403).json({ error: 'Cross-origin requests are not allowed' });
      return;
    }
    if (req.method === 'POST' && req.path === '/api/agents/ingest') {
      next();
      return;
    }
    const header = req.headers.authorization || '';
    let credentials = '';
    if (header.length <= 2048 && /^Basic [A-Za-z0-9+/]+={0,2}$/i.test(header)) {
      credentials = Buffer.from(header.slice(6), 'base64').toString('utf8');
    }
    if (!equalSecret(credentials, `admin:${password}`)) {
      res.setHeader('WWW-Authenticate', 'Basic realm="Tamperer", charset="UTF-8"');
      res.status(401).json({ error: 'Management authentication required' });
      return;
    }
    next();
  };
}
