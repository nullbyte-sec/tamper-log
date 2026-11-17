from pathlib import Path
import hashlib

path = Path('server/tamperEngine.ts')
original = path.read_bytes()
blob = hashlib.sha1(b'blob ' + str(len(original)).encode() + b'\0' + original).hexdigest()
if blob != '3d259bda16ff8d869810ae7c49d67c2e7a80bef6':
    raise SystemExit('Refusing repair: engine source differs from the reviewed version (or is already patched).')
old = """    const agent = this.agents.find((a) => a.id === payload.agentId);
    if (!agent) {
      return { ok: false, acceptedEvents: 0, error: 'Unknown agentId' };
    }
    if (payload.token && agent.token !== payload.token) {
      return { ok: false, acceptedEvents: 0, error: 'Invalid agent token' };
    }
"""
new = """    const rejected = () => ({ ok: false, acceptedEvents: 0, error: 'Invalid agent credentials' });
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return rejected();
    if (typeof payload.agentId !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(payload.agentId)) return rejected();
    if (typeof payload.token !== 'string' || payload.token.length === 0 || payload.token.length > 512) return rejected();

    const agent = this.agents.find((a) => a.id === payload.agentId);
    if (!agent || agent.isManager || agent.id === 'agent-000') return rejected();
    if (typeof agent.token !== 'string' || agent.token.length === 0 || agent.token.length > 512) return rejected();
    const tokenDigest = (token: string) => crypto.createHash('sha256').update(token, 'utf8').digest();
    if (!crypto.timingSafeEqual(tokenDigest(payload.token), tokenDigest(agent.token))) return rejected();
"""
source = original.decode('utf-8')
if source.count(old) != 1:
    raise SystemExit('Refusing repair: authentication block is not unique.')
updated = source.replace(old, new, 1)
if updated.replace(new, old, 1) != source:
    raise SystemExit('Refusing repair: unrelated source changed.')
path.write_bytes(updated.encode('utf-8'))
