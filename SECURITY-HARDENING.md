# Management and agent authentication: containment patch

This is the first hardening increment, not a completed production security audit.

## Startup and login

The server now requires TAMPERER_ADMIN_PASSWORD (32-512 characters). Generate a random password, store it securely, and export it in the environment used to start the server. Do not commit it or paste it into chat. If using sudo, configure the service/environment explicitly rather than assuming sudo preserves it.

The default bind address is 127.0.0.1. Open http://127.0.0.1:3000 in the browser and use HTTP Basic username admin and the configured password. The page, API calls and EventSource share the browser's same-origin Basic credentials; verify this in live browser testing. Basic authentication does not encrypt transport. Use a private network or authenticated TLS reverse proxy; never the previous public plaintext tunnel.

For an explicitly configured deployment use TAMPERER_BIND_HOST and TAMPERER_PUBLIC_ORIGIN. The latter must be the exact browser/agent-facing origin, including a non-default port. Host and browser Origin must match it. Forwarded headers are not trusted. An agent using a different Host is rejected; configure its manager URL accordingly. Direct ingestion needs its registered remote ID and nonempty matching token in JSON; admin credentials are not agent credentials. Loopback binding alone does not protect a publicly forwarded tunnel.

All management endpoints, static workbench routes, and generated bundles require administrator login. Terminal execution is disabled unless TAMPERER_ENABLE_TERMINAL=1. Destructive demo/reset routes are disabled unless TAMPERER_ENABLE_DEMO_ACTIONS=1. Leave these off on real monitored hosts.

## Intentional compatibility changes

The unsafe /api/agents/install.sh and /api/agents/agent.py downloads return 410 after administrator authentication until a hardened provisioning flow is implemented. Existing agents can still ingest with valid credentials. Old curl installers and the launcher may need changes for authentication; do not bypass the gate to make them work.

The missing-token bypass is blocked at the HTTP ingestion boundary; the engine's internal validation still needs defense-in-depth repair. This patch does not persist enrollment: restarting the manager can still lose remote registrations. It does not rotate previously exposed tokens, repair audit correlation, cap all monitoring work, add rate limiting, or separate privileged collection from the web process. Do not describe these outstanding issues as fixed.

## Verification

Run: npx tsx --test server/apiSecurity.test.ts
Then run: npm run lint and npm run build.
Tests cover the gate and credential helper, not the full engine or browser. Execute live HTTP, browser/EventSource and agent ingestion tests before merging. Tests have been authored but not executed by the assistant.
