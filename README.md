# Tamper Blocker (`tamperer` / `tamplogs`)

A real-time Linux log-tamper monitor, cryptographic file integrity (FIM) engine, multi-host Wazuh-style agent collector, and Splunk-inspired SPL log workbench — paired with a downloadable Kali Linux suite (`tamperer`, `tamplogs`, and `tamperer-agent.py`).

> Defensive use only, on machines you own or are authorized to monitor.

## Architecture

| Component | Description | Location |
|---|---|---|
| **Web Workbench UI** | React 19 + Vite + Tailwind CSS Burp Suite-style tabbed interface (Dashboard, Live Alerts, Search & SPL, Agents, Log Stream, File Integrity, Terminal, Audit & Chains, Test Plan, Kali App source & download) with CSV/JSON forensic export. | `src/` |
| **Real-Time Detection Engine** | Express + TypeScript backend watching the host machine's actual `/var/log`, shell history files, and SHA-256 hash chains (`alerts.chain`, `mirror.chain`) using `fs.watch`, `lstat`, and SHA-256 prefix hashing, with SSE live streaming. | `server.ts`, `server/tamperEngine.ts` |
| **Kali Linux Bundle** | Downloadable tarball (`tamperer_kali_suite.tar.gz`) containing `tamperer_gui.py` (`tamperer` desktop launcher), `tamperer.desktop`, `tamperer-agent.py`, `tamper_blocker.py` (`tamplogs`), `monitor.py`, `alerts.py`, `dashboard.py`, `config.yaml`, `tamper-blocker.service`, `install.sh`, and `test_section12.sh`. | `server/kaliBundle.ts` |

## Key Features

- **Real Machine Logs Only**: Automatically discovers, baselines, and monitors actual logs present under `/var/log` (e.g., `dpkg.log`, `apt/*.log`, `nginx/*.log`, `alternatives.log`, `wtmp`, `btmp`, `lastlog`) and shell history files (`~/.*_history`). No synthetic or simulated background logs.
- **13 Tamper Detection Rules + Wazuh/MITRE ATT&CK Mapping**:
  - `CONTENT_MODIFIED` (Wazuh `550`, `T1070.002`) — SHA-256 prefix mismatch on existing bytes
  - `TRUNCATED` (Wazuh `592`, `T1070.002`) — unexpected file size shrink
  - `DELETED_OR_MOVED` (Wazuh `553`, `T1070.002`) — monitored log removed or moved
  - `INODE_REPLACED` (Wazuh `554`, `T1070.002`) — inode changed outside a `logrotate` window
  - `PERM_OWNER_CHANGE` (Wazuh `551`, `T1222.002`) — POSIX mode or UID/GID ownership altered
  - `LOG_FILE_COMMAND`, `SED_INPLACE_ON_LOG`, `SHELL_REDIRECT_OR_HISTORY_WIPE`, `LOG_OVERWRITE`, `JOURNAL_VACUUM`, `AUDIT_RULES_CHANGED`, `LOGGING_SERVICE_STOPPED`, `AUDIT_RULES_REMOVED`
- **Multi-Host Agent Fleet (Wazuh Model)**: Enroll external Kali, Ubuntu, Debian, or RHEL hosts from the **Agents** tab and deploy `tamperer-agent.service` via a single `curl ... | sudo bash` installer to stream remote `/var/log` events and FIM baselines to `/api/agents/ingest`.
- **Splunk-Style Search & SPL**: Filter indexed machine logs with field predicates (`severity=CRIT`, `host=...`, `file=...`, `rule=...`) and pipe aggregations (`| stats count by rule`, `| top file`, `| head 50`).
- **Forensic Export (CSV & JSON)**: Export the currently scoped/filtered **alerts** or **logs** directly from both **Dashboard** and **Live Alerts** to RFC-4180 `.csv` or structured `.json` files for offline forensic analysis.
- **Tamper-Evident SHA-256 Hash Chains**: Every alert and mirrored log line is appended to `/var/lib/tamper_blocker/alerts.chain` and `mirror.chain` using `SHA-256(prev + canonicalJSON)` and verified via `tamplogs --verify` or **Audit & Chains**.
- **Append-Only Hardening**: `--harden` / `--unharden` applies/removes `chattr +a` on critical logs.

## Part 1: Run the Web Workbench

Requirements: **Node.js 20+** and **npm**. No external API keys are required (`server.ts` runs locally on port `3000`).

```bash
npm install
npm run dev               # starts http://localhost:3000 (tsx server.ts)
```

Other scripts:

- `npm run lint` — TypeScript check (`tsc --noEmit`)
- `npm run build` — Build frontend bundle into `dist/`
- `NODE_ENV=production npm start` — Run production server (`node server.ts`)

### HTTP & SSE API (`server.ts`)

- `GET /api/state` — Full snapshot (host status, agents, baselines, real machine logs, alerts, services, audit rules, hash chains)
- `GET /api/stream` — Server-Sent Events (`status`, `agents`, `log`, `alert`, `alerts_updated`, `baselines`, `services`, `chain`)
- `POST /api/terminal/exec` — Execute host/CLI commands (`tamperer`, `tamplogs`, `ls`, `tail`, `stat`, `lsattr`, safe `/var/log/test.log` drills)
- `POST /api/monitor/start` / `POST /api/monitor/stop` — Start or stop real-time `/var/log` watchers
- `POST /api/alerts/:id/ack` / `POST /api/alerts/ack-all` — Acknowledge tamper alerts
- `POST /api/files/harden` / `unharden` / `rebaseline` & `GET /api/files/content` — Manage FIM baselines and `chattr +a`
- `POST /api/chains/verify` / `POST /api/chains/corrupt-demo` — Verify or test-corrupt SHA-256 chains
- `POST /api/spl/query` — Execute SPL search & aggregations
- `GET /api/agents`, `POST /api/agents/enroll`, `POST /api/agents/ingest`, `POST /api/agents/:id/action`, `GET /api/agents/agent.py`, `GET /api/agents/install.sh` — Multi-host agent management
- `POST /api/test-plan/run` & `POST /api/sandbox/reset` — Run Section 12 verification steps & reset baselines/alerts
- `GET /api/bundle/files` & `GET /api/bundle/download` — Inspect or download `tamperer_kali_suite.tar.gz`

## Part 2: Install on Kali Linux (`tamperer` & `tamplogs`)

Download and extract the Kali bundle directly from the running workbench (archive root is `tamperer/`):

```bash
curl -o tamperer_kali_suite.tar.gz http://localhost:3000/api/bundle/download
tar -tzf tamperer_kali_suite.tar.gz
tar -xzf tamperer_kali_suite.tar.gz
cd tamperer
chmod +x install.sh
./install.sh
```

`install.sh` installs system packages (`auditd`, `python3-pip`, `python3-tk`, `python3-yaml`, `audispd-plugins`, `libnotify-bin`, `pulseaudio-utils`, `sound-theme-freedesktop`, `logrotate`), Python packages (`textual`, `inotify_simple`, `pyyaml`), copies scripts into `/opt/tamper_blocker/`, creates `/usr/local/bin/tamplogs`, `/usr/local/bin/tamperer`, and `/usr/share/applications/tamperer.desktop`, and enables `tamper-blocker.service`.

### Usage on Kali

```bash
tamperer                      # Open standalone Burp Suite-style GUI window
sudo tamplogs                 # Launch interactive Textual TUI + popups
sudo tamplogs --no-popup      # TUI only (when systemd service is active)
sudo tamplogs --verify        # Verify alerts.chain & mirror.chain integrity
sudo tamplogs --harden        # Apply chattr +a append-only protection
sudo tamplogs --unharden      # Remove chattr +a (before manual logrotate)
```

## Safe Verification (Section 12)

Always test tamper detection on a throwaway file (`/var/log/test.log`), never live system logs:

```bash
echo test | sudo tee -a /var/log/test.log                      # Appending -> INFO event, 0 alerts
sudo sed -i 's/test/EDIT/' /var/log/test.log                   # Rewriting -> SED_INPLACE_ON_LOG + CONTENT_MODIFIED/INODE_REPLACED
sudo truncate -s 0 /var/log/test.log                           # Truncating -> TRUNCATED + LOG_FILE_COMMAND
sudo chmod 777 /var/log/test.log                               # Permissions -> PERM_OWNER_CHANGE
sudo rm /var/log/test.log                                      # Deletion -> DELETED_OR_MOVED
sudo tamplogs --verify                                         # Hash chains -> True None
```

You can also run steps 1–10 directly from the **Test Plan** tab (`POST /api/test-plan/run`). Note: in minimal container runtimes where `systemd`, `journalctl`, `logrotate`, or `auditctl` are not installed, steps 6–8 and 10 report host binary availability accurately rather than simulating fake daemon output.

## Limitations

- A root attacker can stop `tamper-blocker.service`, run `chattr -a`, or alter files before they are read. Remote agent forwarding plus SHA-256 hash chains (`alerts.chain`, `mirror.chain`) make post-incident tampering provable.
- Hardened (`+a`) logs cannot be rotated by `logrotate` until `--unharden` is run.
- Desktop notifications require an active X11/XWayland session (`--headless` disables popups for daemon mode).
