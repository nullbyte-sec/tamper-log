# Tamper Blocker (tamper-log)

A defensive log-tamper monitor for a single Linux host (built for Kali Linux), plus a web app that simulates it and exports the Kali version.

> Defensive use only, on machines you own or are authorized to monitor.

## What is it?

Tamper Blocker watches system logs, the systemd journal and shell-history files, and alerts you when a log is edited, truncated, deleted, moved, re-permissioned or rotated unexpectedly. It acts like a small SOC for one host.

This repository has two parts:

| Part | What it is | Where |
|---|---|---|
| Web app (simulator) | React + Vite + Tailwind front end with an Express server. Runs the detection engine against a sandbox, with a live alert stream, hash-chain verification, a `tamplogs` terminal console and a runner for the 10-step test plan. | `src/`, `server.ts`, `server/tamperEngine.ts` |
| Kali bundle (the real tool) | Python 3.14 project (`tamper_blocker.py`, `monitor.py`, `alerts.py`, `dashboard.py`, `config.yaml`) that monitors the real host. Downloaded from the web app as `tamper_blocker_kali.tar.gz`. | `server/kaliBundle.ts` |

## Features

- Real-time inotify watch on `/var/log` (recursive), `journalctl -f`, and `~/.*_history` files.
- Per-file baseline: inode, size, mtime, mode, owner, SHA-256 of the already-written bytes.
- Alert kinds include: `TRUNCATED`, `CONTENT_MODIFIED`, `DELETED_OR_MOVED`, `INODE_REPLACED`, `PERM_OWNER_CHANGE`, `LOG_FILE_COMMAND`, `SED_INPLACE_ON_LOG`, `JOURNAL_VACUUM`, `AUDIT_RULES_CHANGED`, `AUDIT_RULES_REMOVED`, `LOGGING_SERVICE_STOPPED`.
- logrotate whitelist: a running or recently seen `logrotate`, or a fresh `/var/lib/logrotate/status`, is treated as legitimate.
- auditd integration (`-k log_tamper`) to report who did it: user, process, PID.
- SHA-256 hash chains for alerts and a mirror of tailed lines (`alerts.chain`, `mirror.chain`), verifiable with `--verify`.
- Optional append-only protection: `--harden` / `--unharden` (`chattr +a` / `-a`).
- Terminal dashboard (Textual): All Logs, per-user, per-file and Alerts views; severity colors; search; pause.
- Desktop popups (`notify-send` plus a Tkinter always-on-top window) sent to the logged-in user's session.

## Part 1: Run the web app

Requirements: Node.js and npm. (ASSUMPTION: a current LTS release, 20 or newer; the repo does not pin a version.)

```bash
git clone https://github.com/nullbyte-sec/tamper-log.git
cd tamper-log
npm install
cp .env.example .env      # placeholders only; see note below
npm run dev               # starts http://localhost:3000
```

Notes:

- `.env.example` lists `GEMINI_API_KEY` and `APP_URL`. Both are placeholders; never commit a real key. OPEN QUESTION: which features, if any, actually call Gemini.
- Port: set `PORT` to change it (default 3000).
- Production: `npm run build`, then `NODE_ENV=production npx tsx server.ts`.
- Type check: `npm run lint`.

### Web API (from `server.ts`)

`GET /api/state`, `GET /api/stream` (SSE), `POST /api/terminal/exec`, `POST /api/monitor/start|stop|noise`, `POST /api/alerts/:id/ack`, `POST /api/alerts/ack-all`, `POST /api/files/harden|unharden|rebaseline`, `GET /api/files/content`, `POST /api/chains/verify`, `POST /api/chains/corrupt-demo`, `POST /api/test-plan/run` (step 1-10), `POST /api/sandbox/reset`, `GET /api/bundle/files`, `GET /api/bundle/download`.

## Part 2: Install the real tool on Kali Linux

Run as a normal user with sudo. The tool itself must run as root.

### 1. System packages and auditd

```bash
sudo apt update
sudo apt install -y auditd python3-pip python3-tk python3-yaml libnotify-bin \
    pulseaudio-utils sound-theme-freedesktop logrotate
sudo systemctl enable --now auditd
```

Do not put `python3-inotify-simple` in this line. It was not found in Kali's apt repositories, and one unknown package name makes apt install nothing, which also skips auditd.

### 2. Python libraries

```bash
sudo pip3 install --break-system-packages textual inotify_simple pyyaml
```

(Alternative: a venv, then point the service `ExecStart` at the venv's python.)

### 3. Get the bundle

With the web app running:

```bash
curl -o tamper_blocker_kali.tar.gz http://localhost:3000/api/bundle/download
tar -tzf tamper_blocker_kali.tar.gz      # check the layout first
```

OPEN QUESTION: the archive layout and any included installer script were not checked. Copy the files so that `tamper_blocker.py`, `monitor.py`, `alerts.py`, `dashboard.py` and `config.yaml` sit directly in `/opt/tamper_blocker/`:

```bash
sudo mkdir -p /opt/tamper_blocker /var/lib/tamper_blocker
sudo tar -xzf tamper_blocker_kali.tar.gz -C /opt/tamper_blocker --strip-components=1   # adjust to the layout above
ls -la /opt/tamper_blocker
```

The default config path is `/opt/tamper_blocker/config.yaml`.

### 4. Command shortcut

```bash
sudo chmod +x /opt/tamper_blocker/tamper_blocker.py
sudo ln -sf /opt/tamper_blocker/tamper_blocker.py /usr/local/bin/tamplogs
```

### 5. Start at boot (systemd)

```bash
sudo tee /etc/systemd/system/tamper-blocker.service > /dev/null <<'EOF'
[Unit]
Description=Tamper Blocker log tamper monitor
After=auditd.service network.target

[Service]
ExecStart=/usr/bin/python3 /opt/tamper_blocker/tamper_blocker.py --headless
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable --now tamper-blocker
sudo systemctl status tamper-blocker --no-pager
```

The service runs `--headless`, which shows no popups. For popups, run the dashboard in a terminal.

### 6. Run it

```bash
sudo tamplogs                 # dashboard + popups
sudo tamplogs --no-popup      # dashboard only (use when the service is also running)
sudo tamplogs --verify        # check the hash chains
sudo tamplogs --harden        # chattr +a on the configured logs
sudo tamplogs --unharden      # chattr -a (do this before logrotate)
```

Dashboard keys: Left/Right switch views, Up/Down scroll, `/` search, `p` pause, `q` quit.

## Configuration

`/opt/tamper_blocker/config.yaml` controls `log_dir`, `history_globs`, `binary_files`, `inplace_ok`, `tail_skip`, `ignore`, `hash_cap_bytes`, `audit_log`, `alert_log`, `mirror_chain`, `remote_syslog` (null by default) and the `harden` list. Alert and mirror chains are stored in `/var/lib/tamper_blocker/`.

## Safe test plan

Use a throwaway file, never a real log:

```bash
echo test | sudo tee -a /var/log/test.log      # append: no alert
sudo truncate -s 0 /var/log/test.log           # TRUNCATED
sudo chmod 777 /var/log/test.log               # PERM_OWNER_CHANGE
sudo rm /var/log/test.log                      # DELETED_OR_MOVED
sudo auditctl -l                               # confirm the log_tamper rules loaded
```

The web app can also run all 10 steps against its sandbox (`POST /api/test-plan/run`).

## Limitations

- A root attacker can stop the tool, remove `chattr +a`, or edit logs before they are read. The hash chains, auditd and remote syslog help you detect and prove this afterwards.
- Process monitoring polls `/proc` every 0.5 s and can miss very short commands; auditd covers the file effects.
- `history -c` and `unset HISTFILE` are shell builtins; only the resulting history-file change is visible.
- Hardened (`+a`) files cannot be rotated by logrotate until you run `--unharden`.
- Popups need an active desktop session. ASSUMPTION: X11; on Wayland the Tkinter window needs XWayland.
- Status: the Python tool started as a systemd service on Kali; end-to-end detection and popup tests on the real host are still to be confirmed.

## License

Not set yet. Add a LICENSE file before sharing publicly.
