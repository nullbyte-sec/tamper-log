# Tamper Blocker (`tamperer` / `tamplogs`)

A real-time Linux log-tamper monitor, cryptographic file integrity (FIM) engine,
multi-host agent collector, and Splunk-inspired SPL log workbench — paired with a
downloadable Kali Linux suite (`tamperer`, `tamplogs`, and `tamperer-agent.py`).

> Defensive use only, on machines you own or are authorized to monitor.

## Requirements

- Kali Linux (or another Debian-based distro)
- Node.js 20+ and npm
- Internet access for `npm install` and `apt` packages

## Part 1: Run the Web Workbench

```bash
git clone https://github.com/nullbyte-sec/tamper-log.git
cd tamper-log
node -v          # must be 20 or higher
npm install --legacy-peer-deps
npm run dev      # starts http://localhost:3000
```

### Fixing the ERESOLVE dependency conflict

If `npm install` fails with an `ERESOLVE` error mentioning `esbuild` or `vite`
peer dependencies (common on Node 24), run:

```bash
rm -rf node_modules package-lock.json
npm install --legacy-peer-deps
```

If that still fails, try:

```bash
npm install --force
```

Note: `--legacy-peer-deps` skips strict peer-dependency checks. This is the
standard fix for esbuild/vite version mismatches.

### Fixing `tsx: not found`

This error means `npm install` didn't complete successfully. Re-run:

```bash
npm install --legacy-peer-deps
npm run dev
```

## Part 2: Download the Kali Bundle

Once the dev server is running (look for `Local: http://localhost:3000` or
`Server listening on port 3000`), open a second terminal:

```bash
cd ~
curl -v -o tamperer_kali_suite.tar.gz http://localhost:3000/api/bundle/download
tar -tzf tamperer_kali_suite.tar.gz    # list contents first
tar -xzf tamperer_kali_suite.tar.gz
cd tamperer
```

### Fixing "Connection refused" on localhost:3000

This means the dev server isn't running. Go back to the first terminal and
make sure `npm run dev` is still active, then retry the curl command.

## Part 3: Install on Kali

```bash
cd ~/tamperer
cat install.sh       # read it before running
chmod +x install.sh
./install.sh
```

The installer:
- Installs apt packages (auditd, python3-pip, python3-tk, python3-yaml, etc.)
- Installs Python packages (textual, inotify_simple, pyyaml)
- Copies scripts into `/opt/tamper_blocker/`
- Creates `/usr/local/bin/tamplogs` and `/usr/local/bin/tamperer`
- Enables `tamper-blocker.service`

### Common pip error on newer Kali

If you see `externally-managed-environment`, the system Python is blocking
global pip installs. Fix:

```bash
sudo apt install python3-venv
python3 -m venv ~/tamper-venv
source ~/tamper-venv/bin/activate
pip install textual inotify_simple pyyaml
```

Then re-run `./install.sh` or manually place the scripts.

## Part 4: Usage

```bash
tamperer                      # GUI window
sudo tamplogs                 # terminal UI
sudo tamplogs --verify        # check hash chains
sudo tamplogs --harden        # chattr +a on logs (skip at first)
sudo tamplogs --unharden      # remove chattr +a before logrotate
```

## Safe Testing

Test only on a throwaway file, never live system logs:

```bash
echo test | sudo tee -a /var/log/test.log
sudo sed -i 's/test/EDIT/' /var/log/test.log
sudo truncate -s 0 /var/log/test.log
sudo chmod 777 /var/log/test.log
sudo rm /var/log/test.log
sudo tamplogs --verify
```

## Trigger Capture (auditd correlation)

When a tamper alert fires, Tamper Blocker correlates it with the auditd event
that caused the write, so you can see *what process/command* triggered it —
not just that a file changed.

### How it works

- On startup, the server installs `auditctl -w <path> -p w -k tamper_watch`
  rules for baselined `/var/log` files (idempotent).
- A continuous tail of `/var/log/audit/audit.log` feeds an in-memory ring
  buffer keyed by the PATH record's `name=`.
- When an alert fires, the correlator searches the buffer for a matching
  audit event within `poll interval + slack` (5s window).
- The matched event's `pid`, `ppid`, `uid`, `exe`, `argv` (reassembled from
  split `a0=`/`a1=`/… and hex-decoded), `cwd`, and `tty` are attached to the
  alert as a `trigger` object.

### Requirements

- `auditd` installed and running
- Server running as root (to read `/var/log/audit/audit.log` and install rules)

### What you'll see

On each alert card: `uid 1000 · bash → curl -o /var/log/test.log ... · tty /dev/pts/3 · cwd /home/kali`
with an expandable full-argv panel.

### Important caveat

Trigger context is **advisory, not tamper-evident proof**. The hash chain proves
the alert existed; it does not prove the trigger wasn't rewritten afterward.
For exact causation (not just correlation), fanotify/eBPF integration is planned
as a v2 feature.

## Cautions

- `--harden` sets `chattr +a` on logs; logrotate can't rotate them until `--unharden` runs.
- The Agents tab uses a `curl ... | sudo bash` installer — only use on hosts you own.
- Keep the web app bound to localhost; don't expose port 3000 to a network.
- The `POST /api/terminal/exec` endpoint runs commands on the host — keep it local.
