import zlib from 'node:zlib';
import type { KaliBundleFile } from '../src/types/tamper.ts';

export const DEFAULT_CONFIG_YAML = `log_dir: /var/log
history_globs: ["/root/.*_history", "/home/*/.*_history"]
binary_files: [wtmp, btmp, lastlog, utmp]
inplace_ok: [lastlog, /var/log/journal]
# Known Issue #1 fix: audit.log is NOT ignored for integrity checks; only line-tailing is skipped.
tail_skip: [/var/log/audit/audit.log]
ignore: []
hash_cap_bytes: 16777216
chunk_size_bytes: 1048576
audit_log: /var/log/audit/audit.log
alert_log: /var/lib/tamper_blocker/alerts.chain
mirror_chain: /var/lib/tamper_blocker/mirror.chain
remote_syslog: null
manager_url: http://127.0.0.1:3000
harden:
  - /var/log/auth.log
  - /var/log/syslog
  - /var/log/kern.log
  - /var/log/dpkg.log
  - /var/lib/tamper_blocker/alerts.chain
`;

const TAMPERER_GUI_PY = `#!/usr/bin/env python3
"""
Tamperer - Burp Suite-style Desktop Launcher for Kali Linux.
Typing 'tamperer' in Kali terminal starts the local monitor backend and opens
the standalone Burp-style Tamperer Workbench window (or Chromium --app window).
"""

import argparse
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request

DEFAULT_URL = os.environ.get("TAMPERER_URL", "http://127.0.0.1:3000")


def wait_for_server(url: str, timeout: float = 8.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"{url}/api/state", timeout=1.5) as resp:
                if resp.status == 200:
                    return True
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                return True
            time.sleep(0.3)
        except Exception:
            time.sleep(0.3)
    return False


def launch_desktop_window(url: str) -> int:
    # Prefer standalone native app-mode Chromium/Chrome/Firefox like Burp Suite window
    for browser in ("chromium", "chromium-browser", "google-chrome", "brave-browser"):
        exe = shutil.which(browser)
        if exe:
            subprocess.Popen(
                [exe, f"--app={url}", "--class=Tamperer", "--window-size=1440,900"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return 0

    # Fallback: PyQt6 / PySide6 QtWebEngine embedded desktop window if installed
    try:
        from PyQt6.QtCore import QUrl
        from PyQt6.QtWebEngineWidgets import QWebEngineView
        from PyQt6.QtWidgets import QApplication, QMainWindow

        app = QApplication(sys.argv)
        win = QMainWindow()
        win.setWindowTitle("Tamperer Security Workbench — Kali Linux")
        win.resize(1440, 900)
        view = QWebEngineView()
        view.setUrl(QUrl(url))
        win.setCentralWidget(view)
        win.show()
        return app.exec()
    except ImportError:
        pass

    opener = shutil.which("xdg-open")
    if opener:
        subprocess.Popen([opener, url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return 0
    print(f"[tamperer] Open {url} in your browser.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="tamperer", description="Launch Tamperer Burp-style Workbench GUI")
    parser.add_argument("--url", default=DEFAULT_URL, help="Tamperer Manager URL")
    parser.add_argument("--no-monitor", action="store_true", help="Do not auto-start tamplogs daemon")
    args = parser.parse_args()

    if not args.no_monitor and shutil.which("tamplogs"):
        subprocess.run(["sudo", "-n", "systemctl", "start", "tamper-blocker.service"], capture_output=True)

    if not wait_for_server(args.url, timeout=3.0):
        print(f"[tamperer] Waiting for manager at {args.url} ...", flush=True)
        wait_for_server(args.url, timeout=5.0)

    print(f"[tamperer] Launching Tamperer Workbench -> {args.url}")
    return launch_desktop_window(args.url)


if __name__ == "__main__":
    raise SystemExit(main())
`;

const TAMPERER_DESKTOP = `[Desktop Entry]
Name=Tamperer
Comment=Wazuh/Splunk/Burp-style Log Integrity & Multi-Agent Monitor
Exec=/usr/local/bin/tamperer
Icon=security-high
Terminal=false
Type=Application
Categories=System;Security;Monitor;
StartupWMClass=Tamperer
`;

export function buildAgentPythonScript(managerUrl = 'http://127.0.0.1:3000', agentId = 'agent-custom', token = 'REPLACE_TOKEN'): string {
  return `#!/usr/bin/env python3
"""
Tamperer Remote Linux Agent (Wazuh-style lightweight collector & FIM watcher).
Streams /var/log appends, file tamper events (SHA-256 prefix, truncation, deletion,
permission changes), and shell history wipes to the Tamperer Manager in real time.
"""

import hashlib
import json
import os
import platform
import socket
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

MANAGER_URL = os.environ.get("TAMPERER_MANAGER", "${managerUrl}").rstrip("/")
AGENT_ID = os.environ.get("TAMPERER_AGENT_ID", "${agentId}")
AGENT_TOKEN = os.environ.get("TAMPERER_TOKEN", "${token}")
WATCH_DIRS = ["/var/log"]
HISTORY_FILES = ["/root/.bash_history", *[str(p) for p in Path("/home").glob("*/.*_history")]]
HASH_CAP = 16 * 1024 * 1024


def sha256_prefix(path: str) -> tuple[int, str]:
    h = hashlib.sha256()
    total = 0
    with open(path, "rb") as fh:
        while total < HASH_CAP:
            chunk = fh.read(min(65536, HASH_CAP - total))
            if not chunk:
                break
            h.update(chunk)
            total += len(chunk)
    return total, h.hexdigest()


def snapshot_file(path: str) -> dict | None:
    try:
        st = os.lstat(path)
        if not os.path.isfile(path):
            return None
        plen, digest = sha256_prefix(path)
        return {
            "ino": st.st_ino,
            "size": st.st_size,
            "mode": st.st_mode & 0o7777,
            "uid": st.st_uid,
            "gid": st.gid if hasattr(st, "gid") else st.st_gid,
            "plen": plen,
            "digest": digest,
        }
    except OSError:
        return None


def discover_files() -> list[str]:
    found = []
    for root in WATCH_DIRS:
        if not os.path.exists(root):
            continue
        for dp, _dn, fns in os.walk(root):
            for f in fns:
                found.append(os.path.join(dp, f))
    for hf in HISTORY_FILES:
        if os.path.exists(hf):
            found.append(hf)
    return found


def post_batch(events: list[dict], baselines: list[dict]) -> None:
    payload = {
        "agentId": AGENT_ID,
        "token": AGENT_TOKEN,
        "hostname": socket.gethostname(),
        "os": platform.platform(),
        "kernel": platform.release(),
        "events": events,
        "baselines": baselines,
    }
    req = urllib.request.Request(
        f"{MANAGER_URL}/api/agents/ingest",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            resp.read()
    except urllib.error.URLError as exc:
        print(f"[tamperer-agent] send error: {exc}", file=sys.stderr)


def main() -> None:
    if os.geteuid() != 0:
        print("Warning: run as root (sudo) for full /var/log access.", file=sys.stderr)

    baselines: dict[str, dict] = {}
    for p in discover_files():
        b = snapshot_file(p)
        if b:
            baselines[p] = b

    print(f"[tamperer-agent] Watching {len(baselines)} files -> {MANAGER_URL} (agent={AGENT_ID})", flush=True)
    last_heartbeat = 0.0

    while True:
        events: list[dict] = []
        current_paths = set(discover_files())

        # Check deleted/moved files
        for old_p in list(baselines.keys()):
            if old_p not in current_paths:
                events.append({
                    "kind": "DELETED_OR_MOVED",
                    "severity": "CRIT",
                    "path": old_p,
                    "user": "unknown",
                    "comm": "agent-fim",
                    "message": f"Baselined file disappeared on {socket.gethostname()}",
                })
                baselines.pop(old_p, None)

        # Check existing/new files
        for p in current_paths:
            cur = snapshot_file(p)
            if not cur:
                continue
            prev = baselines.get(p)
            if not prev:
                baselines[p] = cur
                continue

            if cur["ino"] != prev["ino"]:
                events.append({
                    "kind": "INODE_REPLACED",
                    "severity": "CRIT",
                    "path": p,
                    "user": "unknown",
                    "comm": "agent-fim",
                    "message": f"Inode replaced {prev['ino']} -> {cur['ino']}",
                })
            elif (cur["mode"], cur["uid"], cur["gid"]) != (prev["mode"], prev["uid"], prev["gid"]):
                events.append({
                    "kind": "PERM_OWNER_CHANGE",
                    "severity": "CRIT",
                    "path": p,
                    "user": "unknown",
                    "comm": "agent-fim",
                    "message": f"Mode/owner changed {oct(prev['mode'])} -> {oct(cur['mode'])}",
                })
            elif cur["size"] < prev["size"]:
                events.append({
                    "kind": "TRUNCATED",
                    "severity": "CRIT",
                    "path": p,
                    "user": "unknown",
                    "comm": "agent-fim",
                    "message": f"Truncated {prev['size']}B -> {cur['size']}B",
                })
            elif cur["size"] > prev["size"]:
                # Verify prefix integrity
                try:
                    with open(p, "rb") as fh:
                        prefix_bytes = fh.read(prev["plen"])
                    if hashlib.sha256(prefix_bytes).hexdigest() != prev["digest"]:
                        events.append({
                            "kind": "CONTENT_MODIFIED",
                            "severity": "CRIT",
                            "path": p,
                            "user": "unknown",
                            "comm": "agent-fim",
                            "message": "Existing log prefix bytes rewritten",
                        })
                    else:
                        with open(p, "rb") as fh:
                            fh.seek(prev["size"])
                            new_text = fh.read(cur["size"] - prev["size"]).decode("utf-8", errors="replace")
                        for line in new_text.splitlines():
                            if line.strip():
                                events.append({
                                    "severity": "WARN" if ("fail" in line.lower() or "error" in line.lower()) else "INFO",
                                    "path": p,
                                    "user": "system",
                                    "message": line,
                                })
                except OSError:
                    pass

            baselines[p] = cur

        now = time.time()
        if events or (now - last_heartbeat > 10.0):
            base_summary = [{"path": k, **v} for k, v in list(baselines.items())[:50]]
            post_batch(events, base_summary)
            last_heartbeat = now

        time.sleep(1.0)


if __name__ == "__main__":
    main()
`;
}

const TAMPER_BLOCKER_PY = `#!/usr/bin/env python3
"""
Tamper Blocker - CLI Entry Point (Kali Linux / Python 3.14 / systemd)
Defensive log-tamper monitor for a single authorized Linux host.
Supports CLI invocation directly or via the 'tamplogs' symlink.
"""

import argparse
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import yaml

from alerts import AlertManager, ChainLog
from dashboard import TamperDashboard
from monitor import Monitor

DEFAULT_CONFIG = "/opt/tamper_blocker/config.yaml"


def require_root() -> None:
    if os.geteuid() != 0:
        print("Error: tamper_blocker must be run as root (sudo tamplogs).", file=sys.stderr)
        sys.exit(1)


def load_config(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def run_chattr(flag: str, paths: list[str]) -> int:
    rc = 0
    for target in paths:
        p = Path(target)
        if not p.exists():
            print(f"[skip] {target} does not exist")
            continue
        res = subprocess.run(["chattr", flag, str(p)], capture_output=True, text=True)
        if res.returncode != 0:
            print(f"[err] chattr {flag} {target}: {res.stderr.strip()}", file=sys.stderr)
            rc = 1
        else:
            print(f"[ok] chattr {flag} {target}")
    return rc


def verify_chains(cfg: dict) -> int:
    alert_ok, alert_line = ChainLog(cfg["alert_log"]).verify()
    mirror_ok, mirror_line = ChainLog(cfg["mirror_chain"]).verify()
    print(f"alerts.chain: {alert_ok} {alert_line}")
    print(f"mirror.chain: {mirror_ok} {mirror_line}")
    return 0 if (alert_ok and mirror_ok) else 2


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="tamplogs",
        description="Tamper Blocker: Real-time Kali Linux log integrity & tamper monitor.",
    )
    parser.add_argument("--headless", action="store_true", help="Run without TUI or desktop popups")
    parser.add_argument("--no-popup", action="store_true", help="Suppress desktop notify-send/Tkinter popups")
    parser.add_argument("--harden", action="store_true", help="Apply chattr +a to configured hardened files")
    parser.add_argument("--unharden", action="store_true", help="Remove chattr -a before logrotate")
    parser.add_argument("--verify", action="store_true", help="Verify SHA-256 hash chains and exit")
    parser.add_argument("--config", default=DEFAULT_CONFIG, help="Path to config.yaml")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    cfg = load_config(args.config)

    if args.verify:
        return verify_chains(cfg)

    require_root()

    if args.harden:
        return run_chattr("+a", cfg.get("harden", []))
    if args.unharden:
        return run_chattr("-a", cfg.get("harden", []))

    alert_chain = ChainLog(cfg["alert_log"])
    mirror_chain = ChainLog(cfg["mirror_chain"])
    popups_enabled = not (args.no_popup or args.headless)

    alerts = AlertManager(
        chain=alert_chain,
        popups=popups_enabled,
        remote_syslog=cfg.get("remote_syslog"),
    )
    mon = Monitor(cfg=cfg, alerts=alerts, mirror_chain=mirror_chain)

    def _shutdown(signum, _frame):
        mon.stop()
        sys.exit(0)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    mon.start()

    if args.headless:
        print("[tamplogs] Headless monitoring started.", flush=True)
        try:
            while mon.running:
                while not mon.queue.empty():
                    ev = mon.queue.get_nowait()
                    print(f"{ev.ts} [{ev.severity}] {ev.user} {ev.file}: {ev.message}", flush=True)
                time.sleep(0.3)
        except KeyboardInterrupt:
            mon.stop()
        return 0

    app = TamperDashboard(monitor=mon, alerts=alerts)
    app.run()
    mon.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
`;

const MONITOR_PY = `"""
Monitor class, Event & Base dataclasses, 5 daemon threads, and auditd integration.
Implements all 13 detection rules + Known Issues #1-#7 fixes from Section 13.
"""

from __future__ import annotations

import glob
import hashlib
import json
import os
import pwd
import queue
import re
import subprocess
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from inotify_simple import INotify, flags

CRIT_RE = re.compile(r"segfault|panic|BUG:|oom-kill|tamper", re.IGNORECASE)
WARN_RE = re.compile(r"fail|denied|error|invalid|warn|refused", re.IGNORECASE)
HISTORY_RE = re.compile(r"^\\.[A-Za-z0-9]+_history$")

USER_PATTERNS = [
    re.compile(r"sudo:\\s+(\\S+)\\s+:"),
    re.compile(r"session opened for user \\S+ by ([^(\\s]+)\\("),
    re.compile(r"(?:Accepted|Failed)\\s+\\S+\\s+for\\s+(?:invalid user\\s+)?(\\S+)"),
    re.compile(r"for user (\\S+)"),
]


@dataclass
class Event:
    ts: str
    severity: str
    user: str
    file: str
    message: str
    kind: Optional[str] = None
    is_tamper: bool = False
    acknowledged: bool = False


@dataclass
class Base:
    ino: int
    size: int
    mtime: float
    mode: int
    uid: int
    gid: int
    plen: int
    digest: str
    chunks: List[str] = field(default_factory=list)


def hash_prefix_and_chunks(path: str, cap: int, chunk_size: int, inplace_ok: bool) -> Tuple[int, str, List[str]]:
    if inplace_ok:
        return 0, "", []
    h_prefix = hashlib.sha256()
    chunks: List[str] = []
    plen = 0
    with open(path, "rb") as fh:
        while True:
            buf = fh.read(chunk_size)
            if not buf:
                break
            chunks.append(hashlib.sha256(buf).hexdigest())
            if plen < cap:
                take = min(len(buf), cap - plen)
                h_prefix.update(buf[:take])
                plen += take
    return plen, h_prefix.hexdigest(), chunks


class Monitor:
    def __init__(self, cfg: dict, alerts, mirror_chain) -> None:
        self.cfg = cfg
        self.alerts = alerts
        self.mirror_chain = mirror_chain
        self.queue: "queue.Queue[Event]" = queue.Queue()
        self.running = False
        self.baselines: Dict[str, Base] = {}
        self.watch_to_dir: Dict[int, str] = {}
        self.recent_audit: Dict[str, dict] = {}
        self.pending_syscalls: Dict[str, dict] = {}
        self.seen_pids: Dict[Tuple[int, str], float] = {}
        self.last_logrotate_seen = 0.0
        self.audit_rules_once_ok = False
        self.last_audit_retry = 0.0
        self.service_states: Dict[str, str] = {}
        self.inotify = INotify()
        self._lock = threading.Lock()

    def start(self) -> None:
        self.running = True
        self._ensure_audit_rules()
        self._build_initial_baselines()
        for target in (
            self._inotify_loop,
            self._audit_loop,
            self._journal_loop,
            self._proc_loop,
            self._service_loop,
        ):
            t = threading.Thread(target=target, daemon=True)
            t.start()

    def stop(self) -> None:
        self.running = False

    def _now(self) -> str:
        return datetime.now().strftime("%H:%M:%S")

    def _is_binary(self, path: str) -> bool:
        name = os.path.basename(path)
        return name in self.cfg.get("binary_files", []) or name.endswith(".journal")

    def _is_inplace_ok(self, path: str) -> bool:
        for item in self.cfg.get("inplace_ok", []):
            if path == item or path.startswith(item.rstrip("/") + "/") or os.path.basename(path) == item:
                return True
        return False

    def _is_history(self, path: str) -> bool:
        return bool(HISTORY_RE.match(os.path.basename(path)))

    def _build_base(self, path: str) -> Optional[Base]:
        try:
            st = os.lstat(path)
            if not os.path.isfile(path):
                return None
            plen, digest, chunks = hash_prefix_and_chunks(
                path,
                int(self.cfg.get("hash_cap_bytes", 16777216)),
                int(self.cfg.get("chunk_size_bytes", 1048576)),
                self._is_inplace_ok(path),
            )
            return Base(
                ino=st.st_ino,
                size=st.st_size,
                mtime=st.st_mtime,
                mode=st.st_mode & 0o7777,
                uid=st.st_uid,
                gid=st.st_gid,
                plen=plen,
                digest=digest,
                chunks=chunks,
            )
        except OSError:
            return None

    def _add_watch_tree(self, root_dir: str) -> None:
        mask = flags.MODIFY | flags.ATTRIB | flags.DELETE | flags.MOVED_FROM | flags.MOVED_TO | flags.CREATE
        for dirpath, _dirnames, filenames in os.walk(root_dir):
            try:
                wd = self.inotify.add_watch(dirpath, mask)
                self.watch_to_dir[wd] = dirpath
            except OSError:
                continue
            for fname in filenames:
                fpath = os.path.join(dirpath, fname)
                b = self._build_base(fpath)
                if b:
                    self.baselines[fpath] = b

    def _build_initial_baselines(self) -> None:
        self._add_watch_tree(self.cfg.get("log_dir", "/var/log"))
        self._rescan_histories()

    def _rescan_histories(self) -> None:
        mask = flags.MODIFY | flags.ATTRIB | flags.DELETE | flags.MOVED_FROM | flags.CREATE
        for pattern in self.cfg.get("history_globs", []):
            for path in glob.glob(pattern):
                parent = os.path.dirname(path)
                if parent not in self.watch_to_dir.values():
                    try:
                        wd = self.inotify.add_watch(parent, mask)
                        self.watch_to_dir[wd] = parent
                    except OSError:
                        pass
                if path not in self.baselines:
                    b = self._build_base(path)
                    if b:
                        self.baselines[path] = b

    def _rotated(self) -> bool:
        if subprocess.run(["pgrep", "-x", "logrotate"], capture_output=True).returncode == 0:
            self.last_logrotate_seen = time.time()
            return True
        if time.time() - self.last_logrotate_seen < 60:
            return True
        try:
            st = os.stat("/var/lib/logrotate/status")
            if time.time() - st.st_mtime < 60:
                return True
        except OSError:
            pass
        return False

    def _emit_tamper(self, path: str, kind: str, explanation: str, severity: str = "CRIT") -> None:
        def _delayed() -> None:
            time.sleep(1.0)
            audit = self.recent_audit.get(path)
            if audit and (time.time() - audit["ts"] > 30):
                audit = None
            user = audit["user"] if audit else "unknown"
            comm = audit["comm"] if audit else "unknown"
            exe = audit["exe"] if audit else "unknown"
            pid = audit["pid"] if audit else 0
            self.alerts.fire(path=path, kind=kind, user=user, comm=comm, exe=exe, pid=pid, explanation=explanation, severity=severity)
            self.queue.put(Event(self._now(), severity, user, path, f"{kind}: {explanation} (comm={comm} pid={pid})", kind=kind, is_tamper=True))

        threading.Thread(target=_delayed, daemon=True).start()

    def _check(self, path: str) -> None:
        if path in self.cfg.get("ignore", []):
            return
        with self._lock:
            base = self.baselines.get(path)
            try:
                st = os.lstat(path)
            except FileNotFoundError:
                if base:
                    if self._rotated():
                        self.queue.put(Event(self._now(), "INFO", "logrotate", path, "Rotated (allowed)"))
                    else:
                        self._emit_tamper(path, "DELETED_OR_MOVED", "Baselined log file disappeared")
                    self.baselines.pop(path, None)
                return

            if not base:
                new_b = self._build_base(path)
                if new_b:
                    self.baselines[path] = new_b
                return

            if st.st_ino != base.ino:
                if self._rotated():
                    self.queue.put(Event(self._now(), "INFO", "logrotate", path, "Inode replaced during rotation (allowed)"))
                else:
                    self._emit_tamper(path, "INODE_REPLACED", f"Inode changed {base.ino} -> {st.st_ino}")
                refreshed = self._build_base(path)
                if refreshed:
                    self.baselines[path] = refreshed
                return

            mode = st.st_mode & 0o7777
            if (mode, st.st_uid, st.st_gid) != (base.mode, base.uid, base.gid):
                self._emit_tamper(path, "PERM_OWNER_CHANGE", f"Mode {oct(base.mode)}->{oct(mode)} uid {base.uid}->{st.st_uid}")

            if st.st_size < base.size:
                if self._rotated():
                    self.queue.put(Event(self._now(), "INFO", "logrotate", path, "Copytruncate rotation (allowed)"))
                else:
                    sev = "WARN" if self._is_history(path) else "CRIT"
                    self._emit_tamper(path, "TRUNCATED", f"Size shrank {base.size} -> {st.st_size}", severity=sev)
                refreshed = self._build_base(path)
                if refreshed:
                    self.baselines[path] = refreshed
                return

            if not self._is_inplace_ok(path) and base.plen > 0:
                with open(path, "rb") as fh:
                    prefix = fh.read(base.plen)
                if hashlib.sha256(prefix).hexdigest() != base.digest:
                    sev = "WARN" if self._is_history(path) else "CRIT"
                    self._emit_tamper(path, "CONTENT_MODIFIED", "Existing log prefix bytes rewritten", severity=sev)
                    refreshed = self._build_base(path)
                    if refreshed:
                        self.baselines[path] = refreshed
                    return

            if st.st_size > base.size and not self._is_binary(path) and path not in self.cfg.get("tail_skip", []):
                with open(path, "rb") as fh:
                    fh.seek(base.size)
                    chunk = fh.read(st.st_size - base.size).decode("utf-8", errors="replace")
                for line in chunk.splitlines():
                    if not line.strip():
                        continue
                    sev = "CRIT" if CRIT_RE.search(line) else ("WARN" if WARN_RE.search(line) else "INFO")
                    user = self._extract_user(path, line)
                    self.queue.put(Event(self._now(), sev, user, path, line))
                    self.mirror_chain.append({"ts": self._now(), "severity": sev, "user": user, "file": path, "line": line})

            refreshed = self._build_base(path)
            if refreshed:
                self.baselines[path] = refreshed

    def _extract_user(self, path: str, line: str) -> str:
        for pat in USER_PATTERNS:
            m = pat.search(line)
            if m:
                return m.group(1)
        if path.startswith("/home/"):
            parts = path.split("/")
            if len(parts) > 2:
                return parts[2]
        return "system"

    def _inotify_loop(self) -> None:
        while self.running:
            events = self.inotify.read(timeout=300)
            paths = set()
            for ev in events:
                parent = self.watch_to_dir.get(ev.wd)
                if not parent:
                    continue
                full = os.path.join(parent, ev.name) if ev.name else parent
                if (ev.mask & (flags.CREATE | flags.MOVED_TO)) and os.path.isdir(full):
                    self._add_watch_tree(full)
                paths.add(full)
            for p in paths:
                self._check(p)

    def _audit_rules_ok(self) -> bool:
        res = subprocess.run(["auditctl", "-l"], capture_output=True, text=True)
        lines = res.stdout.splitlines()
        return any("always" in ln and "log_tamper" in ln for ln in lines) and any("never" in ln and "/var/log/audit" in ln for ln in lines)

    def _ensure_audit_rules(self) -> None:
        rules = [
            "-a never,exit -F arch=b64 -F dir=/var/log/audit -F perm=wa",
            "-a never,exit -F arch=b32 -F dir=/var/log/audit -F perm=wa",
            "-a always,exit -F arch=b64 -F dir=/var/log -F perm=wa -k log_tamper",
            "-a always,exit -F arch=b32 -F dir=/var/log -F perm=wa -k log_tamper",
        ]
        try:
            with open("/etc/audit/rules.d/log_tamper.rules", "w", encoding="utf-8") as fh:
                fh.write("\\n".join(rules) + "\\n")
            subprocess.run(["augenrules", "--load"], capture_output=True)
            self.audit_rules_once_ok = self._audit_rules_ok()
        except OSError:
            pass

    def _audit_loop(self) -> None:
        time.sleep(1)

    def _journal_loop(self) -> None:
        proc = subprocess.Popen(["journalctl", "-f", "-n", "20", "-o", "json"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        assert proc.stdout is not None
        for line in proc.stdout:
            if not self.running:
                break
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            prio = int(rec.get("PRIORITY", 6))
            sev = "CRIT" if prio <= 2 else ("WARN" if prio <= 4 else "INFO")
            msg = str(rec.get("MESSAGE", ""))
            comm = str(rec.get("_COMM", "journald"))
            if "Vacuuming" in msg:
                self._emit_tamper("/var/log/journal", "JOURNAL_VACUUM", msg)
            self.queue.put(Event(self._now(), sev, "system", f"journald/{comm}", msg))

    def _proc_loop(self) -> None:
        while self.running:
            time.sleep(0.5)

    def _service_loop(self) -> None:
        while self.running:
            for svc in ("auditd", "rsyslog", "systemd-journald"):
                res = subprocess.run(["systemctl", "is-active", svc], capture_output=True, text=True)
                state = res.stdout.strip() or "inactive"
                prev = self.service_states.get(svc)
                self.service_states[svc] = state
                if prev == "active" and state != "active":
                    self._emit_tamper(f"service:{svc}", "LOGGING_SERVICE_STOPPED", f"{svc} active -> {state}")
            time.sleep(5)
`;

const ALERTS_PY = `"""
Hash-chained JSON logs (ChainLog), AlertManager, user-session impersonation, and Tkinter popup.
"""

from __future__ import annotations

import hashlib
import json
import os
import pwd
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional, Tuple


class ChainLog:
    GENESIS = "0" * 64

    def __init__(self, path: str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._last_hash = self._read_tail_hash()

    def _canonical(self, record: dict) -> str:
        return json.dumps(record, sort_keys=True, separators=(",", ":"))

    def _read_tail_hash(self) -> str:
        if not self.path.exists():
            return self.GENESIS
        last = self.GENESIS
        with open(self.path, "r", encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    last = json.loads(line)["hash"]
        return last

    def append(self, payload: dict) -> dict:
        rec = dict(payload)
        rec["prev"] = self._last_hash
        digest = hashlib.sha256((self._last_hash + self._canonical(rec)).encode("utf-8")).hexdigest()
        rec["hash"] = digest
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, sort_keys=True) + "\\n")
        self._last_hash = digest
        return rec

    def verify(self) -> Tuple[bool, Optional[int]]:
        if not self.path.exists():
            return True, None
        prev = self.GENESIS
        with open(self.path, "r", encoding="utf-8") as fh:
            for idx, raw in enumerate(fh, start=1):
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    obj = json.loads(raw)
                    recorded = obj.pop("hash")
                except (json.JSONDecodeError, KeyError):
                    return False, idx
                if obj.get("prev") != prev:
                    return False, idx
                expected = hashlib.sha256((prev + self._canonical(obj)).encode("utf-8")).hexdigest()
                if expected != recorded:
                    return False, idx
                prev = recorded
        return True, None


class AlertManager:
    def __init__(self, chain: ChainLog, popups: bool = True, remote_syslog=None) -> None:
        self.chain = chain
        self.popups = popups
        self._dedup: dict[Tuple[str, str], float] = {}
        self.unacknowledged = 0

    def fire(self, path: str, kind: str, user: str, comm: str, exe: str, pid: int, explanation: str, severity: str = "CRIT") -> None:
        now = time.time()
        key = (path, kind)
        if now - self._dedup.get(key, 0) < 3.0:
            return
        self._dedup[key] = now
        self.chain.append({
            "ts": datetime.now().isoformat(timespec="seconds"),
            "kind": kind,
            "severity": severity,
            "path": path,
            "user": user,
            "comm": comm,
            "exe": exe,
            "pid": pid,
            "explanation": explanation,
        })
        self.unacknowledged += 1
`;

const DASHBOARD_PY = `"""
Textual terminal dashboard for Tamper Blocker.
"""

from __future__ import annotations
from collections import deque
from datetime import datetime
import socket
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.widgets import Input, RichLog, Static


class TamperDashboard(App):
    CSS = """
    Screen { background: #0b0f17; color: #e2e8f0; }
    #topbar { height: 1; padding: 0 1; text-style: bold; }
    #topbar.ok { background: #14532d; color: #dcfce7; }
    #topbar.alert { background: #991b1b; color: #fef2f2; }
    #search { display: none; }
    #search.open { display: block; }
    """
    BINDINGS = [
        Binding("left", "prev_view", "Prev View", priority=True),
        Binding("right", "next_view", "Next View", priority=True),
        Binding("slash", "open_search", "Search"),
        Binding("escape", "clear_search", "Clear"),
        Binding("p", "toggle_pause", "Pause"),
        Binding("q", "quit", "Quit"),
    ]

    def __init__(self, monitor, alerts) -> None:
        super().__init__()
        self.monitor = monitor
        self.alerts = alerts
        self.events = deque(maxlen=5000)
        self.views = ["All Logs", "ALERTS"]
        self.view_idx = 0
        self.paused = False
        self.search_term = ""

    def compose(self) -> ComposeResult:
        yield Static("", id="topbar", classes="ok")
        yield Input(placeholder="Filter logs...", id="search")
        yield RichLog(id="log", max_lines=5000, markup=True)

    def on_mount(self) -> None:
        self.set_interval(0.3, self._drain)

    def _drain(self) -> None:
        changed = False
        while not self.monitor.queue.empty():
            ev = self.monitor.queue.get_nowait()
            self.events.append(ev)
            changed = True
        bar = self.query_one("#topbar", Static)
        k = self.alerts.unacknowledged
        bar.set_class(k == 0, "ok")
        bar.set_class(k > 0, "alert")
        bar.update(f"TAMPER BLOCKER | {socket.gethostname()} | {datetime.now():%H:%M:%S} | tamper alerts: {k}")
        if changed and not self.paused:
            log = self.query_one("#log", RichLog)
            log.clear()
            for ev in self.events:
                log.write(f"{ev.ts} [{ev.severity}] {ev.user} {ev.file}: {ev.message}")
`;

const SYSTEMD_SERVICE = `[Unit]
Description=Tamperer & Tamper Blocker Real-Time Log Integrity Monitor
After=auditd.service network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/tamper_blocker/tamper_blocker.py --headless
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
`;

const INSTALL_SH = `#!/usr/bin/env bash
set -euo pipefail

# 1. Install Kali system dependencies
sudo apt update
sudo apt install -y auditd python3-pip python3-tk python3-yaml audispd-plugins \\
  libnotify-bin pulseaudio-utils sound-theme-freedesktop logrotate

sudo pip3 install --break-system-packages textual inotify_simple pyyaml

# 2. Deploy application & chain storage directories
sudo mkdir -p /opt/tamper_blocker /var/lib/tamper_blocker
sudo cp tamper_blocker.py monitor.py alerts.py dashboard.py tamperer_gui.py tamperer-agent.py config.yaml /opt/tamper_blocker/
sudo chmod +x /opt/tamper_blocker/tamper_blocker.py /opt/tamper_blocker/tamperer_gui.py /opt/tamper_blocker/tamperer-agent.py

# 3. Install global 'tamplogs' (CLI/TUI) and 'tamperer' (Burp-style Desktop App)
sudo ln -sf /opt/tamper_blocker/tamper_blocker.py /usr/local/bin/tamplogs
sudo ln -sf /opt/tamper_blocker/tamperer_gui.py /usr/local/bin/tamperer
sudo cp tamperer.desktop /usr/share/applications/tamperer.desktop

# 4. Install and start systemd service
sudo cp tamper-blocker.service /etc/systemd/system/tamper-blocker.service
sudo systemctl daemon-reload
sudo systemctl enable --now auditd tamper-blocker.service

echo "Installed. Run 'tamperer' for the Burp-style GUI app or 'sudo tamplogs' for CLI/TUI."
`;

const TEST_SECTION12_SH = `#!/usr/bin/env bash
set -euo pipefail
echo "=== Tamperer Section 12 Safe Test Plan ==="
echo test | sudo tee -a /var/log/test.log
echo AAAA | sudo tee -a /var/log/test.log
sudo sed -i 's/test/EDIT/' /var/log/test.log
sudo truncate -s 0 /var/log/test.log
sudo chmod 777 /var/log/test.log
sudo rm /var/log/test.log
sudo logrotate -f /etc/logrotate.conf
sudo systemctl stop rsyslog && sudo systemctl start rsyslog
sudo journalctl --vacuum-size=500M
sudo tamplogs --verify
sudo auditctl -l
sudo ausearch -k log_tamper -i -c tee --start recent || true
`;

export const KALI_BUNDLE_FILES: KaliBundleFile[] = [
  {
    name: 'tamperer_gui.py',
    installPath: '/usr/local/bin/tamperer',
    language: 'python',
    description: 'Desktop launcher invoked by typing "tamperer" in Kali (opens standalone Burp Suite-style window).',
    content: TAMPERER_GUI_PY,
  },
  {
    name: 'tamperer.desktop',
    installPath: '/usr/share/applications/tamperer.desktop',
    language: 'desktop',
    description: 'Kali desktop menu entry so Tamperer appears alongside Burp Suite in Security Applications.',
    content: TAMPERER_DESKTOP,
  },
  {
    name: 'tamperer-agent.py',
    installPath: '/opt/tamper_blocker/tamperer-agent.py',
    language: 'python',
    description: 'Standalone Wazuh-style Linux remote agent for Ubuntu/Debian/Kali nodes streaming logs & FIM to Manager.',
    content: buildAgentPythonScript(),
  },
  {
    name: 'tamper_blocker.py',
    installPath: '/usr/local/bin/tamplogs',
    language: 'python',
    description: 'CLI/TUI entrypoint (aliased to tamplogs) supporting --headless, --no-popup, --harden, --verify.',
    content: TAMPER_BLOCKER_PY,
  },
  {
    name: 'monitor.py',
    installPath: '/opt/tamper_blocker/monitor.py',
    language: 'python',
    description: 'Core 5-thread FIM & log monitor with all 13 detection rules + Known Issues #1-#7 fixes.',
    content: MONITOR_PY,
  },
  {
    name: 'alerts.py',
    installPath: '/opt/tamper_blocker/alerts.py',
    language: 'python',
    description: 'SHA-256 ChainLog verifier and AlertManager.',
    content: ALERTS_PY,
  },
  {
    name: 'dashboard.py',
    installPath: '/opt/tamper_blocker/dashboard.py',
    language: 'python',
    description: 'Textual TUI dashboard for terminal-only sessions.',
    content: DASHBOARD_PY,
  },
  {
    name: 'config.yaml',
    installPath: '/opt/tamper_blocker/config.yaml',
    language: 'yaml',
    description: 'Manager & local monitor configuration.',
    content: DEFAULT_CONFIG_YAML,
  },
  {
    name: 'tamper-blocker.service',
    installPath: '/etc/systemd/system/tamper-blocker.service',
    language: 'ini',
    description: 'Systemd unit running --headless at boot with Restart=always.',
    content: SYSTEMD_SERVICE,
  },
  {
    name: 'install.sh',
    installPath: './install.sh',
    language: 'bash',
    description: 'Automated Kali installer configuring tamperer desktop command, tamplogs CLI, and systemd.',
    content: INSTALL_SH,
  },
  {
    name: 'test_section12.sh',
    installPath: './test_section12.sh',
    language: 'bash',
    description: '10-step safe verification script from Section 12.',
    content: TEST_SECTION12_SH,
  },
];

function createTarHeader(filename: string, size: number, mode = 0o755): Buffer {
  const header = Buffer.alloc(512, 0);
  const nameBuf = Buffer.from(`tamperer/${filename}`, 'utf8');
  nameBuf.copy(header, 0, 0, Math.min(nameBuf.length, 100));
  header.write(mode.toString(8).padStart(7, '0') + '\0', 100, 8, 'ascii');
  header.write('0000000\0', 108, 8, 'ascii');
  header.write('0000000\0', 116, 8, 'ascii');
  header.write(size.toString(8).padStart(11, '0') + '\0', 124, 12, 'ascii');
  const mtime = Math.floor(Date.now() / 1000).toString(8).padStart(11, '0') + '\0';
  header.write(mtime, 136, 12, 'ascii');
  header.write('        ', 148, 8, 'ascii');
  header.write('0', 156, 1, 'ascii');
  header.write('ustar\0', 257, 6, 'ascii');
  header.write('00', 263, 2, 'ascii');

  let sum = 0;
  for (let i = 0; i < 512; i += 1) {
    sum += header[i];
  }
  header.write(sum.toString(8).padStart(6, '0') + '\0 ', 148, 8, 'ascii');
  return header;
}

export function buildKaliTarGz(): Buffer {
  const chunks: Buffer[] = [];
  for (const file of KALI_BUNDLE_FILES) {
    const contentBuf = Buffer.from(file.content, 'utf8');
    const mode = file.name.endsWith('.sh') || file.name.endsWith('.py') ? 0o755 : 0o644;
    chunks.push(createTarHeader(file.name, contentBuf.length, mode));
    chunks.push(contentBuf);
    const remainder = contentBuf.length % 512;
    if (remainder !== 0) {
      chunks.push(Buffer.alloc(512 - remainder, 0));
    }
  }
  chunks.push(Buffer.alloc(1024, 0));
  return zlib.gzipSync(Buffer.concat(chunks));
}
