import io
import ipaddress
import json
import os
import re
import shutil
import sqlite3
import socket
import subprocess
import threading
import time
import secrets
import uuid
from typing import Any, Dict, List, Optional

import qrcode
from fastapi import Query, Body, FastAPI, File, Header, HTTPException, Request, Response, UploadFile
from fastapi.responses import JSONResponse
from pathlib import Path
import datetime
import tempfile
from contextlib import asynccontextmanager

import tarfile

def atomic_json_write(path: str, data, backup: bool = False, **json_kwargs):
    tmp = path + ".tmp"
    try:
        if backup and os.path.exists(path):
            shutil.copy2(path, path + ".bak")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2, **json_kwargs)
        os.replace(tmp, path)
    except Exception:
        try_run_cmd(["rm", "-f", tmp])
        raise

def _create_backup() -> bool:
    """Core backup logic, no auth or lock check."""
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    latest_path = BACKUP_DIR / "latest.wgadmin"
    tmp_path = BACKUP_DIR / "latest.wgadmin.tmp"

    try:
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            for fname in ["clients.json", "api_token", "api_tokens.json", "avatars.json",
                           "settings.json", "speed_limits.json", "parental_rules.json",
                           "manual_overrides.json", "traffic_stats.sqlite", "wg0.conf",
                           "activity.log", "top_user_event.json", "health_state.json"]:
                fpath = os.path.join(APP_DIR, fname)
                if os.path.exists(fpath):
                    tar.add(fpath, arcname=fname)
            for web_fname in ["index.html", "app.js", "app.css"]:
                fpath = os.path.join(WEB_DIR, web_fname)
                if os.path.exists(fpath):
                    tar.add(fpath, arcname=f"web/{web_fname}")
            # Backup metadata
            meta = {"version": BACKUP_VERSION, "created_at": int(time.time())}
            meta_buf = json.dumps(meta).encode("utf-8")
            info = tarfile.TarInfo(name=".backup_version")
            info.size = len(meta_buf)
            tar.addfile(info, io.BytesIO(meta_buf))

        with open(tmp_path, "wb") as f:
            f.write(buf.getvalue())

        prev_path = BACKUP_DIR / "previous.wgadmin"
        if latest_path.exists():
            if prev_path.exists():
                prev_path.unlink()
            shutil.copy2(latest_path, prev_path)

        os.replace(tmp_path, latest_path)
        return True
    except Exception as e:
        print(f"[backup] failed: {e}")
        try_run_cmd(["rm", "-f", tmp_path], timeout=5)
        return False

def _acquire_backup_lock() -> bool:
    try:
        fd = os.open(BACKUP_LOCK, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        with os.fdopen(fd, 'w') as f:
            f.write(str(int(time.time())))
        return True
    except OSError:
        try:
            if os.path.exists(BACKUP_LOCK):
                mtime = os.path.getmtime(BACKUP_LOCK)
                if time.time() - mtime > 600:
                    os.unlink(BACKUP_LOCK)
                    return _acquire_backup_lock()
        except Exception:
            pass
        return False

def config_changed(reason: str = ""):
    """
    Called when persistent VPN/Admin config changes.
    Creates a backup in background without blocking the API response.
    """
    print(f"[config_changed] {reason}")

    def _task():
        if not _acquire_backup_lock():
            print(f"[backup] skip (lock held): {reason}")
            return
        try:
            _create_backup()
        finally:
            try_run_cmd(["rm", "-f", BACKUP_LOCK], timeout=5)

    t = threading.Thread(target=_task, daemon=True)
    t.start()

# ── iptables / forwarding ──────────────────────────────────────

def _ensure_wg_iptables():
    """Ensure iptables rules exist for wg0 forwarding (re-applied if Docker clears them)."""
    try:
        iface = os.environ.get("WG_EXTERNAL_IFACE", "eth0")
        def _ac(cmd):
            r = subprocess.run(cmd, capture_output=True)
            return r.returncode == 0
        for args in [
            (["iptables", "-C", "FORWARD", "-i", "wg0", "-j", "ACCEPT"],
             ["iptables", "-A", "FORWARD", "-i", "wg0", "-j", "ACCEPT"]),
            (["iptables", "-C", "FORWARD", "-o", "wg0", "-m", "state",
              "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
             ["iptables", "-A", "FORWARD", "-o", "wg0", "-m", "state",
              "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"]),
            (["iptables", "-t", "nat", "-C", "POSTROUTING", "-o", iface, "-j", "MASQUERADE"],
             ["iptables", "-t", "nat", "-A", "POSTROUTING", "-o", iface, "-j", "MASQUERADE"]),
        ]:
            if not _ac(args[0]):
                _ac(args[1])
    except Exception as e:
        print(f"[iptables] ensure error: {e}")

IS_CONTAINER = os.environ.get("WG_INSIDE_CONTAINER", "0") == "1"

if IS_CONTAINER:
    APP_DIR = "/data"
    WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")
    CLIENTS_FILE = os.path.join(APP_DIR, "clients.json")
    BACKUP_DIR = Path(os.path.join(APP_DIR, "backups"))
    WG_CONTAINER = ""

else:
    APP_DIR = "/root/wg-admin-api"
    WEB_DIR = os.path.join(APP_DIR, "web")
    BACKUP_DIR = Path("/var/lib/wg-admin/backups")
    WG_CONTAINER = os.environ.get("WG_CONTAINER", "wg-vpn")
    CLIENTS_FILE = os.environ.get("CLIENTS_FILE", os.path.join(APP_DIR, "clients.json"))

TOKEN_FILE = os.path.join(APP_DIR, "api_token")
TOKEN_NEW_FILE = os.path.join(APP_DIR, "api_token.new")
TOKENS_FILE = os.path.join(APP_DIR, "api_tokens.json")
WG_INTERFACE = os.environ.get("WG_INTERFACE", "wg0")

def _get_hostname() -> str:
    """Return the human-friendly server hostname (env SERVER_HOSTNAME or socket gethostname)."""
    env_name = os.environ.get("SERVER_HOSTNAME", "").strip()
    if env_name:
        return env_name
    return socket.gethostname()

WG_HOST = os.environ.get("WG_HOST")
if not WG_HOST:
    raise RuntimeError("WG_HOST environment variable is required")
WG_PORT = os.environ.get("WG_PORT", "51820")
WG_DNS = os.environ.get("WG_DNS", "1.1.1.1")
WG_ALLOWED_IPS = os.environ.get("WG_ALLOWED_IPS", "0.0.0.0/0, ::/0")
WG_VARIANT = os.environ.get("WG_VARIANT", "wg")
ONLINE_THRESHOLD_SECONDS = int(os.environ.get("ONLINE_THRESHOLD_SECONDS", "1800"))
SETTINGS_FILE = os.path.join(APP_DIR, "settings.json")
TRAFFIC_DB_FILE = os.path.join(APP_DIR, "traffic_stats.sqlite")
TOP_USER_EVENT_FILE = os.path.join(APP_DIR, "top_user_event.json")

LEGACY_PROTECTED_NAMES = {"VadimSmart", "VadimWork", "Router"}
ACTIVITY_LOG = os.path.join(APP_DIR, "activity.log")
SPEED_LIMITS_FILE = os.path.join(APP_DIR, "speed_limits.json")
PARENTAL_RULES_FILE = os.path.join(APP_DIR, "parental_rules.json")
MANUAL_OVERRIDES_FILE = os.path.join(APP_DIR, "manual_overrides.json")
BACKUP_LOCK = os.path.join(os.path.dirname(APP_DIR), "backup.lock")
BACKUP_VERSION = 1

LIVE_TRAFFIC_PREVIOUS: Dict[str, List[Dict[str, Any]]] = {}
LIVE_TRAFFIC_LOCK = threading.Lock()
CPU_CACHE: Dict[str, Any] = {"value": None, "ts": 0}
CPU_CACHE_LOCK = threading.Lock()
CPU_LAST_SAMPLE = None
WG_DUMP_CACHE: Dict[str, Any] = {"value": None, "ts": 0}
WG_DUMP_CACHE_LOCK = threading.Lock()

PARENTAL_LOOP_INTERVAL = 60
_parental_loop_stop = threading.Event()

def _parental_loop():
    while not _parental_loop_stop.wait(PARENTAL_LOOP_INTERVAL):
        try:
            enforce_parental_limits()
        except Exception:
            pass

def _migrate_peer_roles():
    data = read_clients_data()
    clients = data.get("clients", {})
    changed = False
    for client in clients.values():
        if isinstance(client, dict) and client.get("role") is None:
            client["role"] = "admin" if client.get("protected") else "user"
            changed = True
    if changed:
        atomic_json_write(CLIENTS_FILE, data, backup=True)

@asynccontextmanager
async def lifespan(app):
    apply_timezone()
    _migrate_protected_peers()
    _migrate_peer_roles()
    _migrate_old_tokens()
    _reconcile_recovery_token()
    init_traffic_db()
    _ensure_wg_iptables()
    _sync_wg_peers()
    t = threading.Thread(target=_parental_loop, daemon=True)
    t.start()
    yield
    _parental_loop_stop.set()

app = FastAPI(title="FamilyNet API", version="0.4.0", lifespan=lifespan)

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    log_activity("error", "system", "", "", {"error": str(exc), "path": request.url.path})
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})

def _migrate_protected_peers():
    """Migrate legacy PROTECTED_PEERS set to per-client 'protected' field."""
    data = read_clients_data()
    clients = data.get("clients", {})
    changed = False
    for cid, client in clients.items():
        if isinstance(client, dict):
            if client.get("protected") is None and client.get("name") in LEGACY_PROTECTED_NAMES:
                client["protected"] = True
                changed = True
    if changed:
        atomic_json_write(CLIENTS_FILE, data, backup=True)

def get_default_interface() -> str:
    """Return external interface used for default route."""
    try:
        out = subprocess.check_output(
            ["ip", "route", "get", "8.8.8.8"],
            stderr=subprocess.DEVNULL, timeout=5
        ).decode().strip()
        match = re.search(r"dev\s+([^\s]+)", out)
        return match.group(1) if match else "eth0"
    except Exception:
        return os.environ.get("WG_EXTERNAL_IFACE", "eth0")

def _sync_wg_peers():
    data = read_clients_data()
    clients = data.get("clients", {})
    server = data.get("server", {})
    wg_conf_path = os.path.join(APP_DIR, "wg0.conf")

    wg_lines = []
    wg_lines.append("[Interface]")
    wg_lines.append(f"PrivateKey = {server.get('privateKey', '')}")
    wg_lines.append(f"Address = {server.get('address', '10.8.0.1')}/24")
    wg_lines.append(f"ListenPort = {WG_PORT}")
    if WG_VARIANT == "awg":
        wg_lines.extend(["Jc = 4", "Jmin = 10", "Jmax = 50", "S1 = 97", "S2 = 99"])
    external_iface = get_default_interface()
    wg_lines.append(f"PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o {external_iface} -j MASQUERADE")
    wg_lines.append(f"PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o {external_iface} -j MASQUERADE")
    wg_lines.append("")

    for cid, c in clients.items():
        if not c.get("enabled"):
            continue
        pub = c.get("publicKey", "")
        psk = c.get("preSharedKey", "")
        addr = c.get("address", "")
        if not pub or not psk or not addr:
            continue
        wg_lines.append("[Peer]")
        wg_lines.append(f"PublicKey = {pub}")
        wg_lines.append(f"PresharedKey = {psk}")
        wg_lines.append(f"AllowedIPs = {addr}/32")
        wg_lines.append("")

        try:
            fd, psk_tmp = tempfile.mkstemp(prefix="wg-sync-psk-")
            os.close(fd)
            with open(psk_tmp, "w") as f:
                f.write(psk)
            os.chmod(psk_tmp, 0o600)
            run_cmd(["wg", "set", WG_INTERFACE, "peer", pub, "preshared-key", psk_tmp, "allowed-ips", f"{addr}/32"], timeout=8)
        except Exception as e:
            print(f"[_sync_wg_peers] add {cid} ({c.get('name', '?')}): {e}")
        finally:
            try_run_cmd(["rm", "-f", psk_tmp], timeout=5)

    old_pubkeys = set()
    try:
        dump = try_run_cmd(["wg", "show", WG_INTERFACE, "dump"])
        if dump:
            for line in dump.strip().split("\n")[1:]:
                parts = line.split("\t")
                if len(parts) >= 1 and parts[0]:
                    old_pubkeys.add(parts[0])
    except Exception:
        pass

    active_pubkeys = set()
    for cid, c in clients.items():
        if not c.get("enabled"):
            continue
        pk = c.get("publicKey", "")
        if pk:
            active_pubkeys.add(pk)

    stale = old_pubkeys - active_pubkeys
    for pub in stale:
        try:
            run_cmd(["wg", "set", WG_INTERFACE, "peer", pub, "remove"], timeout=8)
            print(f"[_sync_wg_peers] removed stale peer {pub[:20]}...")
        except Exception as e:
            print(f"[_sync_wg_peers] remove stale {pub[:20]}...: {e}")

    try:
        with open(wg_conf_path, "w") as f:
            f.write("\n".join(wg_lines))
    except Exception as e:
        print(f"[_sync_wg_peers] save wg0.conf: {e}")

def apply_timezone() -> None:
    settings = read_settings()
    tz = settings.get("timezone", "auto")
    if tz and tz != "auto":
        os.environ["TZ"] = tz
        try:
            time.tzset()
        except AttributeError:
            pass
    elif "TZ" in os.environ:
        del os.environ["TZ"]
        try:
            time.tzset()
        except AttributeError:
            pass

def read_settings() -> Dict[str, Any]:
    defaults = {
        "traffic_warn_gb": 30,
        "timezone": "auto",
    }

    try:
        with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict):
                defaults.update(data)
    except FileNotFoundError:
        pass
    except Exception as e:
        print(f"[read_settings] error: {e}")

    return defaults

def write_settings(data: Dict[str, Any]) -> Dict[str, Any]:
    current = read_settings()
    current.update(data)

    atomic_json_write(SETTINGS_FILE, current, backup=True)
    return current

def log_activity(action: str, peer: str, client_id: str, ip: str = "", details: Optional[Dict[str, Any]] = None) -> None:
    event = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "action": action,
        "peer": peer,
        "client_id": client_id,
        "ip": ip,
        "details": details or {},
    }

    MAX_LINES = 10000
    TRIM_TO = 5000

    with open(ACTIVITY_LOG, "a+", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")
        if f.tell() > 512 * 1024:  # ~512KB heuristic, count lines only if file is sizable
            f.seek(0)
            lines = f.readlines()
            if len(lines) > MAX_LINES:
                remaining = lines[-TRIM_TO:]
                f.seek(0)
                f.truncate()
                f.writelines(remaining)

def read_speed_limits() -> Dict[str, Any]:
    try:
        with open(SPEED_LIMITS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except Exception as e:
        print(f"[read_speed_limits] error: {e}")
        return {}

def write_speed_limits(data: Dict[str, Any]) -> None:
    atomic_json_write(SPEED_LIMITS_FILE, data, backup=True)

def apply_speed_limits() -> None:
    limits = read_speed_limits()

    if IS_CONTAINER:
        try_run_cmd(["tc", "qdisc", "del", "dev", WG_INTERFACE, "root"], timeout=5)
    else:
        try_run_cmd(["docker", "exec", WG_CONTAINER, "tc", "qdisc", "del", "dev", WG_INTERFACE, "root"], timeout=5)

    active = {
        ip: item for ip, item in limits.items()
        if isinstance(item, dict) and item.get("enabled") and item.get("rate")
    }

    if not active:
        return

    _root_rate = "1000mbit"

    script = [
        f'DEV="{WG_INTERFACE}"',
        'tc qdisc add dev "$DEV" root handle 1: htb default 999',
        f'tc class add dev "$DEV" parent 1: classid 1:1 htb rate {_root_rate} ceil {_root_rate}',
        f'tc class add dev "$DEV" parent 1:1 classid 1:999 htb rate {_root_rate} ceil {_root_rate}',
    ]

    idx = 100
    for ip, item in active.items():
        idx += 1
        rate = validate_rate(item.get("rate", "256kbit"))
        class_id = f"1:{idx}"
        script.append(f'tc class add dev "$DEV" parent 1:1 classid {class_id} htb rate {rate} ceil {rate}')
        script.append(f'tc filter add dev "$DEV" protocol ip parent 1:0 prio {idx} u32 match ip dst {ip}/32 flowid {class_id}')
        script.append(f'tc filter add dev "$DEV" protocol ip parent 1:0 prio {idx} u32 match ip src {ip}/32 flowid {class_id}')

    if IS_CONTAINER:
        run_cmd(["sh", "-c", "\n".join(script)], timeout=10)
    else:
        run_cmd(["docker", "exec", WG_CONTAINER, "sh", "-c", "\n".join(script)], timeout=10)

def set_peer_speed_limit(client_id: str, enabled: bool, rate: str = "") -> Dict[str, Any]:
    if not rate:
        rate = "256kbit"
    peer = find_peer_by_client_id(client_id)
    ip = peer.get("ip")
    name = peer.get("name", client_id)

    if not ip:
        raise HTTPException(status_code=400, detail="Peer IP not found")

    limits = read_speed_limits()

    if enabled:
        limits[ip] = {
            "enabled": True,
            "rate": rate,
            "client_id": client_id,
            "name": name,
            "updated_ts": int(time.time()),
        }
    else:
        limits.pop(ip, None)

    write_speed_limits(limits)
    apply_speed_limits()

    return {
        "ok": True,
        "peer": name,
        "ip": ip,
        "client_id": client_id,
        "speed_limited": enabled,
        "rate": rate if enabled else None,
    }

def read_parental_rules() -> Dict[str, Any]:
    try:
        with open(PARENTAL_RULES_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except Exception as e:
        print(f"[read_parental_rules] error: {e}")
        return {}

def write_parental_rules(data: Dict[str, Any]) -> None:
    atomic_json_write(PARENTAL_RULES_FILE, data, backup=True)

def read_manual_overrides() -> Dict[str, Any]:
    try:
        with open(MANUAL_OVERRIDES_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except Exception as e:
        print(f"[read_manual_overrides] error: {e}")
        return {}

def write_manual_overrides(data: Dict[str, Any]) -> None:
    atomic_json_write(MANUAL_OVERRIDES_FILE, data, backup=True)

def _now_in_offset(rule: dict) -> datetime.datetime:
    offset_min = rule.get("schedule", {}).get("timezone_offset", 0)
    utc = datetime.datetime.now(datetime.timezone.utc)
    return utc - datetime.timedelta(minutes=offset_min)

def check_schedule_block(rule: dict) -> Optional[str]:
    schedule = rule.get("schedule")
    if not schedule or not schedule.get("enabled"):
        return None
    local = _now_in_offset(rule)
    wday = local.weekday()
    current_min = local.hour * 60 + local.minute

    block_days = schedule.get("days", [])
    if block_days and wday not in block_days:
        return None

    start_str = schedule.get("start", "00:00")
    end_str = schedule.get("end", "23:59")
    try:
        start_parts = start_str.split(":")
        end_parts = end_str.split(":")
        start_min = int(start_parts[0]) * 60 + int(start_parts[1])
        end_min = int(end_parts[0]) * 60 + int(end_parts[1])
    except (ValueError, IndexError):
        return None

    if end_min <= start_min:
        if current_min >= start_min or current_min < end_min:
            return "schedule_time"
    else:
        if current_min >= start_min and current_min < end_min:
            return "schedule_time"

    return None

def check_parental_limits(peer: dict, rule: dict) -> Optional[dict]:
    schedule_reason = check_schedule_block(rule)
    if schedule_reason:
        return {"action": "disable", "reason": schedule_reason}

    today = int(peer.get("today_total_bytes", 0))

    hard_limit = int(rule.get("daily_bytes", 0))
    if hard_limit and today >= hard_limit:
        return {"action": "disable", "reason": "daily"}

    threshold = int(rule.get("speed_limit_threshold", 0))
    if threshold and today >= threshold:
        return {"action": "speed_limit", "reason": "threshold", "rate": rule.get("speed_limit_rate") or "256kbit"}

    return {"action": "ok"}

def enforce_parental_limits() -> None:
    rules = read_parental_rules()
    if not rules:
        return
    overrides = read_manual_overrides()
    try:
        peer_data = mark_active_peers(parse_wg_dump(get_wg_dump()))
    except Exception:
        return
    for peer in peer_data.get("peers", []):
        cid = peer.get("client_id")
        if cid in overrides:
            continue
        rule = rules.get(cid)
        if not rule or not rule.get("enabled"):
            continue
        result = check_parental_limits(peer, rule)
        action = result["action"]
        if action == "disable":
            if peer.get("enabled"):
                try:
                    disable_peer(cid)
                except Exception:
                    pass
                log_activity(
                    action="parental_block",
                    peer=peer.get("name", cid),
                    client_id=cid,
                    ip=peer.get("ip", ""),
                    details={"reason": result["reason"]},
                )
        elif action == "speed_limit":
            if not peer.get("speed_limited"):
                try:
                    set_peer_speed_limit(cid, True, result.get("rate", ""))
                except Exception:
                    pass
                log_activity(
                    action="parental_slow",
                    peer=peer.get("name", cid),
                    client_id=cid,
                    ip=peer.get("ip", ""),
                    details={"reason": "threshold", "rate": result.get("rate")},
                )
        elif action == "ok":
            if not peer.get("enabled") and rule.get("auto_enable"):
                try:
                    enable_peer(cid)
                except Exception:
                    pass
                try:
                    set_peer_speed_limit(cid, False)
                except Exception:
                    pass
                log_activity(
                    action="parental_unblock",
                    peer=peer.get("name", cid),
                    client_id=cid,
                    ip=peer.get("ip", ""),
                    details={"reason": "limit_reset"},
                )

def read_activity(limit: int = 30) -> List[Dict[str, Any]]:
    try:
        with open(ACTIVITY_LOG, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except FileNotFoundError:
        return []

    events = []
    for line in lines[-limit:]:
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except Exception:
            continue

    events.reverse()
    return events

_TOKENS_CACHE: Optional[List[Dict[str, Any]]] = None

def _read_tokens_raw() -> List[Dict[str, Any]]:
    global _TOKENS_CACHE
    if _TOKENS_CACHE is not None:
        return _TOKENS_CACHE
    try:
        with open(TOKENS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, list):
                _TOKENS_CACHE = data
                return _TOKENS_CACHE
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    _TOKENS_CACHE = []
    return _TOKENS_CACHE

def _write_tokens_raw(tokens: List[Dict[str, Any]]):
    global _TOKENS_CACHE
    _TOKENS_CACHE = None
    atomic_json_write(TOKENS_FILE, tokens, backup=True)

def _migrate_old_tokens():
    if os.path.isfile(TOKENS_FILE):
        return
    collected = {}
    for path in (TOKEN_NEW_FILE, TOKEN_FILE):
        try:
            with open(path, "r", encoding="utf-8") as f:
                val = f.read().strip()
                if val and val not in collected:
                    collected[val] = True
        except (FileNotFoundError, OSError):
            continue
    if collected:
        tokens_list = []
        for idx, tok in enumerate(collected):
            tokens_list.append({
                "id": f"migrated-{idx}",
                "label": f"Token {idx + 1}" if idx > 0 else "Default",
                "token": tok,
                "created_at": int(time.time()),
            })
        _write_tokens_raw(tokens_list)
        print(f"[auth] migrated {len(tokens_list)} legacy token(s) to {TOKENS_FILE}")

def _reconcile_recovery_token():
    """Ensure the recovery token from the api_token file is always present in
    api_tokens.json. install.sh (re)generates api_token, but _migrate_old_tokens
    only runs once (when api_tokens.json is absent), so a regenerated recovery
    token would otherwise never become valid. Idempotent: adds a 'recovery'
    entry if the value is missing, updates it if it changed."""
    try:
        with open(TOKEN_FILE, "r", encoding="utf-8") as f:
            recovery = f.read().strip()
    except (FileNotFoundError, OSError):
        return
    if not recovery:
        return
    tokens = list(_read_tokens_raw())
    if any(t.get("token") == recovery for t in tokens):
        return
    tokens = [t for t in tokens if t.get("id") != "recovery"]
    tokens.append({
        "id": "recovery",
        "label": "Recovery",
        "token": recovery,
        "created_at": int(time.time()),
    })
    _write_tokens_raw(tokens)
    print(f"[auth] reconciled recovery token into {TOKENS_FILE}")

def get_all_tokens() -> List[Dict[str, Any]]:
    return _read_tokens_raw()

def require_auth(x_api_token: Optional[str]) -> None:
    tokens = _read_tokens_raw()
    if not tokens:
        raise HTTPException(status_code=500, detail="No API tokens configured")
    if not x_api_token:
        raise HTTPException(status_code=401, detail="Unauthorized")
    for t in tokens:
        if t.get("token") == x_api_token:
            return
    raise HTTPException(status_code=401, detail="Unauthorized")

def run_cmd(cmd: List[str], timeout: int = 8, input_text: Optional[str] = None) -> str:
    try:
        result = subprocess.run(cmd, text=True, input=input_text, capture_output=True, timeout=timeout, check=False)
    except FileNotFoundError:
        raise HTTPException(status_code=503, detail=f"Command not found: {cmd[0]}")
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail=f"Command timeout: {' '.join(cmd)}")

    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip())

    return result.stdout.strip()

def try_run_cmd(cmd: List[str], timeout: int = 8) -> Optional[str]:
    try:
        return run_cmd(cmd, timeout=timeout)
    except Exception:
        return None

def get_wg_dump() -> str:
    now = time.time()
    with WG_DUMP_CACHE_LOCK:
        if WG_DUMP_CACHE["value"] and now - WG_DUMP_CACHE["ts"] < 5:
            return WG_DUMP_CACHE["value"]

    if IS_CONTAINER:
        dump = try_run_cmd(["wg", "show", WG_INTERFACE, "dump"])
        if dump:
            with WG_DUMP_CACHE_LOCK:
                WG_DUMP_CACHE["value"] = dump
                WG_DUMP_CACHE["ts"] = now
            return dump
        raise HTTPException(status_code=500, detail=f"Cannot read WireGuard dump for {WG_INTERFACE}")

    host_dump = try_run_cmd(["wg", "show", WG_INTERFACE, "dump"])
    if host_dump:
        with WG_DUMP_CACHE_LOCK:
            WG_DUMP_CACHE["value"] = host_dump
            WG_DUMP_CACHE["ts"] = now
        return host_dump

    if shutil.which("docker"):
        container_dump = try_run_cmd(
            ["docker", "exec", WG_CONTAINER, "wg", "show", WG_INTERFACE, "dump"]
        )
        if container_dump:
            with WG_DUMP_CACHE_LOCK:
                WG_DUMP_CACHE["value"] = container_dump
                WG_DUMP_CACHE["ts"] = now
            return container_dump

    raise HTTPException(status_code=500, detail=f"Cannot read WireGuard dump for {WG_INTERFACE}")

def bytes_to_human(num: int) -> str:
    gb = num / (1024 ** 3)
    if gb < 0.1:
        return "<0.1 GB"
    return f"{gb:.1f} GB"

def backup_size_human(num: int) -> str:
    if num < 1024:
        return f"{num} B"
    if num < 1024 * 1024:
        return f"{num // 1024} KB"
    mb = num / (1024 * 1024)
    if mb < 0.1:
        return "<0.1 MB"
    if mb < 1024:
        return f"{mb:.1f} MB"
    gb = num / (1024 ** 3)
    return f"{gb:.1f} GB"

def handshake_to_text(ts: int) -> str:
    if ts <= 0:
        return "never"

    diff = max(0, int(time.time()) - ts)

    if diff < 60:
        return f"{diff} seconds ago"
    if diff < 3600:
        return f"{diff // 60} minutes ago"
    if diff < 86400:
        return f"{diff // 3600} hours ago"

    return f"{diff // 86400} days ago"

def read_clients_data() -> Dict[str, Any]:
    try:
        with open(CLIENTS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Cannot read clients data: {e}")

def seconds_to_human(seconds: int) -> str:
    seconds = max(0, int(seconds))
    hours = seconds // 3600
    minutes = (seconds % 3600) // 60

    if hours:
        return f"{hours}h {minutes}m"
    if minutes:
        return f"{minutes}m"
    return f"{seconds}s"

def today_key() -> str:
    return time.strftime("%Y-%m-%d", time.gmtime())

def week_key() -> str:
    return time.strftime("%G-W%V", time.gmtime())

def month_key() -> str:
    return time.strftime("%Y-%m", time.gmtime())

def init_traffic_db() -> None:
    with sqlite3.connect(TRAFFIC_DB_FILE, timeout=10) as db:
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("""
            CREATE TABLE IF NOT EXISTS peer_counters (
                public_key TEXT PRIMARY KEY,
                last_rx INTEGER NOT NULL DEFAULT 0,
                last_tx INTEGER NOT NULL DEFAULT 0,
                updated_ts INTEGER NOT NULL DEFAULT 0
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS traffic_totals (
                public_key TEXT NOT NULL,
                period_type TEXT NOT NULL,
                period_key TEXT NOT NULL,
                rx INTEGER NOT NULL DEFAULT 0,
                tx INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (public_key, period_type, period_key)
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS online_totals (
                public_key TEXT NOT NULL,
                day_key TEXT NOT NULL,
                seconds INTEGER NOT NULL DEFAULT 0,
                last_seen_ts INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (public_key, day_key)
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS peer_last_seen (
                public_key TEXT PRIMARY KEY,
                last_seen INTEGER NOT NULL DEFAULT 0,
                updated_ts INTEGER NOT NULL DEFAULT 0
            )
        """)

def save_peer_last_seen(public_key: str, latest_handshake: int) -> int:
    if not public_key or latest_handshake <= 0:
        return 0
    now = int(time.time())
    with sqlite3.connect(TRAFFIC_DB_FILE, timeout=10) as db:
        row = db.execute("SELECT last_seen FROM peer_last_seen WHERE public_key = ?", (public_key,)).fetchone()
        old_last_seen = int(row[0]) if row else 0
        new_last_seen = max(old_last_seen, int(latest_handshake))
        db.execute("""
            INSERT INTO peer_last_seen (public_key, last_seen, updated_ts)
            VALUES (?, ?, ?)
            ON CONFLICT(public_key)
            DO UPDATE SET
                last_seen = CASE
                    WHEN excluded.last_seen > peer_last_seen.last_seen
                    THEN excluded.last_seen
                    ELSE peer_last_seen.last_seen
                END,
                updated_ts = excluded.updated_ts
        """, (public_key, new_last_seen, now))
        return new_last_seen

def get_peer_last_seen(public_key: str) -> int:
    if not public_key:
        return 0
    with sqlite3.connect(TRAFFIC_DB_FILE, timeout=10) as db:
        row = db.execute("SELECT last_seen FROM peer_last_seen WHERE public_key = ?", (public_key,)).fetchone()
    return int(row[0]) if row else 0

def add_traffic_total(db, public_key: str, period_type: str, period_key: str, rx_delta: int, tx_delta: int) -> None:
    db.execute("""
        INSERT INTO traffic_totals (public_key, period_type, period_key, rx, tx)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(public_key, period_type, period_key)
        DO UPDATE SET rx = rx + excluded.rx, tx = tx + excluded.tx
    """, (public_key, period_type, period_key, rx_delta, tx_delta))

def read_traffic_total(db, public_key: str, period_type: str, period_key: str) -> Dict[str, int]:
    row = db.execute("""
        SELECT rx, tx FROM traffic_totals
        WHERE public_key = ? AND period_type = ? AND period_key = ?
    """, (public_key, period_type, period_key)).fetchone()
    if not row:
        return {"rx": 0, "tx": 0}
    return {"rx": int(row[0] or 0), "tx": int(row[1] or 0)}

def update_online_total(db, public_key: str, day: str, online: bool, now_ts: int) -> int:
    row = db.execute("""
        SELECT seconds, last_seen_ts FROM online_totals
        WHERE public_key = ? AND day_key = ?
    """, (public_key, day)).fetchone()

    if not row:
        db.execute("""
            INSERT INTO online_totals (public_key, day_key, seconds, last_seen_ts)
            VALUES (?, ?, 0, ?)
        """, (public_key, day, now_ts if online else 0))
        return 0

    seconds = int(row[0] or 0)
    last_seen = int(row[1] or 0)

    if online:
        if last_seen > 0:
            seconds += min(max(0, now_ts - last_seen), 120)
        db.execute("""
            UPDATE online_totals
            SET seconds = ?, last_seen_ts = ?
            WHERE public_key = ? AND day_key = ?
        """, (seconds, now_ts, public_key, day))
    else:
        db.execute("""
            UPDATE online_totals
            SET last_seen_ts = 0
            WHERE public_key = ? AND day_key = ?
        """, (public_key, day))

    return seconds

def read_rolling_traffic(db, public_key: str, days: int) -> Dict[str, int]:
    cutoff = time.strftime("%Y-%m-%d", time.localtime(time.time() - days * 86400))
    row = db.execute("""
        SELECT COALESCE(SUM(rx), 0), COALESCE(SUM(tx), 0)
        FROM traffic_totals
        WHERE public_key = ? AND period_type = 'day' AND period_key >= ?
    """, (public_key, cutoff)).fetchone()
    return {"rx": int(row[0] or 0), "tx": int(row[1] or 0)}

def cleanup_traffic_db(db) -> None:
    cutoff_day = time.strftime("%Y-%m-%d", time.localtime(time.time() - 180 * 86400))
    db.execute("DELETE FROM traffic_totals WHERE period_type = 'day' AND period_key < ?", (cutoff_day,))
    db.execute("DELETE FROM online_totals WHERE day_key < ?", (cutoff_day,))

def get_period_traffic(public_key: str, rx: int, tx: int, online: bool = False) -> Dict[str, Any]:

    today = today_key()
    week = week_key()
    month = month_key()
    now_ts = int(time.time())

    with sqlite3.connect(TRAFFIC_DB_FILE, timeout=10) as db:
        row = db.execute(
            "SELECT last_rx, last_tx FROM peer_counters WHERE public_key = ?",
            (public_key,),
        ).fetchone()

        # Если peer отключён и переданы нули, не сбрасываем последнюю точку.
        ignore_zero_offline = bool(row) and rx == 0 and tx == 0 and not online

        if row is None:
            rx_delta = 0
            tx_delta = 0
            db.execute(
                "INSERT INTO peer_counters (public_key, last_rx, last_tx, updated_ts) VALUES (?, ?, ?, ?)",
                (public_key, rx, tx, now_ts),
            )
        elif ignore_zero_offline:
            rx_delta = 0
            tx_delta = 0
        else:
            last_rx = int(row[0] or 0)
            last_tx = int(row[1] or 0)

            rx_delta = rx - last_rx if rx >= last_rx else rx
            tx_delta = tx - last_tx if tx >= last_tx else tx

            rx_delta = max(0, rx_delta)
            tx_delta = max(0, tx_delta)

            db.execute(
                "UPDATE peer_counters SET last_rx = ?, last_tx = ?, updated_ts = ? WHERE public_key = ?",
                (rx, tx, now_ts, public_key),
            )

        if rx_delta or tx_delta:
            add_traffic_total(db, public_key, "day", today, rx_delta, tx_delta)
            add_traffic_total(db, public_key, "hour", time.strftime("%Y-%m-%d-%H", time.gmtime()), rx_delta, tx_delta)
            add_traffic_total(db, public_key, "week", week, rx_delta, tx_delta)
            add_traffic_total(db, public_key, "month", month, rx_delta, tx_delta)
            add_traffic_total(db, public_key, "total", "all", rx_delta, tx_delta)

        online_today_seconds = update_online_total(db, public_key, today, online, now_ts)

        day = read_traffic_total(db, public_key, "day", today)
        week_total = read_rolling_traffic(db, public_key, 7)
        month_total = read_traffic_total(db, public_key, "month", month)
        year_total = read_rolling_traffic(db, public_key, 365)
        total = read_traffic_total(db, public_key, "total", "all")

        cleanup_traffic_db(db)

    day_rx, day_tx = day["rx"], day["tx"]
    week_rx, week_tx = week_total["rx"], week_total["tx"]
    month_rx, month_tx = month_total["rx"], month_total["tx"]
    year_rx, year_tx = year_total["rx"], year_total["tx"]
    total_rx, total_tx = total["rx"], total["tx"]

    return {
        "today_rx_bytes": day_rx,
        "today_tx_bytes": day_tx,
        "today_total_bytes": day_rx + day_tx,
        "today_rx_human": bytes_to_human(day_rx),
        "today_tx_human": bytes_to_human(day_tx),
        "today_total_human": bytes_to_human(day_rx + day_tx),

        "week_rx_bytes": week_rx,
        "week_tx_bytes": week_tx,
        "week_total_bytes": week_rx + week_tx,
        "week_rx_human": bytes_to_human(week_rx),
        "week_tx_human": bytes_to_human(week_tx),
        "week_total_human": bytes_to_human(week_rx + week_tx),

        "month_rx_bytes": month_rx,
        "month_tx_bytes": month_tx,
        "month_total_bytes": month_rx + month_tx,
        "month_rx_human": bytes_to_human(month_rx),
        "month_tx_human": bytes_to_human(month_tx),
        "month_total_human": bytes_to_human(month_rx + month_tx),

        "year_rx_bytes": year_rx,
        "year_tx_bytes": year_tx,
        "year_total_bytes": year_rx + year_tx,
        "year_rx_human": bytes_to_human(year_rx),
        "year_tx_human": bytes_to_human(year_tx),
        "year_total_human": bytes_to_human(year_rx + year_tx),

        "saved_total_rx_bytes": total_rx,
        "saved_total_tx_bytes": total_tx,
        "saved_total_bytes": total_rx + total_tx,
        "saved_total_human": bytes_to_human(total_rx + total_tx),
        "saved_total_rx_human": bytes_to_human(total_rx),
        "saved_total_tx_human": bytes_to_human(total_tx),

        "online_today_seconds": online_today_seconds,
        "online_today_human": seconds_to_human(online_today_seconds),
    }

def parse_wg_dump(dump: str) -> Dict[str, Any]:
    lines = [line for line in dump.splitlines() if line.strip()]

    data = read_clients_data()
    clients = data.get("clients", {})

    live_by_public_key: Dict[str, Dict[str, Any]] = {}

    for line in lines[1:]:
        parts = line.split("\t")
        if len(parts) < 8:
            continue

        public_key = parts[0]
        preshared_key = parts[1]
        endpoint = parts[2]
        allowed_ips = parts[3]
        latest_handshake = int(parts[4] or "0")
        transfer_rx = int(parts[5] or "0")
        transfer_tx = int(parts[6] or "0")
        persistent_keepalive = parts[7]

        online = latest_handshake > 0 and int(time.time()) - latest_handshake < ONLINE_THRESHOLD_SECONDS

        period = get_period_traffic(public_key, transfer_rx, transfer_tx, online)
        saved_last_seen = save_peer_last_seen(public_key, latest_handshake)

        live_by_public_key[public_key] = {
            "endpoint": endpoint if endpoint != "(none)" else None,
            "allowed_ips": allowed_ips,
            "latest_handshake": latest_handshake,
            "latest_handshake_text": handshake_to_text(saved_last_seen or latest_handshake),
            "saved_last_seen": saved_last_seen,
            "saved_last_seen_text": handshake_to_text(saved_last_seen),
            "online": online,
            "is_active_now": False,
            "transfer_rx_bytes": transfer_rx,
            "transfer_tx_bytes": transfer_tx,
            "transfer_total_bytes": transfer_rx + transfer_tx,
            "transfer_rx_human": bytes_to_human(transfer_rx),
            "transfer_tx_human": bytes_to_human(transfer_tx),
            "transfer_total_human": bytes_to_human(transfer_rx + transfer_tx),
            **period,
            "persistent_keepalive": persistent_keepalive,
            "has_preshared_key": preshared_key not in ("", "(none)"),
        }

    speed_limits = read_speed_limits()
    peers = []

    if isinstance(clients, dict):
        for client_id, client in clients.items():
            if not isinstance(client, dict):
                continue

            name = str(client.get("name", "")).strip()
            address = str(client.get("address", "")).strip()
            public_key = str(client.get("publicKey", "")).strip()
            enabled = bool(client.get("enabled", True))

            live = live_by_public_key.get(public_key)

            if live:
                endpoint = live["endpoint"]
                allowed_ips = live["allowed_ips"]
                latest_handshake = live["latest_handshake"]
                latest_handshake_text = live["latest_handshake_text"]
                online = live["online"]
                transfer_rx = live["transfer_rx_bytes"]
                transfer_tx = live["transfer_tx_bytes"]
                transfer_total = live["transfer_total_bytes"]
                transfer_rx_human = live["transfer_rx_human"]
                transfer_tx_human = live["transfer_tx_human"]
                transfer_total_human = live["transfer_total_human"]
                persistent_keepalive = live["persistent_keepalive"]
                has_preshared_key = live["has_preshared_key"]
            else:
                endpoint = None
                allowed_ips = f"{address}/32" if address else ""
                latest_handshake = 0
                saved_last_seen = get_peer_last_seen(public_key)
                latest_handshake_text = handshake_to_text(saved_last_seen) if saved_last_seen else "never"
                online = False
                transfer_rx = 0
                transfer_tx = 0
                transfer_total = 0
                transfer_rx_human = bytes_to_human(0)
                transfer_tx_human = bytes_to_human(0)
                transfer_total_human = bytes_to_human(0)
                persistent_keepalive = "off"
                has_preshared_key = bool(client.get("preSharedKey"))
                if public_key:
                    period = get_period_traffic(public_key, 0, 0)
                else:
                    period = {}

            peer_name = name or address or public_key[:10]
            speed_item = speed_limits.get(address, {}) if address else {}

            peers.append({
                "id": public_key[:12],
                "name": peer_name,
                "ip": address,
                "client_id": str(client_id),
                "enabled": enabled,
                "protected": bool(client.get("protected", False)),
                "role": client.get("role", "user"),
                "public_key": public_key,
                "public_key_short": public_key[:10] + "..." if public_key else "",
                "endpoint": endpoint,
                "allowed_ips": allowed_ips,
                "latest_handshake": latest_handshake,
                "latest_handshake_text": latest_handshake_text,
                "online": online,
                "transfer_rx_bytes": transfer_rx,
                "transfer_tx_bytes": transfer_tx,
                "transfer_total_bytes": transfer_total,
                "transfer_rx_human": transfer_rx_human,
                "transfer_tx_human": transfer_tx_human,
                "transfer_total_human": transfer_total_human,
                **(live if live else period),
                "persistent_keepalive": persistent_keepalive,
                "has_preshared_key": has_preshared_key,
            })

    for peer in peers:
        ip = peer.get("ip")
        item = speed_limits.get(ip, {}) if ip else {}
        peer["speed_limited"] = bool(item.get("enabled"))
        peer["speed_limit_rate"] = item.get("rate")

    peers.sort(key=lambda peer: peer.get("ip") or "")

    return {
        "interface": WG_INTERFACE,
        "peers": peers,
        "peer_count": len(peers),
        "online_peer_count": sum(1 for peer in peers if peer["online"]),
        "enabled_peer_count": sum(1 for peer in peers if peer["enabled"]),
        "disabled_peer_count": sum(1 for peer in peers if not peer["enabled"]),
        "online_threshold_seconds": ONLINE_THRESHOLD_SECONDS,
    }

def mark_active_peers(peer_data: Dict[str, Any]) -> Dict[str, Any]:
    top = get_top_user_now(peer_data.get("peers", []))

    peer_data["active_peer_count"] = int(top.get("active_peer_count", 0) or 0)
    peer_data["top_user_now"] = top

    return peer_data

def find_peer_by_client_id(client_id: str) -> Dict[str, Any]:
    data = parse_wg_dump(get_wg_dump())
    for peer in data["peers"]:
        if peer.get("client_id") == client_id:
            return peer
    raise HTTPException(status_code=404, detail=f"Peer not found: {client_id}")

def _get_client_field(client_id: str, field: str, default=None):
    item = get_client(client_id)
    return item["client"].get(field, default)

def can_disable_peer(client_id: str) -> Dict[str, Any]:
    peer = find_peer_by_client_id(client_id)

    if _get_client_field(client_id, "protected", False):
        return {
            "allowed": False,
            "peer": peer["name"],
            "ip": peer["ip"],
            "client_id": client_id,
            "reason": "Protected peer",
        }

    data = parse_wg_dump(get_wg_dump())
    online_count = data["online_peer_count"]

    if peer["online"] and online_count <= 1:
        return {
            "allowed": False,
            "peer": peer["name"],
            "ip": peer["ip"],
            "client_id": client_id,
            "reason": "Last online peer",
        }

    return {
        "allowed": True,
        "peer": peer["name"],
        "ip": peer["ip"],
        "client_id": client_id,
        "reason": None,
    }

def disable_peer(client_id: str) -> Dict[str, Any]:
    check = can_disable_peer(client_id)

    if not check["allowed"]:
        raise HTTPException(status_code=403, detail=check)

    item = get_client(client_id)
    data = item["data"]
    client = item["client"]

    public_key = client.get("publicKey")
    name = client.get("name", client_id)
    address = client.get("address")

    if not public_key:
        raise HTTPException(status_code=500, detail="Client publicKey not found")

    backup_path = f"{CLIENTS_FILE}.bak-{int(time.time())}"
    shutil.copy2(CLIENTS_FILE, backup_path)

    client["enabled"] = False

    atomic_json_write(CLIENTS_FILE, data, backup=True)

    try:
        cmd = ["wg", "set", WG_INTERFACE, "peer", public_key, "remove"]
        if not IS_CONTAINER:
            cmd = ["docker", "exec", WG_CONTAINER] + cmd
        run_cmd(cmd, timeout=8)
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail={
                "message": "Peer disabled in JSON but live wg remove failed",
                "error": str(e),
                "backup": backup_path,
            },
        )

    log_activity(
        action="disable",
        peer=name,
        client_id=client_id,
        ip=address or "",
        details={"backup": backup_path, "public_key_short": public_key[:10] + "..."},
    )

    return {
        "disabled": True,
        "peer": name,
        "ip": address,
        "client_id": client_id,
        "public_key_short": public_key[:10] + "...",
        "backup": backup_path,
    }

def enable_peer(client_id: str) -> Dict[str, Any]:
    item = get_client(client_id)
    data = item["data"]
    client = item["client"]

    name = client.get("name", client_id)
    address = client.get("address")
    public_key = client.get("publicKey")
    preshared_key = client.get("preSharedKey")

    if not address:
        raise HTTPException(status_code=500, detail="Client address not found")
    if not public_key:
        raise HTTPException(status_code=500, detail="Client publicKey not found")
    if not preshared_key:
        raise HTTPException(status_code=500, detail="Client preSharedKey not found")

    backup_path = f"{CLIENTS_FILE}.bak-{int(time.time())}"
    shutil.copy2(CLIENTS_FILE, backup_path)

    client["enabled"] = True

    atomic_json_write(CLIENTS_FILE, data, backup=True)

    try:
        if IS_CONTAINER:
            fd, psk_tmp = tempfile.mkstemp(prefix="wg-psk-")
            os.close(fd)
            with open(psk_tmp, "w") as f:
                f.write(preshared_key)
            os.chmod(psk_tmp, 0o600)
        else:
            fd, psk_tmp = tempfile.mkstemp(prefix="wg-psk-")
            os.close(fd)
            with open(psk_tmp, "w") as f:
                f.write(preshared_key)
            os.chmod(psk_tmp, 0o600)
            run_cmd(
                ["docker", "cp", psk_tmp, f"{WG_CONTAINER}:{psk_tmp}"],
                timeout=8,
            )

        cmd = ["wg", "set", WG_INTERFACE, "peer", public_key, "preshared-key", psk_tmp, "allowed-ips", f"{address}/32"]
        if not IS_CONTAINER:
            cmd = ["docker", "exec", WG_CONTAINER] + cmd
        run_cmd(cmd, timeout=8)
    finally:
        try_run_cmd(["rm", "-f", psk_tmp], timeout=5)
        if not IS_CONTAINER:
            try_run_cmd(["docker", "exec", WG_CONTAINER, "rm", "-f", psk_tmp], timeout=5)

    log_activity(
        action="enable",
        peer=name,
        client_id=client_id,
        ip=address or "",
        details={"backup": backup_path, "public_key_short": public_key[:10] + "...", "method": "live wg set peer"},
    )

    return {
        "enabled": True,
        "peer": name,
        "ip": address,
        "client_id": client_id,
        "public_key_short": public_key[:10] + "...",
        "backup": backup_path,
        "method": "live wg set peer",
    }

def get_client(client_id: str) -> Dict[str, Any]:
    data = read_clients_data()
    clients = data.get("clients", {})
    client = clients.get(client_id)

    if not client:
        raise HTTPException(status_code=404, detail=f"Client not found: {client_id}")

    return {"data": data, "client": client}

def allocate_next_client_ip(data: Dict[str, Any]) -> str:
    server_address = data.get("server", {}).get("address", "10.8.0.1")
    network = ipaddress.ip_network(f"{server_address}/24", strict=False)

    used = {str(network.network_address), str(network.broadcast_address), server_address}

    for client in data.get("clients", {}).values():
        if isinstance(client, dict) and client.get("address"):
            used.add(str(client["address"]))

    for ip in network.hosts():
        ip_str = str(ip)
        if ip_str not in used:
            return ip_str

    raise HTTPException(status_code=500, detail="No free VPN IP addresses")

def create_peer(name: str) -> Dict[str, Any]:
    name = name.strip()

    if not name:
        raise HTTPException(status_code=400, detail="Client name is required")
    if not NAME_RE.match(name):
        raise HTTPException(status_code=400, detail="Client name contains invalid characters")

    data = read_clients_data()
    clients = data.setdefault("clients", {})

    for client in clients.values():
        if isinstance(client, dict) and client.get("name") == name:
            raise HTTPException(status_code=409, detail=f"Client already exists: {name}")

    client_id = run_cmd(["cat", "/proc/sys/kernel/random/uuid"])
    address = allocate_next_client_ip(data)

    if IS_CONTAINER:
        private_key = run_cmd(["wg", "genkey"])
        public_key = run_cmd(["wg", "pubkey"], input_text=private_key + "\n")
        preshared_key = run_cmd(["wg", "genpsk"])
    else:
        private_key = run_cmd(["docker", "exec", WG_CONTAINER, "wg", "genkey"])
        public_key = run_cmd([
            "docker", "exec", "-i", WG_CONTAINER, "wg", "pubkey"
        ], input_text=private_key + "\n")
        preshared_key = run_cmd(["docker", "exec", WG_CONTAINER, "wg", "genpsk"])

    backup_path = f"{CLIENTS_FILE}.bak-{int(time.time())}"
    shutil.copy2(CLIENTS_FILE, backup_path)

    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    clients[client_id] = {
        "name": name,
        "address": address,
        "privateKey": private_key,
        "publicKey": public_key,
        "preSharedKey": preshared_key,
        "createdAt": now,
        "updatedAt": now,
        "enabled": True,
        "protected": False,
        "role": "user",
    }

    atomic_json_write(CLIENTS_FILE, data, backup=True)

    try:
        if IS_CONTAINER:
            fd, psk_tmp = tempfile.mkstemp(prefix="wg-psk-")
            os.close(fd)
            with open(psk_tmp, "w") as f:
                f.write(preshared_key)
            os.chmod(psk_tmp, 0o600)
        else:
            rand_suffix = secrets.token_hex(8)
            psk_tmp = f"/tmp/wg-psk-{rand_suffix}"
            run_cmd(
                [
                    "docker", "exec", WG_CONTAINER, "sh", "-c",
                    f"umask 077 && cat > {psk_tmp} <<'EOF'\n{preshared_key}\nEOF",
                ],
                timeout=8,
            )

        cmd = ["wg", "set", WG_INTERFACE, "peer", public_key, "preshared-key", psk_tmp, "allowed-ips", f"{address}/32"]
        if not IS_CONTAINER:
            cmd = ["docker", "exec", WG_CONTAINER] + cmd
        run_cmd(cmd, timeout=8)
    finally:
        if IS_CONTAINER:
            try_run_cmd(["rm", "-f", psk_tmp], timeout=5)
        else:
            try_run_cmd(["docker", "exec", WG_CONTAINER, "rm", "-f", psk_tmp], timeout=5)

    log_activity(
        action="create",
        peer=name,
        client_id=client_id,
        ip=address,
        details={"backup": backup_path, "public_key_short": public_key[:10] + "..."},
    )
    config_changed(f"peer-created:{name}")

    return {
        "created": True,
        "peer": name,
        "ip": address,
        "client_id": client_id,
        "public_key_short": public_key[:10] + "...",
        "backup": backup_path,
    }

def delete_peer(client_id: str) -> Dict[str, Any]:
    item = get_client(client_id)
    data = item["data"]
    client = item["client"]

    name = client.get("name", client_id)
    address = client.get("address", "")
    public_key = client.get("publicKey", "")

    if client.get("protected", False):
        log_activity(
            action="delete_blocked",
            peer=name,
            client_id=client_id,
            ip=address or "",
            details={"reason": "Protected peer"},
        )
        raise HTTPException(status_code=403, detail="Protected peer")

    backup_path = f"{CLIENTS_FILE}.bak-{int(time.time())}"
    shutil.copy2(CLIENTS_FILE, backup_path)

    clients = data.get("clients", {})
    clients.pop(client_id, None)

    atomic_json_write(CLIENTS_FILE, data, backup=True)

    if public_key:
        cmd = ["wg", "set", WG_INTERFACE, "peer", public_key, "remove"]
        if not IS_CONTAINER:
            cmd = ["docker", "exec", WG_CONTAINER] + cmd
        try_run_cmd(cmd, timeout=8)

    log_activity(
        action="delete",
        peer=name,
        client_id=client_id,
        ip=address or "",
        details={"backup": backup_path, "public_key_short": public_key[:10] + "..." if public_key else ""},
    )
    config_changed(f"peer-deleted:{name}")

    return {
        "deleted": True,
        "peer": name,
        "ip": address,
        "client_id": client_id,
        "backup": backup_path,
    }

def build_xray_links(client_id: str) -> Dict[str, str]:
    uuid_file = "/data/uuid"
    reality_pub_file = "/data/reality_public"

    uuid = "f98da36f-54b3-419b-8066-db8fa98cb517"
    if os.path.exists(uuid_file):
        uuid = open(uuid_file).read().strip()

    pbk = ""
    if os.path.exists(reality_pub_file):
        pbk = open(reality_pub_file).read().strip()

    host = WG_HOST or "147.45.169.35"
    short_id = "d64cc26c"

    links = {
        "reality": f"vless://{uuid}@{host}:443?type=tcp&security=reality&pbk={pbk}&fp=chrome&sni=www.microsoft.com&sid={short_id}&flow=xtls-rprx-vision#REALITY",
        "xhttp": f"vless://{uuid}@{host}:8445?type=xhttp&path=%2Fvless&security=none#XHTTP",
        "ws": f"vless://{uuid}@{host}:8444?type=ws&path=%2Fvless&security=none#WS",
    }
    return links

def build_client_config(client_id: str) -> str:
    if WG_VARIANT == "xray":
        links = build_xray_links(client_id)
        return links.get("ws", "")

    item = get_client(client_id)
    data = item["data"]
    client = item["client"]
    server = data.get("server", {})

    client_private_key = client.get("privateKey")
    client_address = client.get("address")
    client_preshared_key = client.get("preSharedKey")
    server_public_key = server.get("publicKey")

    if not client_private_key:
        raise HTTPException(status_code=500, detail="Client privateKey not found")
    if not client_address:
        raise HTTPException(status_code=500, detail="Client address not found")
    if not server_public_key:
        raise HTTPException(status_code=500, detail="Server publicKey not found")

    lines = [
        "[Interface]",
        f"PrivateKey = {client_private_key}",
        f"Address = {client_address}/32",
        f"DNS = {WG_DNS}",
    ]

    if WG_VARIANT == "awg":
        lines.extend(["Jc = 4", "Jmin = 10", "Jmax = 50", "S1 = 97", "S2 = 99"])

    lines.append("")
    lines.append("[Peer]")
    lines.append(f"PublicKey = {server_public_key}")

    if client_preshared_key:
        lines.append(f"PresharedKey = {client_preshared_key}")

    lines.extend([
        f"AllowedIPs = {WG_ALLOWED_IPS}",
        f"Endpoint = {WG_HOST}:{WG_PORT}",
        "PersistentKeepalive = 25",
        "",
    ])

    return "\n".join(lines)

def get_loadavg() -> Dict[str, str]:
    with open("/proc/loadavg", "r", encoding="utf-8") as f:
        one, five, fifteen, *_ = f.read().split()
    return {"1m": one, "5m": five, "15m": fifteen}

def get_cpu_usage() -> Dict[str, Any]:
    global CPU_LAST_SAMPLE
    now = time.time()

    with CPU_CACHE_LOCK:
        if CPU_CACHE["value"] and now - CPU_CACHE["ts"] < 30:
            return CPU_CACHE["value"]

    def read_cpu():
        with open("/proc/stat", "r", encoding="utf-8") as f:
            fields = list(map(int, f.readline().split()[1:]))
        idle = fields[3] + fields[4]
        total = sum(fields)
        return idle, total

    with CPU_CACHE_LOCK:
        if CPU_LAST_SAMPLE is None:
            CPU_LAST_SAMPLE = (*read_cpu(), now)
            CPU_CACHE["value"] = {"percent": 0.0}
            CPU_CACHE["ts"] = now
            return CPU_CACHE["value"]

        idle1, total1, ts1 = CPU_LAST_SAMPLE
        idle2, total2 = read_cpu()
    elapsed = now - ts1

    if elapsed > 60:
        with CPU_CACHE_LOCK:
            CPU_LAST_SAMPLE = (idle2, total2, now)
            CPU_CACHE["value"] = {"percent": 0.0}
            CPU_CACHE["ts"] = now
            return CPU_CACHE["value"]

    total_delta = total2 - total1
    idle_delta = idle2 - idle1

    if total_delta > 0:
        percent = 100.0 * (1.0 - idle_delta / total_delta)
        percent = max(0.0, min(100.0, percent))
    else:
        percent = 0.0

    result = {"percent": round(percent, 1)}
    with CPU_CACHE_LOCK:
        CPU_CACHE["value"] = result
        CPU_CACHE["ts"] = now
        CPU_LAST_SAMPLE = (idle2, total2, now)
    return result

def get_memory() -> Dict[str, Any]:
    data = {}
    with open("/proc/meminfo", "r", encoding="utf-8") as f:
        for line in f:
            key, value = line.split(":", 1)
            data[key] = int(value.strip().split()[0]) * 1024

    total = data.get("MemTotal", 0)
    available = data.get("MemAvailable", 0)
    used = max(0, total - available)

    return {
        "total_bytes": total,
        "used_bytes": used,
        "available_bytes": available,
        "total_human": bytes_to_human(total),
        "used_human": bytes_to_human(used),
        "available_human": bytes_to_human(available),
        "used_percent": round((used / total) * 100, 2) if total else 0,
    }

def get_disk_root() -> Dict[str, Any]:
    usage = shutil.disk_usage("/")
    return {
        "total_bytes": usage.total,
        "used_bytes": usage.used,
        "free_bytes": usage.free,
        "total_human": bytes_to_human(usage.total),
        "used_human": bytes_to_human(usage.used),
        "free_human": bytes_to_human(usage.free),
        "used_percent": round((usage.used / usage.total) * 100, 2) if usage.total else 0,
    }

def get_uptime() -> Dict[str, Any]:
    with open("/proc/uptime", "r", encoding="utf-8") as f:
        seconds = int(float(f.read().split()[0]))

    return {
        "seconds": seconds,
        "human": f"{seconds // 86400}d {(seconds % 86400) // 3600}h {(seconds % 3600) // 60}m",
    }

# ── Auth middleware ──────────────────────────────────────────
PUBLIC_PATHS = {"/", "/app.js", "/app.css", "/sw.js", "/manifest.json", "/health"}

@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    if request.url.path in PUBLIC_PATHS:
        return await call_next(request)

    client_ip = request.client.host
    if client_ip in ("127.0.0.1", "::1", "10.8.0.1"):
        return await call_next(request)

    try:
        data = read_clients_data()
        for c, client in data.get("clients", {}).items():
            if client.get("role") == "admin" and client.get("address") == client_ip:
                return await call_next(request)
    except Exception:
        pass

    x_api_token = request.headers.get("x-api-token")
    if x_api_token:
        try:
            require_auth(x_api_token)
            return await call_next(request)
        except HTTPException:
            pass

    token = request.query_params.get("token")
    if token:
        try:
            require_auth(token)
            return await call_next(request)
        except HTTPException:
            pass

    return JSONResponse(status_code=401, content={"detail": "Unauthorized"})

@app.get("/app.css")
def web_css():
    with open(os.path.join(WEB_DIR, "app.css"), "r", encoding="utf-8") as f:
        return Response(content=f.read(), media_type="text/css; charset=utf-8",
                        headers={"Cache-Control": "no-cache, no-store, must-revalidate"})

@app.get("/app.js")
def web_js():
    with open(os.path.join(WEB_DIR, "app.js"), "r", encoding="utf-8") as f:
        return Response(content=f.read(), media_type="application/javascript; charset=utf-8",
                        headers={"Cache-Control": "no-cache, no-store, must-revalidate"})

@app.post("/settings")
def update_settings(
    payload: Dict[str, Any] = Body(...),
    x_api_token: Optional[str] = Header(default=None),
) -> Dict[str, Any]:


    update = {}

    if "traffic_warn_gb" in payload:
        v = int(payload["traffic_warn_gb"])
        if v > 0:
            update["traffic_warn_gb"] = v

    if "timezone" in payload:
        tz = payload["timezone"].strip()
        if tz:
            update["timezone"] = tz

    if not update:
        return read_settings()

    result = write_settings(update)
    apply_timezone()
    config_changed("settings-updated")
    return result

@app.get("/health")
def health():
    return {"status": "ok"}

HEALTH_FILE = os.path.join(APP_DIR, "health_state.json")

def _read_health() -> Dict[str, Any]:
    try:
        with open(HEALTH_FILE, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"last_issue_ts": None, "healthy_since": None}

def _write_health(data: Dict[str, Any]) -> None:
    atomic_json_write(HEALTH_FILE, data)

def _days_since(ts: Optional[int]) -> int:
    if ts is None:
        return 0
    return max(0, int((time.time() - ts) / 86400))

@app.get("/diagnostics")
def diagnostics(x_api_token: Optional[str] = Header(default=None)) -> Dict[str, Any]:


    # WG check
    wg_dump = try_run_cmd(["wg", "show", WG_INTERFACE, "dump"])
    wg_ok = wg_dump is not None and len(wg_dump.strip()) > 0

    # Internet check (ip route or ping)
    internet_ok = try_run_cmd(["ip", "route", "get", "8.8.8.8"]) is not None
    if not internet_ok:
        internet_ok = try_run_cmd(["ping", "-c", "1", "-W", "3", "8.8.8.8"]) is not None

    # Backup check
    info = backup_file_info("latest.wgadmin")
    backup_ok = info.get("exists") and (time.time() - info.get("mtime", 0)) < 3 * 86400

    # Peers check: any online in last 30 min
    peers_ok = False
    if wg_ok:
        parsed = parse_wg_dump(wg_dump)
        for p in parsed.get("peers", []):
            now_ts = time.time()
            lh = int(p.get("latest_handshake", 0))
            if lh > 0 and p.get("online") and (now_ts - lh) < 1800:
                peers_ok = True
                break

    # Healthy days counter
    health = _read_health()
    now = int(time.time())
    has_issue = not (wg_ok and internet_ok and backup_ok and peers_ok)
    if has_issue:
        health["last_issue_ts"] = now
        if health.get("healthy_since") is not None:
            health["healthy_since"] = None
    else:
        if health.get("healthy_since") is None:
            health["healthy_since"] = now
    _write_health(health)

    days_ok = _days_since(health.get("healthy_since")) if health.get("healthy_since") else 0

    # System metrics
    cpu_pct = 0.0
    try:
        with open("/proc/stat") as f:
            parts = f.readline().strip().split()
        if parts and parts[0] == 'cpu' and len(parts) >= 5:
            user, nice, system, idle = int(parts[1]), int(parts[2]), int(parts[3]), int(parts[4])
            iowait = int(parts[5]) if len(parts) > 5 else 0
            irq = int(parts[6]) if len(parts) > 6 else 0
            softirq = int(parts[7]) if len(parts) > 7 else 0
            steal = int(parts[8]) if len(parts) > 8 else 0
            total = user + nice + system + idle + iowait + irq + softirq + steal
            if total > idle:
                cpu_pct = round((total - idle) / total * 100, 1)
    except Exception: pass

    mem_pct = 0.0
    mem_total = 0; mem_avail = 0
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    mem_total = int(line.split()[1])
                elif line.startswith("MemAvailable:"):
                    mem_avail = int(line.split()[1])
        if mem_total:
            mem_pct = round((1 - mem_avail / mem_total) * 100, 1)
    except Exception: pass

    disk_pct = 0.0
    disk_total = 0; disk_used = 0
    try:
        out = subprocess.run(["df", "-B1", "/"], capture_output=True, text=True, timeout=5).stdout
        lines = out.strip().splitlines()
        if len(lines) >= 2:
            parts = lines[1].split()
            if len(parts) >= 3:
                disk_total = int(parts[1])
                disk_used = int(parts[2])
                if disk_total:
                    disk_pct = round(disk_used / disk_total * 100, 1)
    except Exception: pass

    return {
        "wg": wg_ok,
        "internet": internet_ok,
        "backup": backup_ok,
        "peers": peers_ok,
        "all_ok": wg_ok and internet_ok and backup_ok and peers_ok,
        "days_ok": days_ok,
        "checks": {
            "wg": "ok" if wg_ok else "fail",
            "internet": "ok" if internet_ok else "fail",
            "backup": "ok" if backup_ok else "fail",
            "peers": "ok" if peers_ok else "fail",
        },
        "cpu_pct": cpu_pct,
        "mem_pct": mem_pct,
        "mem_total": mem_total,
        "mem_avail": mem_avail,
        "disk_pct": disk_pct,
        "disk_total": disk_total,
        "disk_used": disk_used,
    }

@app.get("/tokens")
def list_tokens(x_api_token: Optional[str] = Header(default=None)) -> List[Dict[str, Any]]:

    result = []
    for t in get_all_tokens():
        tok = t.get("token", "")
        result.append({
            "id": t.get("id"),
            "label": t.get("label", ""),
            "prefix": tok[:8] + "..." + tok[-4:] if len(tok) > 12 else tok,
            "created_at": t.get("created_at"),
        })
    return result

@app.post("/tokens")
def create_token(
    payload: Dict[str, Any] = Body(default={}),
    x_api_token: Optional[str] = Header(default=None),
) -> Dict[str, Any]:

    label = str(payload.get("label", "")).strip() or "Unnamed"
    new_id = str(uuid.uuid4())[:8]
    # Accept user-provided password or generate one
    new_token = str(payload.get("password", "")).strip()
    if not new_token:
        new_token = secrets.token_hex(32)
    tokens = _read_tokens_raw()
    tokens.append({
        "id": new_id,
        "label": label,
        "token": new_token,
        "created_at": int(time.time()),
    })
    _write_tokens_raw(tokens)
    log_activity(action="token_created", peer="", client_id="", ip="", details={"label": label, "id": new_id})
    config_changed("token-created")
    return {"id": new_id, "label": label, "token": new_token}

@app.delete("/tokens/{token_id}")
def revoke_token(
    token_id: str,
    x_api_token: Optional[str] = Header(default=None),
) -> Dict[str, Any]:

    tokens = _read_tokens_raw()
    for t in tokens:
        if t.get("token") == x_api_token and t.get("id") == token_id:
            raise HTTPException(status_code=400, detail="Cannot revoke the current session token")
    new_tokens = [t for t in tokens if t.get("id") != token_id]
    if len(new_tokens) == len(tokens):
        raise HTTPException(status_code=404, detail="Token not found")
    _write_tokens_raw(new_tokens)
    log_activity(action="token_revoked", peer="", client_id="", ip="", details={"id": token_id})
    config_changed("token-revoked")
    return {"ok": True, "revoked": token_id}

@app.post("/peer/create")
def peer_create(
    payload: Dict[str, Any] = Body(...),
    x_api_token: Optional[str] = Header(default=None),
) -> Dict[str, Any]:

    return create_peer(str(payload.get("name", "")))

@app.get("/peers")
def peers(x_api_token: Optional[str] = Header(default=None)) -> Dict[str, Any]:

    return mark_active_peers(parse_wg_dump(get_wg_dump()))

@app.post("/peer/{client_id}/disable")
def peer_disable(client_id: str, x_api_token: Optional[str] = Header(default=None)) -> Dict[str, Any]:

    result = disable_peer(client_id)
    overrides = read_manual_overrides()
    overrides[client_id] = {"ts": int(time.time())}
    write_manual_overrides(overrides)
    return result

@app.post("/peer/{client_id}/enable")
def peer_enable(client_id: str, x_api_token: Optional[str] = Header(default=None)) -> Dict[str, Any]:

    overrides = read_manual_overrides()
    overrides.pop(client_id, None)
    write_manual_overrides(overrides)
    return enable_peer(client_id)

@app.post("/peer/{client_id}/name")
def peer_rename(client_id: str, payload: Dict[str, Any] = Body(default={}), x_api_token: Optional[str] = Header(default=None)) -> Dict[str, Any]:

    new_name = str(payload.get("name", "")).strip()
    if not new_name:
        raise HTTPException(status_code=400, detail="Name is required")
    if not NAME_RE.match(new_name):
        raise HTTPException(status_code=400, detail="Name contains invalid characters")
    item = get_client(client_id)
    data = item["data"]
    client = item["client"]
    old_name = client.get("name", client_id)
    client["name"] = new_name
    atomic_json_write(CLIENTS_FILE, data, backup=True)
    log_activity(action="rename", peer=old_name, client_id=client_id, ip=client.get("address", ""), details={"old_name": old_name, "new_name": new_name})
    return {"ok": True, "client_id": client_id, "name": new_name}

NAME_RE = re.compile(r"^[\w\s\-\.а-яА-ЯёЁ]+$")
RATE_RE = re.compile(r"^\d+(kbit|mbit|gbit|kbps|mbps|gbps)$")

def validate_rate(raw: Any) -> str:
    s = str(raw).strip().lower() if raw else "256kbit"
    if not RATE_RE.match(s):
        raise HTTPException(status_code=400, detail=f"Invalid rate: {raw!r}")
    return s

@app.post("/peer/{client_id}/speed-limit")
def peer_speed_limit(
    client_id: str,
    payload: Dict[str, Any] = Body(default={}),
    x_api_token: Optional[str] = Header(default=None),
) -> Dict[str, Any]:

    rate = validate_rate(payload.get("rate"))
    overrides = read_manual_overrides()
    overrides[client_id] = {"ts": int(time.time())}
    write_manual_overrides(overrides)
    peer = find_peer_by_client_id(client_id)
    log_activity("parental_slow", peer.get("name", client_id), client_id, peer.get("ip", ""), {"reason": "manual"})
    return set_peer_speed_limit(client_id, True, rate)

@app.post("/peer/{client_id}/speed-normal")
def peer_speed_normal(client_id: str, x_api_token: Optional[str] = Header(default=None)) -> Dict[str, Any]:

    overrides = read_manual_overrides()
    overrides.pop(client_id, None)
    write_manual_overrides(overrides)
    peer = find_peer_by_client_id(client_id)
    log_activity("speed_normal", peer.get("name", client_id), client_id, peer.get("ip", ""))
    return set_peer_speed_limit(client_id, False)

@app.get("/parental/rules")
def parental_get_rules(x_api_token: Optional[str] = Header(default=None)) -> Dict[str, Any]:

    rules = read_parental_rules()
    return {"rules": rules}

@app.put("/parental/rules/{client_id}")
def parental_set_rule(client_id: str, payload: Dict[str, Any] = Body(default={}), x_api_token: Optional[str] = Header(default=None)) -> Dict[str, Any]:

    rules = read_parental_rules()
    enabled = bool(payload.get("enabled", False))
    if enabled:
        schedule = payload.get("schedule")
        if schedule and isinstance(schedule, dict):
            schedule.setdefault("enabled", False)
        rules[client_id] = {
            "enabled": enabled,
            "daily_bytes": int(payload.get("daily_bytes", 0)),
            "speed_limit_threshold": int(payload.get("speed_limit_threshold", 0)),
            "speed_limit_rate": str(payload.get("speed_limit_rate")) if "speed_limit_rate" in payload else "256kbit",
            "auto_enable": bool(payload.get("auto_enable", True)),
            "schedule": schedule,
            "updated_ts": int(time.time()),
        }
    else:
        rules.pop(client_id, None)
    write_parental_rules(rules)
    overrides = read_manual_overrides()
    overrides.pop(client_id, None)
    write_manual_overrides(overrides)
    enforce_parental_limits()
    return {"ok": True, "client_id": client_id, "enabled": enabled}

@app.delete("/peer/{client_id}")
def peer_delete(client_id: str, x_api_token: Optional[str] = Header(default=None)) -> Dict[str, Any]:

    return delete_peer(client_id)

@app.post("/peer/{client_id}/role")
def peer_set_role(client_id: str, payload: Dict[str, Any] = Body(default={}), x_api_token: Optional[str] = Header(default=None)) -> Dict[str, Any]:

    role = str(payload.get("role", "")).strip()
    if role not in ("admin", "user"):
        raise HTTPException(status_code=400, detail="Role must be 'admin' or 'user'")
    item = get_client(client_id)
    data = item["data"]
    client = item["client"]
    client["role"] = role
    atomic_json_write(CLIENTS_FILE, data, backup=True)
    log_activity(action="role_change", peer=client.get("name", client_id), client_id=client_id,
                 ip=client.get("address", ""), details={"role": role})
    config_changed(f"peer-role:{client_id}:{role}")
    return {"ok": True, "client_id": client_id, "role": role}

@app.post("/peer/{client_id}/protect")
def peer_protect(client_id: str, payload: Dict[str, Any] = Body(default={}), x_api_token: Optional[str] = Header(default=None)) -> Dict[str, Any]:

    protected = bool(payload.get("protected", True))
    item = get_client(client_id)
    data = item["data"]
    client = item["client"]
    name = client.get("name", client_id)
    client["protected"] = protected
    atomic_json_write(CLIENTS_FILE, data, backup=True)
    log_activity(
        action="protect" if protected else "unprotect",
        peer=name,
        client_id=client_id,
        ip=client.get("address", ""),
        details={"protected": protected},
    )
    return {"ok": True, "client_id": client_id, "protected": protected}

@app.get("/peer/{client_id}/config")
def peer_config(client_id: str, x_api_token: Optional[str] = Header(default=None), token: Optional[str] = Query(default=None)):

    config = build_client_config(client_id)
    item = get_client(client_id)
    fname = f"{client_id}.conf"
    if WG_VARIANT == "xray":
        fname = f"{client_id}.txt"
    return Response(
        content=config,
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )

@app.get("/peer/{client_id}/qr")
def peer_qr(client_id: str, proto: Optional[str] = Query(default=None), x_api_token: Optional[str] = Header(default=None), token: Optional[str] = Query(default=None)):

    if WG_VARIANT == "xray" and proto:
        links = build_xray_links(client_id)
        config = links.get(proto, "")
    else:
        config = build_client_config(client_id)
    if not config:
        raise HTTPException(400, "No config for this protocol")
    img = qrcode.make(config)
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    return Response(content=buffer.getvalue(), media_type="image/png")

@app.get("/xray/links")
def xray_links(x_api_token: Optional[str] = Header(default=None), token: Optional[str] = Query(default=None)):
    links = build_xray_links("")
    return links

@app.get("/peer/{client_id}/traffic/days")
def peer_traffic_days(client_id: str, x_api_token: Optional[str] = Header(default=None)) -> Dict[str, Any]:

    peer = find_peer_by_client_id(client_id)
    if not peer:
        raise HTTPException(404, "Peer not found")
    public_key = peer.get("public_key") or peer.get("pubkey") or ""
    if not public_key:
        return {"days": []}
    cutoff = time.strftime("%Y-%m-%d", time.localtime(time.time() - 60 * 86400))
    with sqlite3.connect(TRAFFIC_DB_FILE, timeout=10) as db:
        rows = db.execute("""
            SELECT period_key, rx, tx FROM traffic_totals
            WHERE public_key = ? AND period_type = 'day' AND period_key >= ?
            ORDER BY period_key ASC
        """, (public_key, cutoff)).fetchall()
    return {"days": [{"date": r[0], "rx": int(r[1]), "tx": int(r[2])} for r in rows]}

@app.get("/peer/{client_id}/traffic/hours")
def peer_traffic_hours(client_id: str, date: Optional[str] = Query(default=None), x_api_token: Optional[str] = Header(default=None)) -> Dict[str, Any]:

    peer = find_peer_by_client_id(client_id)
    if not peer:
        raise HTTPException(404, "Peer not found")
    public_key = peer.get("public_key") or peer.get("pubkey") or ""
    if not public_key:
        return {"hours": []}
    if not date:
        date = today_key()
    with sqlite3.connect(TRAFFIC_DB_FILE, timeout=10) as db:
        rows = db.execute("""
            SELECT period_key, rx, tx FROM traffic_totals
            WHERE public_key = ? AND period_type = 'hour' AND period_key LIKE ?
            ORDER BY period_key ASC
        """, (public_key, date + "%")).fetchall()
        if rows:
            return {"hours": [{"h": r[0].split("-")[-1], "rx": int(r[1]), "tx": int(r[2])} for r in rows]}
        if date == today_key():
            day = read_traffic_total(db, public_key, "day", date)
            total_rx, total_tx = day["rx"], day["tx"]
            current_hour = int(time.strftime("%H", time.gmtime()))
            hours = []
            if total_rx or total_tx:
                cnt = current_hour + 1
                for h in range(cnt):
                    hours.append({"h": f"{h:02d}", "rx": total_rx // cnt, "tx": total_tx // cnt})
            return {"hours": hours}
        return {"hours": []}

@app.get("/traffic/global/hours")
def global_traffic_hours(x_api_token: Optional[str] = Header(default=None)) -> Dict[str, Any]:

    today = today_key()
    with sqlite3.connect(TRAFFIC_DB_FILE, timeout=10) as db:
        rows = db.execute("""
            SELECT period_key, SUM(rx), SUM(tx) FROM traffic_totals
            WHERE period_type = 'hour' AND period_key LIKE ?
            GROUP BY period_key ORDER BY period_key ASC
        """, (today + "%",)).fetchall()
        if rows:
            return {"hours": [{"h": r[0].split("-")[-1], "rx": int(r[1]), "tx": int(r[2])} for r in rows]}
        return {"hours": []}

@app.get("/traffic/global/days")
def global_traffic_days(x_api_token: Optional[str] = Header(default=None)) -> Dict[str, Any]:

    cutoff = time.strftime("%Y-%m-%d", time.localtime(time.time() - 365 * 86400))
    with sqlite3.connect(TRAFFIC_DB_FILE, timeout=10) as db:
        rows = db.execute("""
            SELECT period_key, SUM(rx), SUM(tx)
            FROM traffic_totals
            WHERE period_type = 'day' AND period_key >= ?
            GROUP BY period_key ORDER BY period_key ASC
        """, (cutoff,)).fetchall()
    return {"days": [{"date": r[0], "rx": int(r[1]), "tx": int(r[2])} for r in rows]}

@app.get("/activity")
def activity(x_api_token: Optional[str] = Header(default=None), limit: int = 30) -> Dict[str, Any]:

    limit = max(1, min(limit, 100))
    return {
        "events": read_activity(limit),
        "limit": limit,
    }

def load_top_user_event() -> Dict[str, Any]:
    try:
        with open(TOP_USER_EVENT_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except Exception:
        return {}

def save_top_user_event(data: Dict[str, Any]) -> None:
    try:
        atomic_json_write(TOP_USER_EVENT_FILE, data)
    except Exception:
        pass

def get_top_user_now(peers: List[Dict[str, Any]]) -> Dict[str, Any]:
    now_ts = time.time()

    for peer in peers:
        peer["is_active_now"] = False

    best = None
    active_peer_count = 0
    active_peer_keys = []
    active_peer_threshold_mbps = 0.01

    current_keys = set()

    TOP_WINDOW = 600  # 10 minutes

    for peer in peers:
        public_key = peer.get("public_key")
        if not public_key:
            continue

        current_keys.add(public_key)

        rx = int(peer.get("transfer_rx_bytes") or 0)
        tx = int(peer.get("transfer_tx_bytes") or 0)

        with LIVE_TRAFFIC_LOCK:
            samples = LIVE_TRAFFIC_PREVIOUS.get(public_key)
            if samples is None:
                samples = []
                LIVE_TRAFFIC_PREVIOUS[public_key] = samples
            samples.append({"ts": now_ts, "rx": rx, "tx": tx})
            cutoff = now_ts - TOP_WINDOW
            LIVE_TRAFFIC_PREVIOUS[public_key] = [s for s in samples if s["ts"] >= cutoff]

        if len(LIVE_TRAFFIC_PREVIOUS[public_key]) < 2:
            peer["is_active_now"] = peer.get("online") and int(peer.get("latest_handshake", 0)) > 0 and (now_ts - int(peer.get("latest_handshake", 0))) < 120
            continue

        oldest = LIVE_TRAFFIC_PREVIOUS[public_key][0]
        dt = max(5.0, now_ts - oldest["ts"])
        rx_delta = rx - oldest["rx"]
        tx_delta = tx - oldest["tx"]

        if rx_delta < 0 or tx_delta < 0:
            continue

        total_delta = rx_delta + tx_delta
        total_mbps = (total_delta * 8) / dt / 1_000_000
        rx_mbps = (rx_delta * 8) / dt / 1_000_000
        tx_mbps = (tx_delta * 8) / dt / 1_000_000

        if peer.get("online") and total_mbps >= active_peer_threshold_mbps:
            active_peer_keys.append(public_key)
            peer["is_active_now"] = True

        if not peer.get("is_active_now"):
            peer["is_active_now"] = peer.get("online") and int(peer.get("latest_handshake", 0)) > 0 and (now_ts - int(peer.get("latest_handshake", 0))) < 120

    active_peer_count = sum(1 for p in peers if p.get("is_active_now"))

    with LIVE_TRAFFIC_LOCK:
        for key in list(LIVE_TRAFFIC_PREVIOUS.keys()):
            if key not in current_keys:
                LIVE_TRAFFIC_PREVIOUS.pop(key, None)

    for peer in peers:
        if not peer.get("online"):
            continue
        bytes_today = int(peer.get("today_total_bytes") or 0)
        if not best or bytes_today > best["today_total_bytes"]:
            best = {
                "name": peer.get("name"),
                "ip": peer.get("ip"),
                "rx_mbps": 0,
                "tx_mbps": 0,
                "total_mbps": 0,
                "today_total_bytes": bytes_today,
                "today_total_human": peer.get("today_total_human", "0.00 B"),
            }

    if not best:
        return {
            "active": False,
            "threshold_mbps": 1.0,
            "active_peer_count": active_peer_count,
            "active_peer_keys": active_peer_keys,
            "active_peer_threshold_mbps": active_peer_threshold_mbps,
            "last_event": load_top_user_event(),
        }

    best["active"] = best["today_total_bytes"] > 0
    best["threshold_bytes"] = 1024
    best["active_peer_count"] = active_peer_count
    best["active_peer_keys"] = active_peer_keys
    best["active_peer_threshold_mbps"] = active_peer_threshold_mbps

    if best["active"]:
        best["ts"] = int(time.time())
        save_top_user_event(best)

    best["last_event"] = load_top_user_event()

    return best

@app.get("/dashboard")
def dashboard(x_api_token: Optional[str] = Header(default=None)) -> Dict[str, Any]:


    peer_data = parse_wg_dump(get_wg_dump())
    total_rx = sum(peer["transfer_rx_bytes"] for peer in peer_data["peers"])
    total_tx = sum(peer["transfer_tx_bytes"] for peer in peer_data["peers"])

    vpn_today = sum(peer.get("today_total_bytes", 0) for peer in peer_data["peers"])
    vpn_week = sum(peer.get("week_total_bytes", 0) for peer in peer_data["peers"])
    vpn_month = sum(peer.get("month_total_bytes", 0) for peer in peer_data["peers"])
    vpn_year = sum(peer.get("year_total_bytes", 0) for peer in peer_data["peers"])
    vpn_saved_total = sum(peer.get("saved_total_bytes", peer.get("transfer_total_bytes", 0)) for peer in peer_data["peers"])

    top_user_now = get_top_user_now(peer_data["peers"])

    online_peers = [
        {
            "name": peer["name"],
            "ip": peer["ip"],
            "latest_handshake_text": peer["latest_handshake_text"],
            "transfer_total_human": peer["transfer_total_human"],
            "protected": peer["protected"],
        }
        for peer in peer_data["peers"]
        if peer["online"]
    ]

    return {
        "variant": WG_VARIANT,
        "hostname": _get_hostname(),
        "uptime": get_uptime(),
        "cpu": get_cpu_usage(),
        "loadavg": get_loadavg(),
        "memory": get_memory(),
        "disk_root": get_disk_root(),
        "wireguard": {
            "interface": peer_data["interface"],
            "peer_count": peer_data["peer_count"],
            "online_peer_count": peer_data["online_peer_count"],
            "online_threshold_seconds": peer_data["online_threshold_seconds"],
            "total_rx_bytes": total_rx,
            "total_tx_bytes": total_tx,
            "total_traffic_bytes": total_rx + total_tx,
            "total_rx_human": bytes_to_human(total_rx),
            "total_tx_human": bytes_to_human(total_tx),
            "total_traffic_human": bytes_to_human(total_rx + total_tx),

            "vpn_today_bytes": vpn_today,
            "vpn_week_bytes": vpn_week,
            "vpn_month_bytes": vpn_month,
            "vpn_year_bytes": vpn_year,
            "vpn_saved_total_bytes": vpn_saved_total,
            "traffic_warn_bytes": read_settings().get("traffic_warn_gb", 30) * 1024 * 1024 * 1024,
            "timezone": read_settings().get("timezone", "auto"),

            "vpn_today_human": bytes_to_human(vpn_today),
            "vpn_week_human": bytes_to_human(vpn_week),
            "vpn_month_human": bytes_to_human(vpn_month),
            "vpn_year_human": bytes_to_human(vpn_year),
            "vpn_saved_total_human": bytes_to_human(vpn_saved_total),

            "top_user_now": top_user_now,
            "online_peers": online_peers,
        },
    }

def backup_file_info(name: str) -> Dict[str, Any]:
    path = BACKUP_DIR / name
    if not path.exists():
        return {"exists": False, "name": name}
    st = path.stat()
    return {
        "exists": True,
        "name": name,
        "size": st.st_size,
        "size_human": backup_size_human(st.st_size),
        "mtime": int(st.st_mtime),
        "path": str(path),
    }

@app.get("/backup/status")
def backup_status(x_api_token: Optional[str] = Header(default=None)) -> Response:

    data = {
        "latest": backup_file_info("latest.wgadmin"),
        "previous": backup_file_info("previous.wgadmin"),
    }
    return Response(
        content=json.dumps(data),
        media_type="application/json",
        headers={"Cache-Control": "no-store, no-cache, must-revalidate"},
    )

@app.post("/backup/create")
def backup_create(x_api_token: Optional[str] = Header(default=None)) -> Dict[str, Any]:

    if not _acquire_backup_lock():
        return {"created": False, "message": "Backup already in progress"}

    ok = _create_backup()

    try_run_cmd(["rm", "-f", BACKUP_LOCK], timeout=5)

    return {
        "created": ok,
        "latest": backup_file_info("latest.wgadmin"),
        "previous": backup_file_info("previous.wgadmin"),
    }

@app.get("/backup/download/{kind}")
def backup_download(
    kind: str,
    x_api_token: Optional[str] = Header(default=None),
    token: Optional[str] = Query(default=None),
):


    if kind not in ("latest", "previous"):
        raise HTTPException(status_code=400, detail="Invalid backup kind")

    path = BACKUP_DIR / f"{kind}.wgadmin"
    if not path.exists():
        raise HTTPException(status_code=404, detail="Backup not found")

    ts = datetime.datetime.fromtimestamp(path.stat().st_mtime).strftime("%Y-%m-%d_%H-%M")
    filename = f"FamilyNet-VPN-{ts}.wgadmin"

    return Response(
        content=path.read_bytes(),
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"'
        },
    )

def _fix_wg_interface(conf_path: str) -> bool:
    """Replace hardcoded external iface in PostUp/PostDown with current default route iface."""
    try:
        iface = get_default_interface()
        with open(conf_path, "r") as f:
            content = f.read()
        new_content = re.sub(r"(-o\s+)\S+", r"\g<1>" + iface, content)
        new_content = re.sub(r"(POSTROUTING\s+-o\s+)\S+", r"\g<1>" + iface, new_content)
        if new_content != content:
            with open(conf_path, "w") as f:
                f.write(new_content)
            print(f"[restore] wg interface fixed to {iface}")
        return True
    except Exception as e:
        print(f"[restore] wg interface fix skipped: {e}")
        return False


def _clean_restore_safety(safety_dir: str, keep: int = 3):
    """Remove old restore-safety timestamp groups, keep the most recent `keep`."""
    files: Dict[str, List[str]] = {}
    for f in os.listdir(safety_dir):
        parts = f.rsplit(".", 1)
        if len(parts) != 2 or not parts[1].isdigit():
            continue
        ts = parts[1]
        files.setdefault(ts, []).append(f)
    sorted_ts = sorted(files.keys(), reverse=True)
    for ts in sorted_ts[keep:]:
        for f in files[ts]:
            try:
                os.remove(os.path.join(safety_dir, f))
            except OSError:
                pass


def _rollback_from_safety(safety_dir: str, dst_dir: str):
    """Restore files from safety copies, overwriting current ones."""
    by_base: Dict[str, List[str]] = {}
    for f in os.listdir(safety_dir):
        parts = f.rsplit(".", 1)
        if len(parts) != 2 or not parts[1].isdigit():
            continue
        base = parts[0]
        by_base.setdefault(base, []).append(f)
    for base, versions in by_base.items():
        latest = max(versions, key=lambda x: int(x.rsplit(".", 1)[1]))
        src = os.path.join(safety_dir, latest)
        dst = os.path.join(dst_dir, base)
        try:
            shutil.copy2(src, dst)
            print(f"[restore rollback] {base} restored")
        except Exception as e:
            print(f"[restore rollback] failed for {base}: {e}")


def _do_restore(path: Path, label: str) -> Dict[str, Any]:
    """Extract a .wgadmin tarball into APP_DIR and restart services."""
    safety_dir = os.path.join(APP_DIR, "restore-safety")
    os.makedirs(safety_dir, exist_ok=True)
    restore_ts = int(time.time())
    extracted_members = []  # track for rollback

    # ── 1. Validate tar integrity + check version ──
    try:
        with tarfile.open(path, "r:gz") as tar:
            for member in tar.getmembers():
                if member.isfile():
                    f = tar.extractfile(member)
                    if f:
                        f.read()
                if member.name == ".backup_version":
                    data = json.loads(tar.extractfile(member).read())
                    ver = data.get("version", 0)
                    if ver != BACKUP_VERSION:
                        return {"ok": False, "message":
                                f"Unsupported backup version {ver}. Current version is {BACKUP_VERSION}. Create a fresh backup."}
    except Exception as e:
        return {"ok": False, "message": f"Backup file is corrupted or unreadable: {e}"}

    # ── 2. Check disk space ──
    try:
        archive_size = path.stat().st_size
        usage = shutil.disk_usage(APP_DIR)
        needed = archive_size * 3  # safety copies + extracted data
        if usage.free < needed:
            return {"ok": False, "message":
                    f"Low disk space: {usage.free // 1024 // 1024} MB free, need ~{needed // 1024 // 1024} MB. Free up space and try again."}
    except OSError as e:
        print(f"[restore] disk check skipped: {e}")

    # ── 3. Extract with safety copies ──
    skipped = []
    try:
        with tarfile.open(path, "r:gz") as tar:
            for member in tar.getmembers():
                if not member.isreg() or member.name == ".backup_version":
                    continue
                is_web = member.name.startswith("web/")
                src_name = member.name[4:] if is_web else os.path.basename(member.name)
                if not src_name:
                    continue
                dst_dir = WEB_DIR if is_web else APP_DIR
                dst_path = os.path.join(dst_dir, src_name)

                # save safety copy
                if os.path.exists(dst_path):
                    safety_path = os.path.join(safety_dir, f"{src_name}.{restore_ts}")
                    try:
                        shutil.copy2(dst_path, safety_path)
                    except OSError:
                        pass

                # extract to temp then atomic replace
                tmp_fd, tmp_path = tempfile.mkstemp(dir=dst_dir, prefix=".restore-")
                try:
                    with os.fdopen(tmp_fd, "wb") as tmpf:
                        data = tar.extractfile(member)
                        if data:
                            tmpf.write(data.read())
                    os.replace(tmp_path, dst_path)
                    extracted_members.append(dst_path)
                except Exception as e:
                    try_run_cmd(["rm", "-f", tmp_path], timeout=5)
                    skipped.append(src_name)
                    print(f"[restore] skip {src_name}: {e}")
    except Exception as e:
        # Rollback on catastrophic failure
        _rollback_from_safety(safety_dir, APP_DIR)
        _rollback_from_safety(safety_dir, WEB_DIR)
        return {"ok": False, "message": f"Restore failed, rolled back: {e}"}

    # ── 4. Fix wg0.conf interface ──
    wg_conf_path = os.path.join(APP_DIR, "wg0.conf")
    if os.path.exists(wg_conf_path):
        _fix_wg_interface(wg_conf_path)

    # ── 5. Restart services ──
    if IS_CONTAINER and os.path.exists(wg_conf_path):
        try_run_cmd(["wg-quick", "down", wg_conf_path], timeout=10)
        run_cmd(["wg-quick", "up", wg_conf_path], timeout=10)
    elif not IS_CONTAINER:
        try_run_cmd(["docker", "stop", WG_CONTAINER], timeout=15)
        run_cmd(["docker", "start", WG_CONTAINER], timeout=15)

    if not IS_CONTAINER:
        try_run_cmd(["systemctl", "restart", "wg-admin-api"], timeout=15)

    # ── Log success ──
    log_activity("maintenance", "system", "", "",
                 {"action": "restore-backup-completed", "label": label, "skipped": skipped})

    # ── 6. Clean old safety files ──
    _clean_restore_safety(safety_dir, keep=3)

    msg = f"Restored from {label}, services restarted"
    if skipped:
        msg += f" (skipped: {', '.join(skipped)})"
    return {"ok": True, "message": msg}

@app.post("/backup/restore/{kind}")
def backup_restore(kind: str, x_api_token: Optional[str] = Header(default=None)) -> Dict[str, Any]:


    if kind not in ("latest", "previous"):
        raise HTTPException(status_code=400, detail="Invalid backup kind")

    path = BACKUP_DIR / f"{kind}.wgadmin"
    if not path.exists():
        raise HTTPException(status_code=404, detail="Backup not found")

    log_activity(
        "maintenance",
        "system",
        "",
        "",
        {"action": "restore-backup-started", "kind": kind, "file": str(path)},
    )

    try:
        return _do_restore(path, f"{kind}.wgadmin")
    except Exception as e:
        log_activity("maintenance", "system", "", "", {"action": "restore-backup-failed", "error": str(e)})
        raise HTTPException(status_code=500, detail=f"Restore failed: {e}")

MAX_BACKUP_SIZE = 100 * 1024 * 1024  # 100 MB

@app.post("/backup/upload")
async def backup_upload(
    file: UploadFile = File(...),
    x_api_token: Optional[str] = Header(default=None),
):


    if not file.filename or not file.filename.endswith(".wgadmin"):
        raise HTTPException(status_code=400, detail="File must be a .wgadmin backup")

    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    path = BACKUP_DIR / "uploaded.wgadmin"

    try:
        content = await file.read()
        if len(content) > MAX_BACKUP_SIZE:
            raise HTTPException(status_code=413, detail="Backup file too large (max 100 MB)")
        path.write_bytes(content)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save upload: {e}")

    log_activity("maintenance", "system", "", "", {"action": "restore-from-upload", "file": file.filename})

    try:
        return _do_restore(path, f"upload ({file.filename})")
    except Exception as e:
        log_activity("maintenance", "system", "", "", {"action": "restore-upload-failed", "error": str(e)})
        raise HTTPException(status_code=500, detail=f"Restore failed: {e}")

@app.post("/maintenance/restart-vpn")
def maintenance_restart_vpn(x_api_token: Optional[str] = Header(default=None)) -> Dict[str, Any]:

    wg_conf_path = os.path.join(APP_DIR, "wg0.conf")
    if IS_CONTAINER and os.path.exists(wg_conf_path):
        try_run_cmd(["wg-quick", "down", wg_conf_path], timeout=10)
        run_cmd(["wg-quick", "up", wg_conf_path], timeout=10)
        out = "wg-quick restarted"
    elif not IS_CONTAINER:
        out = run_cmd(["docker", "restart", WG_CONTAINER], timeout=30)
    else:
        out = "vpn restart skipped (config not found)"
    log_activity("maintenance", "system", "", "", {"action": "restart-vpn"})
    return {"ok": True, "action": "restart-vpn", "output": out}

@app.post("/maintenance/restart-admin")
def maintenance_restart_admin(x_api_token: Optional[str] = Header(default=None)) -> Dict[str, Any]:

    run_cmd(["nohup", "bash", "-c", "sleep 2 && systemctl restart wg-admin-api >/dev/null 2>&1 &"], timeout=5)
    log_activity("maintenance", "system", "", "", {"action": "restart-admin"})
    return {"ok": True, "action": "restart-admin", "message": "Restart scheduled"}

@app.post("/maintenance/reboot-server")
def maintenance_reboot_server(x_api_token: Optional[str] = Header(default=None)) -> Dict[str, Any]:

    run_cmd(["nohup", "bash", "-c", "sleep 5 && reboot >/dev/null 2>&1 &"], timeout=5)
    return {"ok": True, "action": "reboot-server", "message": "Reboot scheduled"}

AVATARS_PATH = os.path.join(APP_DIR, "avatars.json")

@app.get("/avatars")
def get_avatars(x_api_token: Optional[str] = Header(default=None)) -> Response:

    if os.path.exists(AVATARS_PATH):
        with open(AVATARS_PATH, "r") as f:
            return Response(content=f.read(), media_type="application/json")
    return Response(content="{}", media_type="application/json")

@app.post("/avatars")
def save_avatars(payload: Dict[str, Any] = Body(default={}), x_api_token: Optional[str] = Header(default=None)) -> Dict[str, Any]:

    with open(AVATARS_PATH, "w") as f:
        json.dump(payload, f)
    return {"ok": True}

@app.get("/")
def root() -> Response:
    with open(os.path.join(WEB_DIR, "index.html"), "r", encoding="utf-8") as f:
        return Response(content=f.read(), media_type="text/html; charset=utf-8",
                        headers={"Cache-Control": "no-cache, no-store, must-revalidate",
                                 "Pragma": "no-cache", "Expires": "0"})
