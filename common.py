import io, ipaddress, json, os, re, shutil, socket, subprocess, threading, time, secrets, uuid, datetime, tempfile, tarfile
from typing import Any, Dict, List, Optional
from pathlib import Path
from fastapi import Body, FastAPI, File, Header, HTTPException, Request, Response, UploadFile
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager

IS_CONTAINER = os.environ.get("WG_INSIDE_CONTAINER", "0") == "1"

if IS_CONTAINER:
    APP_DIR = "/data"
    WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")
    CLIENTS_FILE = os.path.join(APP_DIR, "clients.json")
    BACKUP_DIR = Path(os.path.join(APP_DIR, "backups"))
else:
    APP_DIR = "/root/wg-admin-api"
    WEB_DIR = os.path.join(APP_DIR, "web")
    BACKUP_DIR = Path("/var/lib/wg-admin/backups")
    CLIENTS_FILE = os.environ.get("CLIENTS_FILE", os.path.join(APP_DIR, "clients.json"))

TOKEN_FILE = os.path.join(APP_DIR, "api_token")
TOKEN_NEW_FILE = os.path.join(APP_DIR, "api_token.new")
TOKENS_FILE = os.path.join(APP_DIR, "api_tokens.json")
SETTINGS_FILE = os.path.join(APP_DIR, "settings.json")
ACTIVITY_LOG = os.path.join(APP_DIR, "activity.log")
HEALTH_FILE = os.path.join(APP_DIR, "health_state.json")
SPEED_LIMITS_FILE = os.path.join(APP_DIR, "speed_limits.json")
PARENTAL_RULES_FILE = os.path.join(APP_DIR, "parental_rules.json")
MANUAL_OVERRIDES_FILE = os.path.join(APP_DIR, "manual_overrides.json")
TOP_USER_EVENT_FILE = os.path.join(APP_DIR, "top_user_event.json")
AVATARS_PATH = os.path.join(APP_DIR, "avatars.json")
BACKUP_LOCK = os.path.join(os.path.dirname(APP_DIR), "backup.lock")
BACKUP_VERSION = 1

LEGACY_PROTECTED_NAMES = {"VadimSmart", "VadimWork", "Router"}
PUBLIC_PATHS = {"/", "/app.js", "/app.css", "/sw.js", "/manifest.json", "/health"}

CPU_CACHE: Dict[str, Any] = {"value": None, "ts": 0}
CPU_CACHE_LOCK = threading.Lock()
CPU_LAST_SAMPLE = None

NAME_RE = re.compile(r"^[\w\s\-\.а-яА-ЯёЁ]+$")
RATE_RE = re.compile(r"^\d+(kbit|mbit|gbit|kbps|mbps|gbps)$")

def atomic_json_write(path: str, data, backup: bool = False, **json_kwargs):
    tmp = path + ".tmp"
    try:
        if backup and os.path.exists(path):
            shutil.copy2(path, path + ".bak")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2, **json_kwargs)
        os.replace(tmp, path)
        if backup:
            _cleanup_old_baks(path)
    except Exception:
        try_run_cmd(["rm", "-f", tmp])
        raise

def _cleanup_old_baks(path: str, keep: int = 3) -> None:
    import glob
    baks = sorted(glob.glob(str(path) + ".bak-*"), key=os.path.getmtime)
    for old in baks[:-keep]:
        try:
            os.remove(old)
        except OSError:
            pass

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

def bytes_to_human(num: int) -> str:
    if num < 1024: return f"{num} B"
    if num < 1024 * 1024: return f"{num // 1024} KB"
    mb = num / (1024.0 * 1024)
    if mb < 1024: return f"{mb:.1f} MB"
    return f"{mb / 1024:.1f} GB"

def backup_size_human(num: int) -> str:
    if num < 1024: return f"{num} B"
    if num < 1024 * 1024: return f"{num // 1024} KB"
    mb = num / (1024.0 * 1024)
    if mb < 0.1: return "<0.1 MB"
    if mb < 1024: return f"{mb:.1f} MB"
    return f"{mb / 1024:.1f} GB"

def handshake_to_text(ts: int) -> str:
    if ts <= 0: return "never"
    diff = max(0, int(time.time()) - ts)
    if diff < 60: return f"{diff} seconds ago"
    if diff < 3600: return f"{diff // 60} minutes ago"
    if diff < 86400: return f"{diff // 3600} hours ago"
    return f"{diff // 86400} days ago"

def seconds_to_human(seconds: int) -> str:
    seconds = max(0, int(seconds))
    hours = seconds // 3600
    minutes = (seconds % 3600) // 60
    if hours: return f"{hours}h {minutes}m"
    if minutes: return f"{minutes}m"
    return f"{seconds}s"

def today_key() -> str:
    return time.strftime("%Y-%m-%d", time.gmtime())

def week_key() -> str:
    return time.strftime("%G-W%V", time.gmtime())

def month_key() -> str:
    return time.strftime("%Y-%m", time.gmtime())

def _get_hostname() -> str:
    env_name = os.environ.get("SERVER_HOSTNAME", "").strip()
    if env_name: return env_name
    return socket.gethostname()

def get_default_interface() -> str:
    try:
        out = subprocess.check_output(["ip", "route", "get", "8.8.8.8"], stderr=subprocess.DEVNULL, timeout=5).decode().strip()
        match = re.search(r"dev\s+([^\s]+)", out)
        return match.group(1) if match else "eth0"
    except Exception:
        return os.environ.get("WG_EXTERNAL_IFACE", "eth0")

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
        with CPU_CACHE_LOCK: CPU_LAST_SAMPLE = (idle2, total2, now); CPU_CACHE["value"] = {"percent": 0.0}; CPU_CACHE["ts"] = now
        return CPU_CACHE["value"]
    total_delta = total2 - total1; idle_delta = idle2 - idle1
    percent = 100.0 * (1.0 - idle_delta / total_delta) if total_delta > 0 else 0.0
    percent = max(0.0, min(100.0, percent))
    result = {"percent": round(percent, 1)}
    with CPU_CACHE_LOCK: CPU_CACHE["value"] = result; CPU_CACHE["ts"] = now; CPU_LAST_SAMPLE = (idle2, total2, now)
    return result

def get_memory() -> Dict[str, Any]:
    data = {}
    with open("/proc/meminfo", "r", encoding="utf-8") as f:
        for line in f:
            key, value = line.split(":", 1)
            data[key] = int(value.strip().split()[0]) * 1024
    total = data.get("MemTotal", 0); available = data.get("MemAvailable", 0); used = max(0, total - available)
    return {"total_bytes": total, "used_bytes": used, "available_bytes": available,
            "total_human": bytes_to_human(total), "used_human": bytes_to_human(used),
            "available_human": bytes_to_human(available),
            "used_percent": round((used / total) * 100, 2) if total else 0}

def get_disk_root() -> Dict[str, Any]:
    usage = shutil.disk_usage("/")
    return {"total_bytes": usage.total, "used_bytes": usage.used, "free_bytes": usage.free,
            "total_human": bytes_to_human(usage.total), "used_human": bytes_to_human(usage.used),
            "free_human": bytes_to_human(usage.free),
            "used_percent": round((usage.used / usage.total) * 100, 2) if usage.total else 0}

def get_uptime() -> Dict[str, Any]:
    with open("/proc/uptime", "r", encoding="utf-8") as f:
        seconds = int(float(f.read().split()[0]))
    return {"seconds": seconds, "human": f"{seconds // 86400}d {(seconds % 86400) // 3600}h {(seconds % 3600) // 60}m"}

def read_settings() -> Dict[str, Any]:
    defaults = {"traffic_warn_gb": 30, "timezone": "auto"}
    try:
        with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict): defaults.update(data)
    except (FileNotFoundError, Exception): pass
    return defaults

def write_settings(data: Dict[str, Any]) -> Dict[str, Any]:
    current = read_settings(); current.update(data)
    atomic_json_write(SETTINGS_FILE, current, backup=True)
    return current

def apply_timezone() -> None:
    settings = read_settings(); tz = settings.get("timezone", "auto")
    if tz and tz != "auto":
        os.environ["TZ"] = tz
        try: time.tzset()
        except AttributeError: pass
    elif "TZ" in os.environ:
        del os.environ["TZ"]
        try: time.tzset()
        except AttributeError: pass

def log_activity(action: str, peer: str, client_id: str, ip: str = "", details: Optional[Dict[str, Any]] = None) -> None:
    event = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "action": action,
             "peer": peer, "client_id": client_id, "ip": ip, "details": details or {}}
    MAX_LINES = 10000; TRIM_TO = 5000
    with open(ACTIVITY_LOG, "a+", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")
        if f.tell() > 512 * 1024:
            f.seek(0); lines = f.readlines()
            if len(lines) > MAX_LINES:
                remaining = lines[-TRIM_TO:]; f.seek(0); f.truncate(); f.writelines(remaining)

def read_activity(limit: int = 30) -> List[Dict[str, Any]]:
    try:
        with open(ACTIVITY_LOG, "r", encoding="utf-8") as f: lines = f.readlines()
    except FileNotFoundError: return []
    events = []
    for line in lines[-limit:]:
        line = line.strip()
        if not line: continue
        try: events.append(json.loads(line))
        except Exception: continue
    events.reverse(); return events

_TOKENS_CACHE: Optional[List[Dict[str, Any]]] = None

def _read_tokens_raw() -> List[Dict[str, Any]]:
    global _TOKENS_CACHE
    if _TOKENS_CACHE is not None: return _TOKENS_CACHE
    try:
        with open(TOKENS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, list):
                _TOKENS_CACHE = data; return _TOKENS_CACHE
    except (FileNotFoundError, json.JSONDecodeError): pass
    _TOKENS_CACHE = []; return _TOKENS_CACHE

def _write_tokens_raw(tokens: List[Dict[str, Any]]):
    global _TOKENS_CACHE; _TOKENS_CACHE = None
    atomic_json_write(TOKENS_FILE, tokens, backup=True)

def _migrate_old_tokens():
    if os.path.isfile(TOKENS_FILE): return
    collected = {}
    for path in (TOKEN_NEW_FILE, TOKEN_FILE):
        try:
            with open(path, "r", encoding="utf-8") as f:
                val = f.read().strip()
                if val and val not in collected: collected[val] = True
        except (FileNotFoundError, OSError): continue
    if collected:
        tokens_list = []
        for idx, tok in enumerate(collected):
            tokens_list.append({"id": f"migrated-{idx}", "label": f"Token {idx + 1}" if idx > 0 else "Default",
                                "token": tok, "created_at": int(time.time())})
        _write_tokens_raw(tokens_list); print(f"[auth] migrated {len(tokens_list)} legacy token(s) to {TOKENS_FILE}")

def _reconcile_recovery_token():
    try:
        with open(TOKEN_FILE, "r", encoding="utf-8") as f: recovery = f.read().strip()
    except (FileNotFoundError, OSError): return
    if not recovery: return
    tokens = list(_read_tokens_raw())
    if any(t.get("token") == recovery for t in tokens): return
    tokens = [t for t in tokens if t.get("id") != "recovery"]
    tokens.append({"id": "recovery", "label": "Recovery", "token": recovery, "created_at": int(time.time())})
    _write_tokens_raw(tokens); print(f"[auth] reconciled recovery token into {TOKENS_FILE}")

def get_all_tokens() -> List[Dict[str, Any]]:
    return _read_tokens_raw()

def require_auth(x_api_token: Optional[str]) -> None:
    tokens = _read_tokens_raw()
    if not tokens: raise HTTPException(status_code=500, detail="No API tokens configured")
    if not x_api_token: raise HTTPException(status_code=401, detail="Unauthorized")
    for t in tokens:
        if t.get("token") == x_api_token: return
    raise HTTPException(status_code=401, detail="Unauthorized")

def read_clients_data() -> Dict[str, Any]:
    try:
        with open(CLIENTS_FILE, "r", encoding="utf-8") as f: return json.load(f)
    except Exception as e: raise HTTPException(status_code=500, detail=f"Cannot read clients data: {e}")

def get_client(client_id: str) -> Dict[str, Any]:
    data = read_clients_data(); clients = data.get("clients", {}); client = clients.get(client_id)
    if not client: raise HTTPException(status_code=404, detail=f"Client not found: {client_id}")
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
        if ip_str not in used: return ip_str
    raise HTTPException(status_code=500, detail="No free VPN IP addresses")

def validate_rate(raw: Any) -> str:
    s = str(raw).strip().lower() if raw else "256kbit"
    if not RATE_RE.match(s): raise HTTPException(status_code=400, detail=f"Invalid rate: {raw!r}")
    return s

def read_speed_limits() -> Dict[str, Any]:
    try:
        with open(SPEED_LIMITS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except Exception: return {}

def write_speed_limits(data: Dict[str, Any]) -> None:
    atomic_json_write(SPEED_LIMITS_FILE, data, backup=True)

def read_parental_rules() -> Dict[str, Any]:
    try:
        with open(PARENTAL_RULES_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except Exception: return {}

def write_parental_rules(data: Dict[str, Any]) -> None:
    atomic_json_write(PARENTAL_RULES_FILE, data, backup=True)

def read_manual_overrides() -> Dict[str, Any]:
    try:
        with open(MANUAL_OVERRIDES_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except Exception: return {}

def write_manual_overrides(data: Dict[str, Any]) -> None:
    atomic_json_write(MANUAL_OVERRIDES_FILE, data, backup=True)

def _create_backup() -> bool:
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
                if os.path.exists(fpath): tar.add(fpath, arcname=fname)
            for web_fname in ["index.html", "app.js", "app.css"]:
                fpath = os.path.join(WEB_DIR, web_fname)
                if os.path.exists(fpath): tar.add(fpath, arcname=f"web/{web_fname}")
            meta = {"version": BACKUP_VERSION, "created_at": int(time.time())}
            meta_buf = json.dumps(meta).encode("utf-8")
            info = tarfile.TarInfo(name=".backup_version"); info.size = len(meta_buf)
            tar.addfile(info, io.BytesIO(meta_buf))
        with open(tmp_path, "wb") as f: f.write(buf.getvalue())
        prev_path = BACKUP_DIR / "previous.wgadmin"
        if latest_path.exists():
            if prev_path.exists(): prev_path.unlink()
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
        with os.fdopen(fd, 'w') as f: f.write(str(int(time.time())))
        return True
    except OSError:
        try:
            if os.path.exists(BACKUP_LOCK):
                mtime = os.path.getmtime(BACKUP_LOCK)
                if time.time() - mtime > 600:
                    os.unlink(BACKUP_LOCK); return _acquire_backup_lock()
        except Exception: pass
        return False

def config_changed(reason: str = ""):
    print(f"[config_changed] {reason}")
    def _task():
        if not _acquire_backup_lock(): return
        try: _create_backup()
        finally: try_run_cmd(["rm", "-f", BACKUP_LOCK], timeout=5)
    t = threading.Thread(target=_task, daemon=True); t.start()

def backup_file_info(name: str) -> Dict[str, Any]:
    path = BACKUP_DIR / name
    if not path.exists(): return {"exists": False, "name": name}
    st = path.stat()
    return {"exists": True, "name": name, "size": st.st_size, "size_human": backup_size_human(st.st_size),
            "mtime": int(st.st_mtime), "path": str(path)}

def _fix_wg_interface(conf_path: str) -> bool:
    try:
        iface = get_default_interface()
        with open(conf_path, "r") as f: content = f.read()
        new_content = re.sub(r"(-o\s+)\S+", r"\g<1>" + iface, content)
        new_content = re.sub(r"(POSTROUTING\s+-o\s+)\S+", r"\g<1>" + iface, new_content)
        if new_content != content:
            with open(conf_path, "w") as f: f.write(new_content)
            print(f"[restore] wg interface fixed to {iface}")
        return True
    except Exception as e:
        print(f"[restore] wg interface fix skipped: {e}"); return False

def _clean_restore_safety(safety_dir: str, keep: int = 3):
    files: Dict[str, List[str]] = {}
    for f in os.listdir(safety_dir):
        parts = f.rsplit(".", 1)
        if len(parts) != 2 or not parts[1].isdigit(): continue
        ts = parts[1]; files.setdefault(ts, []).append(f)
    for ts in sorted(files.keys(), reverse=True)[keep:]:
        for f in files[ts]:
            try: os.remove(os.path.join(safety_dir, f))
            except OSError: pass

def _rollback_from_safety(safety_dir: str, dst_dir: str):
    by_base: Dict[str, List[str]] = {}
    for f in os.listdir(safety_dir):
        parts = f.rsplit(".", 1)
        if len(parts) != 2 or not parts[1].isdigit(): continue
        base = parts[0]; by_base.setdefault(base, []).append(f)
    for base, versions in by_base.items():
        latest = max(versions, key=lambda x: int(x.rsplit(".", 1)[1]))
        try: shutil.copy2(os.path.join(safety_dir, latest), os.path.join(dst_dir, base))
        except Exception as e: print(f"[restore rollback] failed for {base}: {e}")

def _do_restore(path: Path, label: str, post_restart: callable = None) -> Dict[str, Any]:
    safety_dir = os.path.join(APP_DIR, "restore-safety")
    os.makedirs(safety_dir, exist_ok=True); restore_ts = int(time.time())
    extracted_members = []
    try:
        with tarfile.open(path, "r:gz") as tar:
            for member in tar.getmembers():
                if member.isfile() and member.name == ".backup_version":
                    data = json.loads(tar.extractfile(member).read())
                    ver = data.get("version", 0)
                    if ver != BACKUP_VERSION:
                        return {"ok": False, "message": f"Unsupported backup version {ver}. Current version is {BACKUP_VERSION}. Create a fresh backup."}
    except Exception as e:
        return {"ok": False, "message": f"Backup file is corrupted or unreadable: {e}"}
    try:
        archive_size = path.stat().st_size; usage = shutil.disk_usage(APP_DIR)
        needed = archive_size * 3
        if usage.free < needed:
            return {"ok": False, "message": f"Low disk space: {usage.free // 1024 // 1024} MB free, need ~{needed // 1024 // 1024} MB."}
    except OSError as e: print(f"[restore] disk check skipped: {e}")
    skipped = []
    try:
        with tarfile.open(path, "r:gz") as tar:
            for member in tar.getmembers():
                if not member.isreg() or member.name == ".backup_version": continue
                is_web = member.name.startswith("web/")
                src_name = member.name[4:] if is_web else os.path.basename(member.name)
                if not src_name: continue
                dst_dir = WEB_DIR if is_web else APP_DIR; dst_path = os.path.join(dst_dir, src_name)
                if os.path.exists(dst_path):
                    safety_path = os.path.join(safety_dir, f"{src_name}.{restore_ts}")
                    try: shutil.copy2(dst_path, safety_path)
                    except OSError: pass
                tmp_fd, tmp_path = tempfile.mkstemp(dir=dst_dir, prefix=".restore-")
                try:
                    with os.fdopen(tmp_fd, "wb") as tmpf:
                        data = tar.extractfile(member)
                        if data: tmpf.write(data.read())
                    os.replace(tmp_path, dst_path); extracted_members.append(dst_path)
                except Exception as e:
                    try_run_cmd(["rm", "-f", tmp_path], timeout=5); skipped.append(src_name); print(f"[restore] skip {src_name}: {e}")
    except Exception as e:
        _rollback_from_safety(safety_dir, APP_DIR); _rollback_from_safety(safety_dir, WEB_DIR)
        return {"ok": False, "message": f"Restore failed, rolled back: {e}"}
    wg_conf_path = os.path.join(APP_DIR, "wg0.conf")
    if os.path.exists(wg_conf_path): _fix_wg_interface(wg_conf_path)
    if post_restart: post_restart()
    log_activity("maintenance", "system", "", "", {"action": "restore-backup-completed", "label": label, "skipped": skipped})
    _clean_restore_safety(safety_dir, keep=3)
    msg = f"Restored from {label}, services restarted"
    if skipped: msg += f" (skipped: {', '.join(skipped)})"
    return {"ok": True, "message": msg}

def _read_health() -> Dict[str, Any]:
    try:
        with open(HEALTH_FILE, "r") as f: return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError): return {"last_issue_ts": None, "healthy_since": None}

def _write_health(data: Dict[str, Any]) -> None:
    atomic_json_write(HEALTH_FILE, data)

def _days_since(ts: Optional[int]) -> int:
    if ts is None: return 0
    return max(0, int((time.time() - ts) / 86400))

def _migrate_protected_peers():
    data = read_clients_data(); clients = data.get("clients", {}); changed = False
    for cid, client in clients.items():
        if isinstance(client, dict):
            if client.get("protected") is None and client.get("name") in LEGACY_PROTECTED_NAMES:
                client["protected"] = True; changed = True
    if changed: atomic_json_write(CLIENTS_FILE, data, backup=True)

def _migrate_peer_roles():
    data = read_clients_data(); clients = data.get("clients", {}); changed = False
    for client in clients.values():
        if isinstance(client, dict) and client.get("role") is None:
            client["role"] = "admin" if client.get("protected") else "user"; changed = True
    if changed: atomic_json_write(CLIENTS_FILE, data, backup=True)

def _now_in_offset(rule: dict) -> datetime.datetime:
    offset_min = rule.get("schedule", {}).get("timezone_offset", 0)
    return datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=offset_min)

def check_schedule_block(rule: dict) -> Optional[str]:
    schedule = rule.get("schedule")
    if not schedule or not schedule.get("enabled"): return None
    local = _now_in_offset(rule); wday = local.weekday(); current_min = local.hour * 60 + local.minute
    block_days = schedule.get("days", [])
    if block_days and wday not in block_days: return None
    start_str = schedule.get("start", "00:00"); end_str = schedule.get("end", "23:59")
    try:
        start_min = int(start_str.split(":")[0]) * 60 + int(start_str.split(":")[1])
        end_min = int(end_str.split(":")[0]) * 60 + int(end_str.split(":")[1])
    except (ValueError, IndexError): return None
    if end_min <= start_min:
        if current_min >= start_min or current_min < end_min: return "schedule_time"
    else:
        if current_min >= start_min and current_min < end_min: return "schedule_time"
    return None

def check_parental_limits(peer: dict, rule: dict) -> Optional[dict]:
    schedule_reason = check_schedule_block(rule)
    if schedule_reason: return {"action": "disable", "reason": schedule_reason}
    today = int(peer.get("today_total_bytes", 0))
    hard_limit = int(rule.get("daily_bytes", 0))
    if hard_limit and today >= hard_limit: return {"action": "disable", "reason": "daily"}
    threshold = int(rule.get("speed_limit_threshold", 0))
    if threshold and today >= threshold: return {"action": "speed_limit", "reason": "threshold", "rate": rule.get("speed_limit_rate") or "256kbit"}
    return {"action": "ok"}

def load_top_user_event() -> Dict[str, Any]:
    try:
        with open(TOP_USER_EVENT_FILE, "r", encoding="utf-8") as f: return json.load(f) if isinstance(json.load(f), dict) else {}
    except Exception: return {}

def save_top_user_event(data: Dict[str, Any]) -> None:
    try: atomic_json_write(TOP_USER_EVENT_FILE, data)
    except Exception: pass
