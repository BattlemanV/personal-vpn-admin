import io, json, os, re, secrets, shutil, subprocess, sqlite3, threading, time, uuid as uuid_mod
from typing import Any, Dict, List, Optional
from pathlib import Path

import qrcode
from fastapi import Body, FastAPI, File, Header, HTTPException, Query, Request, Response, UploadFile
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager

from common import (
    IS_CONTAINER, APP_DIR, WEB_DIR, CLIENTS_FILE, BACKUP_DIR, TOKEN_FILE, TOKEN_NEW_FILE,
    TOKENS_FILE, SETTINGS_FILE, ACTIVITY_LOG, HEALTH_FILE, PUBLIC_PATHS, LEGACY_PROTECTED_NAMES,
    atomic_json_write, run_cmd, try_run_cmd, bytes_to_human, handshake_to_text,
    seconds_to_human, today_key, week_key, month_key,
    _get_hostname, get_loadavg, get_cpu_usage, get_memory, get_disk_root, get_uptime,
    read_settings, write_settings, apply_timezone,
    log_activity, read_activity,
    _read_tokens_raw, _write_tokens_raw, _migrate_old_tokens, _reconcile_recovery_token,
    get_all_tokens, require_auth,
    read_clients_data, get_client, allocate_next_client_ip,
    _create_backup, _acquire_backup_lock, config_changed, backup_file_info,
    _do_restore, _read_health, _write_health, _days_since,
    _migrate_protected_peers, _migrate_peer_roles, NAME_RE, AVATARS_PATH,
)

XRAY_CONFIG = os.path.join(APP_DIR, "xray.json")
XRAY_HOST = os.environ.get("XRAY_HOST") or os.environ.get("WG_HOST")
if not XRAY_HOST:
    raise RuntimeError("XRAY_HOST environment variable is required")

XRAY_REALITY_PORT = int(os.environ.get("REALITY_PORT", "443"))
XRAY_WS_PORT = int(os.environ.get("WS_PORT", "8444"))
XRAY_XHTTP_PORT = int(os.environ.get("XHTTP_PORT", "8445"))
XRAY_WS_INTERNAL = int(os.environ.get("XRAY_PORT", "8443"))
XRAY_XHTTP_INTERNAL = 8445
XRAY_API_PORT = int(os.environ.get("XRAY_API_PORT", "62789"))

TRAFFIC_DB_FILE = os.path.join(APP_DIR, "traffic_stats.sqlite")

REALITY_PUBLIC_KEY_FILE = os.path.join(APP_DIR, "reality_public")
REALITY_SHORT_ID_FILE = os.path.join(APP_DIR, "reality_short_id")

def _read_reality_public() -> str:
    try:
        with open(REALITY_PUBLIC_KEY_FILE, "r") as f:
            return f.read().strip()
    except (FileNotFoundError, OSError):
        return ""

def _read_short_id() -> str:
    try:
        with open(REALITY_SHORT_ID_FILE, "r") as f:
            return f.read().strip()
    except (FileNotFoundError, OSError):
        return ""

def sync_xray_config_background() -> None:
    import threading
    threading.Thread(target=sync_xray_config, daemon=True).start()

def sync_xray_config() -> None:
    data = read_clients_data()
    clients = data.get("clients", {})

    existing = {}
    try:
        with open(XRAY_CONFIG, "r") as f:
            existing = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        pass

    existing_reality = {}
    for inbound in existing.get("inbounds", []):
        ss = inbound.get("streamSettings", {})
        if ss.get("security") == "reality":
            existing_reality = ss.get("realitySettings", {})

    enabled_clients = [
        c for c in clients.values()
        if isinstance(c, dict) and c.get("enabled", True) and c.get("xray_uuid")
    ]

    reality_clients = [
        {"id": c["xray_uuid"], "email": c["xray_uuid"], "flow": "xtls-rprx-vision"} for c in enabled_clients
    ]
    ws_clients = [{"id": c["xray_uuid"], "email": c["xray_uuid"]} for c in enabled_clients]
    xhttp_clients = [{"id": c["xray_uuid"], "email": c["xray_uuid"]} for c in enabled_clients]

    reality_settings = dict(existing_reality)
    if not reality_settings.get("privateKey"):
        keys_out = try_run_cmd(["xray", "x25519"], timeout=10)
        private_key = ""
        public_key = ""
        if keys_out:
            for line in keys_out.splitlines():
                if "PrivateKey" in line:
                    private_key = line.split()[-1]
                elif "PublicKey" in line:
                    public_key = line.split()[-1]
        short_id = secrets.token_hex(4)
        reality_settings = {
            "show": False, "dest": "www.microsoft.com:443", "xver": 0,
            "serverNames": ["www.microsoft.com"], "privateKey": private_key,
            "maxTimeDiff": 0, "shortIds": [short_id],
        }
        if public_key:
            with open(REALITY_PUBLIC_KEY_FILE, "w") as f:
                f.write(public_key)
        with open(REALITY_SHORT_ID_FILE, "w") as f:
            f.write(short_id)
    else:
        if not os.path.exists(REALITY_PUBLIC_KEY_FILE):
            pub_out = try_run_cmd(["xray", "x25519", "-i", reality_settings.get("privateKey", "")], timeout=10)
            if pub_out:
                for line in pub_out.splitlines():
                    if "PublicKey" in line:
                        with open(REALITY_PUBLIC_KEY_FILE, "w") as f:
                            f.write(line.split()[-1])
        if not os.path.exists(REALITY_SHORT_ID_FILE):
            short_ids = reality_settings.get("shortIds", [])
            if short_ids:
                with open(REALITY_SHORT_ID_FILE, "w") as f:
                    f.write(short_ids[0])

    config = {
        "log": {"loglevel": "warning"},
        "api": {"tag": "api", "services": ["StatsService", "HandlerService"]},
        "stats": {},
        "policy": {
            "levels": {"0": {"statsUserUplink": True, "statsUserDownlink": True}},
            "system": {"statsInboundUplink": True, "statsInboundDownlink": True},
        },
        "inbounds": [
            {
                "port": XRAY_REALITY_PORT, "protocol": "vless",
                "settings": {"clients": reality_clients, "decryption": "none"},
                "streamSettings": {
                    "network": "tcp", "security": "reality",
                    "realitySettings": reality_settings,
                },
                "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
            },
            {
                "port": XRAY_WS_INTERNAL, "protocol": "vless",
                "settings": {"clients": ws_clients, "decryption": "none"},
                "streamSettings": {
                    "network": "ws", "security": "none",
                    "wsSettings": {"path": "/vless"},
                },
                "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
            },
            {
                "port": XRAY_XHTTP_INTERNAL, "protocol": "vless",
                "settings": {"clients": xhttp_clients, "decryption": "none"},
                "streamSettings": {
                    "network": "xhttp", "security": "none",
                    "xhttpSettings": {"path": "/vless"},
                },
                "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
            },
            {
                "tag": "api",
                "port": XRAY_API_PORT, "listen": "127.0.0.1",
                "protocol": "dokodemo-door",
                "settings": {"address": "127.0.0.1"},
            },
        ],
        "outbounds": [
            {"protocol": "freedom", "tag": "direct", "settings": {"domainStrategy": "UseIP"}},
            {"protocol": "freedom", "tag": "api"},
            {"protocol": "blackhole", "tag": "block"},
        ],
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                {"type": "field", "inboundTag": ["api"], "outboundTag": "api"},
                {"type": "field", "outboundTag": "direct", "network": "tcp,udp"},
            ],
        },
    }

    atomic_json_write(XRAY_CONFIG, config)
    try_run_cmd(["pkill", "-x", "xray"], timeout=5)
    subprocess.Popen(
        ["nohup", "xray", "run", "-c", XRAY_CONFIG],
        stdout=open("/tmp/xray.log", "a"), stderr=subprocess.STDOUT,
    )

def build_xray_link(client_id: str, proto: str) -> str:
    item = get_client(client_id)
    client = item["client"]
    uid = client.get("xray_uuid", "")
    name = client.get("name", client_id)
    if not uid:
        raise HTTPException(status_code=500, detail="Client xray_uuid not found")

    proto = proto.lower()
    if proto == "reality":
        pubkey = _read_reality_public()
        short_id = _read_short_id()
        if not pubkey or not short_id:
            raise HTTPException(status_code=500, detail="REALITY keys not initialized")
        return (
            f"vless://{uid}@{XRAY_HOST}:{XRAY_REALITY_PORT}"
            f"?type=tcp&security=reality&pbk={pubkey}"
            f"&fp=chrome&sni=www.microsoft.com&sid={short_id}"
            f"#{name}"
        )
    elif proto == "ws":
        return (
            f"vless://{uid}@{XRAY_HOST}:{XRAY_WS_PORT}"
            f"?type=ws&path=/vless&security=none"
            f"#{name}"
        )
    elif proto == "xhttp":
        return (
            f"vless://{uid}@{XRAY_HOST}:{XRAY_XHTTP_PORT}"
            f"?type=xhttp&path=/vless&security=none"
            f"#{name}"
        )
    raise HTTPException(status_code=400, detail=f"Unknown protocol: {proto}")

def post_restart_xray():
    sync_xray_config_background()

_TRAFFIC_CACHE: Dict[str, Dict[str, int]] = {}
_TRAFFIC_CACHE_TS: float = 0
_TRAFFIC_ACCUM: Dict[str, Dict[str, int]] = {}

def get_xray_traffic() -> Dict[str, Dict[str, int]]:
    global _TRAFFIC_CACHE, _TRAFFIC_CACHE_TS, _TRAFFIC_ACCUM
    now = time.time()
    if now - _TRAFFIC_CACHE_TS < 30:
        return _TRAFFIC_CACHE
    result: Dict[str, Dict[str, int]] = {}
    out = try_run_cmd(["xray", "api", "statsquery", "--server", f"127.0.0.1:{XRAY_API_PORT}", "-pattern", "user>>>"], timeout=5)
    if out:
        try:
            data = json.loads(out)
            entries = []
            if isinstance(data, dict):
                entries = data.get("stat", [])
            elif isinstance(data, list):
                entries = data
            for entry in entries:
                if isinstance(entry, dict):
                    name = entry.get("name", "")
                    value = int(entry.get("value", 0))
                    match = re.search(r"user>>>([^>]+)>>>traffic>>>(downlink|uplink)", name)
                    if match:
                        email = match.group(1)
                        direction = match.group(2)
                        result.setdefault(email, {"downlink": 0, "uplink": 0})
                        result[email][direction] = max(result[email][direction], value)
        except json.JSONDecodeError:
            pass
    for email, data in result.items():
        prev = _TRAFFIC_ACCUM.get(email, {"downlink": 0, "uplink": 0})
        _TRAFFIC_ACCUM[email] = {
            "downlink": max(prev["downlink"], data["downlink"]),
            "uplink": max(prev["uplink"], data["uplink"]),
        }
    _TRAFFIC_CACHE = dict(_TRAFFIC_ACCUM)
    _TRAFFIC_CACHE_TS = now
    return _TRAFFIC_CACHE

def init_traffic_db() -> None:
    with sqlite3.connect(TRAFFIC_DB_FILE, timeout=10) as db:
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("CREATE TABLE IF NOT EXISTS peer_counters (public_key TEXT PRIMARY KEY, last_rx INTEGER NOT NULL DEFAULT 0, last_tx INTEGER NOT NULL DEFAULT 0, updated_ts INTEGER NOT NULL DEFAULT 0)")
        db.execute("CREATE TABLE IF NOT EXISTS traffic_totals (public_key TEXT NOT NULL, period_type TEXT NOT NULL, period_key TEXT NOT NULL, rx INTEGER NOT NULL DEFAULT 0, tx INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (public_key, period_type, period_key))")
        db.execute("CREATE TABLE IF NOT EXISTS online_totals (public_key TEXT NOT NULL, day_key TEXT NOT NULL, seconds INTEGER NOT NULL DEFAULT 0, last_seen_ts INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (public_key, day_key))")
        db.execute("CREATE TABLE IF NOT EXISTS peer_last_seen (public_key TEXT PRIMARY KEY, last_seen INTEGER NOT NULL DEFAULT 0, updated_ts INTEGER NOT NULL DEFAULT 0)")

def save_peer_last_seen(peer_key: str, latest_handshake: int) -> int:
    if not peer_key or latest_handshake <= 0: return 0
    now = int(time.time())
    with sqlite3.connect(TRAFFIC_DB_FILE, timeout=10) as db:
        row = db.execute("SELECT last_seen FROM peer_last_seen WHERE public_key = ?", (peer_key,)).fetchone()
        old_last_seen = int(row[0]) if row else 0
        new_last_seen = max(old_last_seen, int(latest_handshake))
        db.execute("INSERT INTO peer_last_seen (public_key, last_seen, updated_ts) VALUES (?, ?, ?) ON CONFLICT(public_key) DO UPDATE SET last_seen = CASE WHEN excluded.last_seen > peer_last_seen.last_seen THEN excluded.last_seen ELSE peer_last_seen.last_seen END, updated_ts = excluded.updated_ts", (peer_key, new_last_seen, now))
        return new_last_seen

def get_peer_last_seen(peer_key: str) -> int:
    if not peer_key: return 0
    with sqlite3.connect(TRAFFIC_DB_FILE, timeout=10) as db:
        row = db.execute("SELECT last_seen FROM peer_last_seen WHERE public_key = ?", (peer_key,)).fetchone()
    return int(row[0]) if row else 0

def add_traffic_total(db, peer_key: str, period_type: str, period_key: str, rx_delta: int, tx_delta: int) -> None:
    db.execute("INSERT INTO traffic_totals (public_key, period_type, period_key, rx, tx) VALUES (?, ?, ?, ?, ?) ON CONFLICT(public_key, period_type, period_key) DO UPDATE SET rx = rx + excluded.rx, tx = tx + excluded.tx", (peer_key, period_type, period_key, rx_delta, tx_delta))

def read_traffic_total(db, peer_key: str, period_type: str, period_key: str) -> Dict[str, int]:
    row = db.execute("SELECT rx, tx FROM traffic_totals WHERE public_key = ? AND period_type = ? AND period_key = ?", (peer_key, period_type, period_key)).fetchone()
    if not row: return {"rx": 0, "tx": 0}
    return {"rx": int(row[0] or 0), "tx": int(row[1] or 0)}

def update_online_total(db, peer_key: str, day: str, online: bool, now_ts: int) -> int:
    row = db.execute("SELECT seconds, last_seen_ts FROM online_totals WHERE public_key = ? AND day_key = ?", (peer_key, day)).fetchone()
    if not row:
        db.execute("INSERT INTO online_totals (public_key, day_key, seconds, last_seen_ts) VALUES (?, ?, 0, ?)", (peer_key, day, now_ts if online else 0))
        return 0
    seconds = int(row[0] or 0); last_seen = int(row[1] or 0)
    if online:
        if last_seen > 0: seconds += min(max(0, now_ts - last_seen), 120)
        db.execute("UPDATE online_totals SET seconds = ?, last_seen_ts = ? WHERE public_key = ? AND day_key = ?", (seconds, now_ts, peer_key, day))
    else:
        db.execute("UPDATE online_totals SET last_seen_ts = 0 WHERE public_key = ? AND day_key = ?", (peer_key, day))
    return seconds

def read_rolling_traffic(db, peer_key: str, days: int) -> Dict[str, int]:
    cutoff = time.strftime("%Y-%m-%d", time.localtime(time.time() - days * 86400))
    row = db.execute("SELECT COALESCE(SUM(rx), 0), COALESCE(SUM(tx), 0) FROM traffic_totals WHERE public_key = ? AND period_type = 'day' AND period_key >= ?", (peer_key, cutoff)).fetchone()
    return {"rx": int(row[0] or 0), "tx": int(row[1] or 0)}

def cleanup_traffic_db(db) -> None:
    cutoff_day = time.strftime("%Y-%m-%d", time.localtime(time.time() - 180 * 86400))
    db.execute("DELETE FROM traffic_totals WHERE period_type = 'day' AND period_key < ?", (cutoff_day,))
    db.execute("DELETE FROM online_totals WHERE day_key < ?", (cutoff_day,))

def get_period_traffic(peer_key: str, rx: int, tx: int, online: bool = False) -> Dict[str, Any]:
    today = today_key(); week = week_key(); month = month_key(); now_ts = int(time.time())
    with sqlite3.connect(TRAFFIC_DB_FILE, timeout=10) as db:
        row = db.execute("SELECT last_rx, last_tx FROM peer_counters WHERE public_key = ?", (peer_key,)).fetchone()
        ignore_zero_offline = bool(row) and rx == 0 and tx == 0 and not online
        if row is None:
            rx_delta = 0; tx_delta = 0
            db.execute("INSERT INTO peer_counters (public_key, last_rx, last_tx, updated_ts) VALUES (?, ?, ?, ?)", (peer_key, rx, tx, now_ts))
        elif ignore_zero_offline: rx_delta = 0; tx_delta = 0
        else:
            last_rx = int(row[0] or 0); last_tx = int(row[1] or 0)
            rx_delta = rx - last_rx if rx >= last_rx else rx; tx_delta = tx - last_tx if tx >= last_tx else tx
            rx_delta = max(0, rx_delta); tx_delta = max(0, tx_delta)
            db.execute("UPDATE peer_counters SET last_rx = ?, last_tx = ?, updated_ts = ? WHERE public_key = ?", (rx, tx, now_ts, peer_key))
        if rx_delta or tx_delta:
            add_traffic_total(db, peer_key, "day", today, rx_delta, tx_delta)
            add_traffic_total(db, peer_key, "hour", time.strftime("%Y-%m-%d-%H", time.gmtime()), rx_delta, tx_delta)
            add_traffic_total(db, peer_key, "week", week, rx_delta, tx_delta)
            add_traffic_total(db, peer_key, "month", month, rx_delta, tx_delta)
            add_traffic_total(db, peer_key, "total", "all", rx_delta, tx_delta)
        online_today_seconds = update_online_total(db, peer_key, today, online, now_ts)
        day_t = read_traffic_total(db, peer_key, "day", today)
        week_total = read_rolling_traffic(db, peer_key, 7)
        month_total = read_traffic_total(db, peer_key, "month", month)
        year_total = read_rolling_traffic(db, peer_key, 365)
        total = read_traffic_total(db, peer_key, "total", "all")
        cleanup_traffic_db(db)
    return {
        "today_rx_bytes": day_t["rx"], "today_tx_bytes": day_t["tx"], "today_total_bytes": day_t["rx"] + day_t["tx"],
        "today_rx_human": bytes_to_human(day_t["rx"]), "today_tx_human": bytes_to_human(day_t["tx"]), "today_total_human": bytes_to_human(day_t["rx"] + day_t["tx"]),
        "week_rx_bytes": week_total["rx"], "week_tx_bytes": week_total["tx"], "week_total_bytes": week_total["rx"] + week_total["tx"],
        "week_rx_human": bytes_to_human(week_total["rx"]), "week_tx_human": bytes_to_human(week_total["tx"]), "week_total_human": bytes_to_human(week_total["rx"] + week_total["tx"]),
        "month_rx_bytes": month_total["rx"], "month_tx_bytes": month_total["tx"], "month_total_bytes": month_total["rx"] + month_total["tx"],
        "month_rx_human": bytes_to_human(month_total["rx"]), "month_tx_human": bytes_to_human(month_total["tx"]), "month_total_human": bytes_to_human(month_total["rx"] + month_total["tx"]),
        "year_rx_bytes": year_total["rx"], "year_tx_bytes": year_total["tx"], "year_total_bytes": year_total["rx"] + year_total["tx"],
        "year_rx_human": bytes_to_human(year_total["rx"]), "year_tx_human": bytes_to_human(year_total["tx"]), "year_total_human": bytes_to_human(year_total["rx"] + year_total["tx"]),
        "saved_total_rx_bytes": total["rx"], "saved_total_tx_bytes": total["tx"], "saved_total_bytes": total["rx"] + total["tx"],
        "saved_total_human": bytes_to_human(total["rx"] + total["tx"]), "saved_total_rx_human": bytes_to_human(total["rx"]), "saved_total_tx_human": bytes_to_human(total["tx"]),
        "online_today_seconds": online_today_seconds, "online_today_human": seconds_to_human(online_today_seconds),
    }

def _build_peer_entry(client: Dict[str, Any], client_id: str) -> Dict[str, Any]:
    name = client.get("name", client_id)
    address = client.get("address", "")
    uid = client.get("xray_uuid", "")
    traffic_all = get_xray_traffic()
    peer_traffic = traffic_all.get(uid, {})
    dl = peer_traffic.get("downlink", 0)
    ul = peer_traffic.get("uplink", 0)
    total = dl + ul
    period = get_period_traffic(uid, ul, dl, False) if uid else {}
    now = int(time.time())
    has_traffic = bool(total) or bool(period.get("today_total_bytes"))
    last_seen = save_peer_last_seen(uid, now) if has_traffic else 0
    if not last_seen:
        last_seen = get_peer_last_seen(uid)
    online = last_seen > 0 and (now - last_seen) < 1800
    return {
        "id": client_id[:12],
        "name": name,
        "ip": address,
        "client_id": client_id,
        "enabled": bool(client.get("enabled", True)),
        "protected": bool(client.get("protected", False)),
        "role": client.get("role", "user"),
        "xray_uuid": uid,
        "public_key": "",
        "public_key_short": "",
        "endpoint": None,
        "allowed_ips": "",
        "latest_handshake": last_seen,
        "latest_handshake_text": handshake_to_text(last_seen),
        "online": online,
        "is_active_now": online,
        "transfer_rx_bytes": ul, "transfer_tx_bytes": dl, "transfer_total_bytes": total,
        "transfer_rx_human": bytes_to_human(ul), "transfer_tx_human": bytes_to_human(dl),
        "transfer_total_human": bytes_to_human(total),
        **period,
        "persistent_keepalive": "off",
        "has_preshared_key": False,
        "speed_limited": False,
        "speed_limit_rate": None,
    }

@asynccontextmanager
async def lifespan(app):
    apply_timezone()
    _migrate_protected_peers()
    _migrate_peer_roles()
    _migrate_old_tokens()
    _reconcile_recovery_token()
    init_traffic_db()
    try:
        sync_xray_config()
    except Exception as e:
        print(f"[xray] initial sync_xray_config: {e}")
    yield

app = FastAPI(title="FamilyNet Xray API", version="0.4.0", lifespan=lifespan)

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    log_activity("error", "system", "", "", {"error": str(exc), "path": request.url.path})
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})

@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    if request.url.path in PUBLIC_PATHS:
        return await call_next(request)
    client_ip = request.client.host
    if client_ip == "10.8.0.1":
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
        return Response(
            content=f.read(), media_type="text/css; charset=utf-8",
            headers={"Cache-Control": "no-cache, no-store, must-revalidate"},
        )

@app.get("/app.js")
def web_js():
    with open(os.path.join(WEB_DIR, "app.js"), "r", encoding="utf-8") as f:
        return Response(
            content=f.read(), media_type="application/javascript; charset=utf-8",
            headers={"Cache-Control": "no-cache, no-store, must-revalidate"},
        )

@app.get("/")
def root() -> Response:
    with open(os.path.join(WEB_DIR, "index.html"), "r", encoding="utf-8") as f:
        return Response(
            content=f.read(), media_type="text/html; charset=utf-8",
            headers={"Cache-Control": "no-cache, no-store, must-revalidate"},
        )

@app.get("/sw.js")
def sw_js() -> Response:
    with open(os.path.join(WEB_DIR, "sw.js"), "r", encoding="utf-8") as f:
        return Response(
            content=f.read(), media_type="application/javascript; charset=utf-8",
            headers={"Cache-Control": "no-cache, no-store, must-revalidate"},
        )

@app.get("/manifest.json")
def manifest_json() -> Response:
    with open(os.path.join(WEB_DIR, "manifest.json"), "r", encoding="utf-8") as f:
        return Response(
            content=f.read(), media_type="application/manifest+json; charset=utf-8",
            headers={"Cache-Control": "no-cache, no-store, must-revalidate"},
        )

@app.get("/health")
def health():
    return {"status": "ok"}

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

@app.get("/tokens")
def list_tokens(
    x_api_token: Optional[str] = Header(default=None),
) -> List[Dict[str, Any]]:
    return [
        {
            "id": t.get("id"),
            "label": t.get("label", ""),
            "prefix": (
                (t["token"][:8] + "..." + t["token"][-4:])
                if len(t.get("token", "")) > 12
                else t.get("token", "")
            ),
            "created_at": t.get("created_at"),
        }
        for t in get_all_tokens()
    ]

@app.post("/tokens")
def create_token(
    payload: Dict[str, Any] = Body(default={}),
    x_api_token: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    label = str(payload.get("label", "")).strip() or "Unnamed"
    new_id = str(uuid_mod.uuid4())[:8]
    new_token = str(payload.get("password", "")).strip()
    if not new_token:
        new_token = secrets.token_hex(32)
    tokens = _read_tokens_raw()
    tokens.append(
        {"id": new_id, "label": label, "token": new_token, "created_at": int(time.time())}
    )
    _write_tokens_raw(tokens)
    log_activity("token_created", "", "", "", {"label": label, "id": new_id})
    config_changed("token-created")
    return {"id": new_id, "label": label, "token": new_token}

@app.delete("/tokens/{token_id}")
def revoke_token(
    token_id: str, x_api_token: Optional[str] = Header(default=None)
) -> Dict[str, Any]:
    tokens = _read_tokens_raw()
    for t in tokens:
        if t.get("token") == x_api_token and t.get("id") == token_id:
            raise HTTPException(status_code=400, detail="Cannot revoke the current session token")
    new_tokens = [t for t in tokens if t.get("id") != token_id]
    if len(new_tokens) == len(tokens):
        raise HTTPException(status_code=404, detail="Token not found")
    _write_tokens_raw(new_tokens)
    log_activity("token_revoked", "", "", "", {"id": token_id})
    config_changed("token-revoked")
    return {"ok": True, "revoked": token_id}

@app.get("/backup/status")
def backup_status(
    x_api_token: Optional[str] = Header(default=None),
) -> Response:
    return Response(
        content=json.dumps(
            {
                "latest": backup_file_info("latest.wgadmin"),
                "previous": backup_file_info("previous.wgadmin"),
            }
        ),
        media_type="application/json",
        headers={"Cache-Control": "no-store, no-cache, must-revalidate"},
    )

@app.post("/backup/create")
def backup_create(
    x_api_token: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    if not _acquire_backup_lock():
        return {"created": False, "message": "Backup already in progress"}
    ok = _create_backup()
    try_run_cmd(["rm", "-f", os.path.join(os.path.dirname(APP_DIR), "backup.lock")], timeout=5)
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
    ts = time.strftime("%Y-%m-%d_%H-%M", time.gmtime(path.stat().st_mtime))
    return Response(
        content=path.read_bytes(),
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="FamilyNet-VPN-{ts}.wgadmin"'
        },
    )

@app.post("/backup/restore/{kind}")
def backup_restore(
    kind: str, x_api_token: Optional[str] = Header(default=None)
) -> Dict[str, Any]:
    if kind not in ("latest", "previous"):
        raise HTTPException(status_code=400, detail="Invalid backup kind")
    path = BACKUP_DIR / f"{kind}.wgadmin"
    if not path.exists():
        raise HTTPException(status_code=404, detail="Backup not found")
    log_activity("maintenance", "system", "", "", {"action": "restore-backup-started", "kind": kind, "file": str(path)})
    try:
        return _do_restore(path, f"{kind}.wgadmin", post_restart=post_restart_xray)
    except Exception as e:
        log_activity("maintenance", "system", "", "", {"action": "restore-backup-failed", "error": str(e)})
        raise HTTPException(status_code=500, detail=f"Restore failed: {e}")

MAX_BACKUP_SIZE = 100 * 1024 * 1024

@app.post("/backup/upload")
async def backup_upload(
    file: UploadFile = File(...), x_api_token: Optional[str] = Header(default=None)
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
        return _do_restore(path, f"upload ({file.filename})", post_restart=post_restart_xray)
    except Exception as e:
        log_activity("maintenance", "system", "", "", {"action": "restore-upload-failed", "error": str(e)})
        raise HTTPException(status_code=500, detail=f"Restore failed: {e}")

@app.get("/activity")
def activity(
    x_api_token: Optional[str] = Header(default=None), limit: int = 30
) -> Dict[str, Any]:
    limit = max(1, min(limit, 100))
    return {"events": read_activity(limit), "limit": limit}

@app.get("/avatars")
def get_avatars(x_api_token: Optional[str] = Header(default=None)) -> Response:
    if os.path.exists(AVATARS_PATH):
        with open(AVATARS_PATH, "r") as f:
            return Response(content=f.read(), media_type="application/json")
    return Response(content="{}", media_type="application/json")

@app.post("/avatars")
def save_avatars(
    payload: Dict[str, Any] = Body(default={}),
    x_api_token: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    with open(AVATARS_PATH, "w") as f:
        json.dump(payload, f)
    return {"ok": True}

@app.post("/maintenance/restart-admin")
def maintenance_restart_admin(
    x_api_token: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    run_cmd(["nohup", "bash", "-c", "sleep 2 && systemctl restart wg-admin-api >/dev/null 2>&1 &"], timeout=5)
    log_activity("maintenance", "system", "", "", {"action": "restart-admin"})
    return {"ok": True, "action": "restart-admin", "message": "Restart scheduled"}

@app.post("/maintenance/reboot-server")
def maintenance_reboot_server(
    x_api_token: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    run_cmd(["nohup", "bash", "-c", "sleep 5 && reboot >/dev/null 2>&1 &"], timeout=5)
    return {"ok": True, "action": "reboot-server", "message": "Reboot scheduled"}

@app.get("/dashboard")
def dashboard(x_api_token: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    data = read_clients_data()
    clients = data.get("clients", {})
    peers_list = [_build_peer_entry(c, cid) for cid, c in clients.items() if isinstance(c, dict)]
    total_rx = sum(p["transfer_rx_bytes"] for p in peers_list)
    total_tx = sum(p["transfer_tx_bytes"] for p in peers_list)
    vpn_today = sum(p.get("today_total_bytes", 0) for p in peers_list)
    vpn_week = sum(p.get("week_total_bytes", 0) for p in peers_list)
    vpn_month = sum(p.get("month_total_bytes", 0) for p in peers_list)
    vpn_year = sum(p.get("year_total_bytes", 0) for p in peers_list)
    vpn_saved_total = sum(p.get("saved_total_bytes", 0) for p in peers_list)
    online_count = sum(1 for p in peers_list if p["online"])
    online_peers = [{"name": p["name"], "ip": p["ip"], "latest_handshake_text": p["latest_handshake_text"],
                      "transfer_total_human": p["transfer_total_human"], "protected": p["protected"]}
                     for p in peers_list if p["online"]]
    best = None
    for p in peers_list:
        if not p.get("online"): continue
        bt = int(p.get("today_total_bytes") or 0)
        if not best or bt > best["today_total_bytes"]:
            best = {"name": p["name"], "ip": p["ip"], "today_total_bytes": bt,
                    "today_total_human": p.get("today_total_human", "0 B")}
    top_user_now = {"active": bool(best), "threshold_mbps": 1.0, "active_peer_count": online_count,
                     "active_peer_keys": [], "active_peer_threshold_mbps": 0.01, "last_event": {}}
    if best:
        top_user_now.update(best)
        top_user_now["ts"] = int(time.time())
    return {
        "variant": "xray",
        "hostname": _get_hostname(),
        "uptime": get_uptime(),
        "cpu": get_cpu_usage(),
        "loadavg": get_loadavg(),
        "memory": get_memory(),
        "disk_root": get_disk_root(),
        "wireguard": {
            "interface": "xray",
            "peer_count": len(peers_list),
            "online_peer_count": online_count,
            "online_threshold_seconds": 1800,
            "total_rx_bytes": total_rx, "total_tx_bytes": total_tx,
            "total_traffic_bytes": total_rx + total_tx,
            "total_rx_human": bytes_to_human(total_rx),
            "total_tx_human": bytes_to_human(total_tx),
            "total_traffic_human": bytes_to_human(total_rx + total_tx),
            "vpn_today_bytes": vpn_today, "vpn_week_bytes": vpn_week, "vpn_month_bytes": vpn_month,
            "vpn_year_bytes": vpn_year, "vpn_saved_total_bytes": vpn_saved_total,
            "vpn_today_human": bytes_to_human(vpn_today), "vpn_week_human": bytes_to_human(vpn_week),
            "vpn_month_human": bytes_to_human(vpn_month), "vpn_year_human": bytes_to_human(vpn_year),
            "vpn_saved_total_human": bytes_to_human(vpn_saved_total),
            "traffic_warn_bytes": read_settings().get("traffic_warn_gb", 30) * 1024 * 1024 * 1024,
            "timezone": read_settings().get("timezone", "auto"),
            "top_user_now": top_user_now,
            "online_peers": online_peers,
        },
    }

@app.get("/peers")
def peers(x_api_token: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    data = read_clients_data()
    clients = data.get("clients", {})
    peers_list = [
        _build_peer_entry(c, cid)
        for cid, c in clients.items()
        if isinstance(c, dict)
    ]
    peers_list.sort(key=lambda p: p.get("ip") or "")
    online_count = sum(1 for p in peers_list if p["online"])
    best = None
    for p in peers_list:
        if not p.get("online"): continue
        bt = int(p.get("today_total_bytes") or 0)
        if not best or bt > best["today_total_bytes"]:
            best = {"name": p["name"], "ip": p["ip"], "today_total_bytes": bt,
                    "today_total_human": p.get("today_total_human", "0 B")}
    top_user_now = {"active": bool(best), "threshold_mbps": 1.0, "active_peer_count": online_count,
                     "active_peer_keys": [], "active_peer_threshold_mbps": 0.01, "last_event": {}}
    if best:
        top_user_now.update(best)
        top_user_now["ts"] = int(time.time())
    return {
        "interface": "xray",
        "peers": peers_list,
        "peer_count": len(peers_list),
        "online_peer_count": online_count,
        "enabled_peer_count": sum(1 for p in peers_list if p["enabled"]),
        "disabled_peer_count": sum(1 for p in peers_list if not p["enabled"]),
        "online_threshold_seconds": 1800,
        "active_peer_count": online_count,
        "top_user_now": top_user_now,
    }

@app.post("/peer/create")
def peer_create(
    payload: Dict[str, Any] = Body(...),
    x_api_token: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    name = str(payload.get("name", "")).strip()
    if not name:
        raise HTTPException(status_code=400, detail="Client name is required")
    if not NAME_RE.match(name):
        raise HTTPException(status_code=400, detail="Client name contains invalid characters")
    data = read_clients_data()
    clients = data.setdefault("clients", {})
    for client in clients.values():
        if isinstance(client, dict) and client.get("name") == name:
            raise HTTPException(status_code=409, detail=f"Client already exists: {name}")
    client_id = str(uuid_mod.uuid4())
    address = allocate_next_client_ip(data)
    backup_path = f"{CLIENTS_FILE}.bak-{int(time.time())}"
    shutil.copy2(CLIENTS_FILE, backup_path)
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    clients[client_id] = {
        "name": name, "address": address,
        "xray_uuid": str(uuid_mod.uuid4()),
        "createdAt": now, "updatedAt": now,
        "enabled": True, "protected": False, "role": "user",
    }
    atomic_json_write(CLIENTS_FILE, data, backup=True)
    log_activity("create", name, client_id, address, {"backup": backup_path})
    sync_xray_config_background()
    config_changed(f"peer-created:{name}")
    return {"created": True, "peer": name, "ip": address, "client_id": client_id}

@app.delete("/peer/{client_id}")
def peer_delete(
    client_id: str, x_api_token: Optional[str] = Header(default=None)
) -> Dict[str, Any]:
    item = get_client(client_id)
    data = item["data"]
    client = item["client"]
    name = client.get("name", client_id)
    address = client.get("address", "")
    if client.get("protected", False):
        log_activity("delete_blocked", name, client_id, address, {"reason": "Protected peer"})
        raise HTTPException(status_code=403, detail="Protected peer")
    backup_path = f"{CLIENTS_FILE}.bak-{int(time.time())}"
    shutil.copy2(CLIENTS_FILE, backup_path)
    data.get("clients", {}).pop(client_id, None)
    atomic_json_write(CLIENTS_FILE, data, backup=True)
    log_activity("delete", name, client_id, address, {"backup": backup_path})
    sync_xray_config_background()
    config_changed(f"peer-deleted:{name}")
    return {"deleted": True, "peer": name, "ip": address, "client_id": client_id, "backup": backup_path}

@app.post("/peer/{client_id}/disable")
def peer_disable(
    client_id: str, x_api_token: Optional[str] = Header(default=None)
) -> Dict[str, Any]:
    item = get_client(client_id)
    data = item["data"]
    client = item["client"]
    name = client.get("name", client_id)
    address = client.get("address", "")
    public_key = client.get("publicKey", "")
    if client.get("protected", False):
        raise HTTPException(status_code=403, detail="Protected peer")
    backup_path = f"{CLIENTS_FILE}.bak-{int(time.time())}"
    shutil.copy2(CLIENTS_FILE, backup_path)
    client["enabled"] = False
    atomic_json_write(CLIENTS_FILE, data, backup=True)
    log_activity("disable", name, client_id, address, {"backup": backup_path})
    sync_xray_config_background()
    return {"disabled": True, "peer": name, "ip": address, "client_id": client_id, "backup": backup_path}

@app.post("/peer/{client_id}/enable")
def peer_enable(
    client_id: str, x_api_token: Optional[str] = Header(default=None)
) -> Dict[str, Any]:
    item = get_client(client_id)
    data = item["data"]
    client = item["client"]
    name = client.get("name", client_id)
    address = client.get("address", "")
    backup_path = f"{CLIENTS_FILE}.bak-{int(time.time())}"
    shutil.copy2(CLIENTS_FILE, backup_path)
    client["enabled"] = True
    atomic_json_write(CLIENTS_FILE, data, backup=True)
    log_activity("enable", name, client_id, address, {"backup": backup_path})
    sync_xray_config_background()
    return {"enabled": True, "peer": name, "ip": address, "client_id": client_id, "backup": backup_path}

@app.post("/peer/{client_id}/name")
def peer_rename(
    client_id: str,
    payload: Dict[str, Any] = Body(default={}),
    x_api_token: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
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
    log_activity("rename", old_name, client_id, client.get("address", ""),
                 {"old_name": old_name, "new_name": new_name})
    return {"ok": True, "client_id": client_id, "name": new_name}

@app.post("/peer/{client_id}/role")
def peer_set_role(
    client_id: str,
    payload: Dict[str, Any] = Body(default={}),
    x_api_token: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    role = str(payload.get("role", "")).strip()
    if role not in ("admin", "user"):
        raise HTTPException(status_code=400, detail="Role must be 'admin' or 'user'")
    item = get_client(client_id)
    data = item["data"]
    client = item["client"]
    client["role"] = role
    atomic_json_write(CLIENTS_FILE, data, backup=True)
    log_activity("role_change", client.get("name", client_id), client_id,
                 client.get("address", ""), {"role": role})
    config_changed(f"peer-role:{client_id}:{role}")
    return {"ok": True, "client_id": client_id, "role": role}

@app.post("/peer/{client_id}/protect")
def peer_protect(
    client_id: str,
    payload: Dict[str, Any] = Body(default={}),
    x_api_token: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    protected = bool(payload.get("protected", True))
    item = get_client(client_id)
    data = item["data"]
    client = item["client"]
    name = client.get("name", client_id)
    client["protected"] = protected
    atomic_json_write(CLIENTS_FILE, data, backup=True)
    log_activity("protect" if protected else "unprotect", name, client_id,
                 client.get("address", ""), {"protected": protected})
    return {"ok": True, "client_id": client_id, "protected": protected}

@app.get("/peer/{client_id}/config")
def peer_config(
    client_id: str,
    proto: Optional[str] = Query(default="reality"),
    x_api_token: Optional[str] = Header(default=None),
    token: Optional[str] = Query(default=None),
):
    link = build_xray_link(client_id, proto)
    return Response(
        content=link,
        media_type="text/plain; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{client_id}-{proto}.txt"'
        },
    )

@app.get("/peer/{client_id}/qr")
def peer_qr(
    client_id: str,
    proto: Optional[str] = Query(default="reality"),
    x_api_token: Optional[str] = Header(default=None),
    token: Optional[str] = Query(default=None),
):
    link = build_xray_link(client_id, proto)
    if not link:
        raise HTTPException(400, "No config for this protocol")
    img = qrcode.make(link)
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    return Response(content=buffer.getvalue(), media_type="image/png")

@app.get("/parental/rules")
def parental_get_rules(
    x_api_token: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    return {"rules": {}}

def _get_xray_peer_key(client_id: str) -> str:
    data = read_clients_data()
    client = data.get("clients", {}).get(client_id)
    if not client:
        for cid, c in data.get("clients", {}).items():
            if isinstance(c, dict) and (c.get("xray_uuid") == client_id or c.get("name") == client_id):
                return c.get("xray_uuid", client_id)
        return ""
    return client.get("xray_uuid", "")

@app.get("/peer/{client_id}/traffic/days")
def peer_traffic_days(
    client_id: str, x_api_token: Optional[str] = Header(default=None)
) -> Dict[str, Any]:
    peer_key = _get_xray_peer_key(client_id)
    if not peer_key: return {"days": []}
    cutoff = time.strftime("%Y-%m-%d", time.localtime(time.time() - 60 * 86400))
    with sqlite3.connect(TRAFFIC_DB_FILE, timeout=10) as db:
        rows = db.execute("SELECT period_key, rx, tx FROM traffic_totals WHERE public_key = ? AND period_type = 'day' AND period_key >= ? ORDER BY period_key ASC", (peer_key, cutoff)).fetchall()
    return {"days": [{"date": r[0], "rx": int(r[1]), "tx": int(r[2])} for r in rows]}

@app.get("/peer/{client_id}/traffic/hours")
def peer_traffic_hours(
    client_id: str,
    date: Optional[str] = Query(default=None),
    x_api_token: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    peer_key = _get_xray_peer_key(client_id)
    if not peer_key: return {"hours": []}
    if not date: date = today_key()
    with sqlite3.connect(TRAFFIC_DB_FILE, timeout=10) as db:
        rows = db.execute("SELECT period_key, rx, tx FROM traffic_totals WHERE public_key = ? AND period_type = 'hour' AND period_key LIKE ? ORDER BY period_key ASC", (peer_key, date + "%")).fetchall()
        if rows: return {"hours": [{"h": r[0].split("-")[-1], "rx": int(r[1]), "tx": int(r[2])} for r in rows]}
        if date == today_key():
            day = read_traffic_total(db, peer_key, "day", date); total_rx, total_tx = day["rx"], day["tx"]
            current_hour = int(time.strftime("%H", time.gmtime()))
            if total_rx or total_tx:
                cnt = current_hour + 1
                return {"hours": [{"h": f"{h:02d}", "rx": total_rx // cnt, "tx": total_tx // cnt} for h in range(cnt)]}
    return {"hours": []}

@app.get("/traffic/global/hours")
def global_traffic_hours(
    x_api_token: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    today = today_key()
    with sqlite3.connect(TRAFFIC_DB_FILE, timeout=10) as db:
        rows = db.execute("SELECT period_key, SUM(rx), SUM(tx) FROM traffic_totals WHERE period_type = 'hour' AND period_key LIKE ? GROUP BY period_key ORDER BY period_key ASC", (today + "%",)).fetchall()
        if rows: return {"hours": [{"h": r[0].split("-")[-1], "rx": int(r[1]), "tx": int(r[2])} for r in rows]}
    return {"hours": []}

@app.get("/traffic/global/days")
def global_traffic_days(
    x_api_token: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    cutoff = time.strftime("%Y-%m-%d", time.localtime(time.time() - 365 * 86400))
    with sqlite3.connect(TRAFFIC_DB_FILE, timeout=10) as db:
        rows = db.execute("SELECT period_key, SUM(rx), SUM(tx) FROM traffic_totals WHERE period_type = 'day' AND period_key >= ? GROUP BY period_key ORDER BY period_key ASC", (cutoff,)).fetchall()
    return {"days": [{"date": r[0], "rx": int(r[1]), "tx": int(r[2])} for r in rows]}

@app.post("/peer/{client_id}/speed-limit")
def peer_speed_limit(
    client_id: str,
    payload: Dict[str, Any] = Body(default={}),
    x_api_token: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    return {"ok": True, "peer": client_id, "speed_limited": True}

@app.post("/peer/{client_id}/speed-normal")
def peer_speed_normal(
    client_id: str, x_api_token: Optional[str] = Header(default=None)
) -> Dict[str, Any]:
    return {"ok": True, "peer": client_id, "speed_limited": False}

@app.put("/parental/rules/{client_id}")
def parental_set_rule(
    client_id: str,
    payload: Dict[str, Any] = Body(default={}),
    x_api_token: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    return {"ok": True, "client_id": client_id, "enabled": bool(payload.get("enabled", False))}

@app.get("/xray/links")
def xray_links(x_api_token: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    data = read_clients_data()
    clients = data.get("clients", {})
    links = {}
    for cid, client in clients.items():
        if not isinstance(client, dict) or not client.get("enabled", True):
            continue
        uid = client.get("xray_uuid", "")
        if not uid:
            continue
        name = client.get("name", cid)
        links[cid] = {
            "name": name,
            "uuid": uid,
            "reality": build_xray_link(cid, "reality"),
            "ws": build_xray_link(cid, "ws"),
            "xhttp": build_xray_link(cid, "xhttp"),
        }
    return {"links": links}

@app.post("/maintenance/restart-vpn")
def maintenance_restart_vpn(
    x_api_token: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    try:
        sync_xray_config()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Xray restart failed: {e}")
    log_activity("maintenance", "system", "", "", {"action": "restart-vpn"})
    return {"ok": True, "action": "restart-vpn", "output": "xray restarted"}

@app.get("/diagnostics")
def diagnostics(x_api_token: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    xray_ok = try_run_cmd(["pidof", "xray"], timeout=5) is not None
    internet_ok = try_run_cmd(["ip", "route", "get", "8.8.8.8"], timeout=5) is not None
    info = backup_file_info("latest.wgadmin")
    backup_ok = info.get("exists") and (time.time() - info.get("mtime", 0)) < 3 * 86400
    health = _read_health()
    now = int(time.time())
    has_issue = not (xray_ok and internet_ok and backup_ok)
    if has_issue:
        health["last_issue_ts"] = now
    if has_issue and health.get("healthy_since") is not None:
        health["healthy_since"] = None
    elif not has_issue and health.get("healthy_since") is None:
        health["healthy_since"] = now
    _write_health(health)
    days_ok = _days_since(health.get("healthy_since")) if health.get("healthy_since") else 0
    cpu_pct = 0.0
    try:
        with open("/proc/stat") as f:
            parts = f.readline().strip().split()
        if parts and parts[0] == "cpu" and len(parts) >= 5:
            user, nice, system, idle = int(parts[1]), int(parts[2]), int(parts[3]), int(parts[4])
            iowait = int(parts[5]) if len(parts) > 5 else 0
            irq = int(parts[6]) if len(parts) > 6 else 0
            softirq = int(parts[7]) if len(parts) > 7 else 0
            steal = int(parts[8]) if len(parts) > 8 else 0
            total = user + nice + system + idle + iowait + irq + softirq + steal
            if total > idle:
                cpu_pct = round((total - idle) / total * 100, 1)
    except Exception:
        pass
    mem_pct = 0.0
    mem_total = 0
    mem_avail = 0
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    mem_total = int(line.split()[1])
                elif line.startswith("MemAvailable:"):
                    mem_avail = int(line.split()[1])
        if mem_total:
            mem_pct = round((1 - mem_avail / mem_total) * 100, 1)
    except Exception:
        pass
    disk_pct = 0.0
    disk_total = 0
    disk_used = 0
    try:
        out = subprocess.run(
            ["df", "-B1", "/"], capture_output=True, text=True, timeout=5
        ).stdout
        lines = out.strip().splitlines()
        if len(lines) >= 2:
            parts = lines[1].split()
            if len(parts) >= 3:
                disk_total = int(parts[1])
                disk_used = int(parts[2])
            if disk_total:
                disk_pct = round(disk_used / disk_total * 100, 1)
    except Exception:
        pass
    return {
        "wg": xray_ok,
        "internet": internet_ok,
        "backup": backup_ok,
        "peers": False,
        "all_ok": xray_ok and internet_ok and backup_ok,
        "days_ok": days_ok,
        "checks": {
            "wg": "ok" if xray_ok else "fail",
            "internet": "ok" if internet_ok else "fail",
            "backup": "ok" if backup_ok else "fail",
            "peers": "ok" if False else "fail",
        },
        "cpu_pct": cpu_pct,
        "mem_pct": mem_pct,
        "mem_total": mem_total,
        "mem_avail": mem_avail,
        "disk_pct": disk_pct,
        "disk_total": disk_total,
        "disk_used": disk_used,
        "awg": None,
    }
