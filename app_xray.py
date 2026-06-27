import io, json, os, re, secrets, shutil, subprocess, threading, time, uuid as uuid_mod
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
    _get_hostname, get_loadavg, get_cpu_usage, get_memory, get_disk_root, get_uptime,
    read_settings, write_settings, apply_timezone,
    log_activity, read_activity,
    _read_tokens_raw, _write_tokens_raw, _migrate_old_tokens, _reconcile_recovery_token,
    get_all_tokens, require_auth,
    read_clients_data, get_client, allocate_next_client_ip,
    _create_backup, _acquire_backup_lock, config_changed, backup_file_info,
    _do_restore, _read_health, _write_health, _days_since,
    _migrate_protected_peers, _migrate_peer_roles, NAME_RE,
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
    sync_xray_config()

_ONLINE_UUIDS: List[str] = []
_ONLINE_UUIDS_TS: float = 0

def get_online_uuids() -> List[str]:
    global _ONLINE_UUIDS, _ONLINE_UUIDS_TS
    now = time.time()
    if now - _ONLINE_UUIDS_TS < 15:
        return _ONLINE_UUIDS
    out = try_run_cmd(["xray", "api", "statsgetallonlineusers", "--server", f"127.0.0.1:{XRAY_API_PORT}"], timeout=5)
    if out:
        try:
            data = json.loads(out)
            if isinstance(data, dict):
                _ONLINE_UUIDS = data.get("users", [])
            elif isinstance(data, list):
                _ONLINE_UUIDS = data
            else:
                _ONLINE_UUIDS = []
        except json.JSONDecodeError:
            _ONLINE_UUIDS = [line.strip() for line in out.splitlines() if line.strip()]
    else:
        _ONLINE_UUIDS = []
    _ONLINE_UUIDS_TS = now
    return _ONLINE_UUIDS

def _build_peer_entry(client: Dict[str, Any], client_id: str) -> Dict[str, Any]:
    name = client.get("name", client_id)
    address = client.get("address", "")
    uid = client.get("xray_uuid", "")
    online = uid in get_online_uuids()
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
        "latest_handshake": int(time.time()) if online else 0,
        "latest_handshake_text": handshake_to_text(int(time.time())) if online else "never",
        "online": online,
        "is_active_now": online,
        "transfer_rx_bytes": 0, "transfer_tx_bytes": 0, "transfer_total_bytes": 0,
        "transfer_rx_human": bytes_to_human(0), "transfer_tx_human": bytes_to_human(0),
        "transfer_total_human": bytes_to_human(0),
        "today_rx_bytes": 0, "today_tx_bytes": 0, "today_total_bytes": 0,
        "today_rx_human": bytes_to_human(0), "today_tx_human": bytes_to_human(0),
        "today_total_human": bytes_to_human(0),
        "week_rx_bytes": 0, "week_tx_bytes": 0, "week_total_bytes": 0,
        "week_rx_human": bytes_to_human(0), "week_tx_human": bytes_to_human(0),
        "week_total_human": bytes_to_human(0),
        "month_rx_bytes": 0, "month_tx_bytes": 0, "month_total_bytes": 0,
        "month_rx_human": bytes_to_human(0), "month_tx_human": bytes_to_human(0),
        "month_total_human": bytes_to_human(0),
        "year_rx_bytes": 0, "year_tx_bytes": 0, "year_total_bytes": 0,
        "year_rx_human": bytes_to_human(0), "year_tx_human": bytes_to_human(0),
        "year_total_human": bytes_to_human(0),
        "saved_total_rx_bytes": 0, "saved_total_tx_bytes": 0, "saved_total_bytes": 0,
        "saved_total_human": bytes_to_human(0),
        "persistent_keepalive": "off",
        "has_preshared_key": False,
        "speed_limited": False,
        "speed_limit_rate": None,
        "today_total_human": bytes_to_human(0),
    }

@asynccontextmanager
async def lifespan(app):
    apply_timezone()
    _migrate_protected_peers()
    _migrate_peer_roles()
    _migrate_old_tokens()
    _reconcile_recovery_token()
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
    online_uuids = get_online_uuids()
    online_count = sum(1 for c in clients.values() if isinstance(c, dict) and c.get("xray_uuid", "") in online_uuids)
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
            "vpn_today_bytes": 0, "vpn_week_bytes": 0, "vpn_month_bytes": 0,
            "vpn_year_bytes": 0, "vpn_saved_total_bytes": 0,
            "vpn_today_human": bytes_to_human(0), "vpn_week_human": bytes_to_human(0),
            "vpn_month_human": bytes_to_human(0), "vpn_year_human": bytes_to_human(0),
            "vpn_saved_total_human": bytes_to_human(0),
            "traffic_warn_bytes": read_settings().get("traffic_warn_gb", 30) * 1024 * 1024 * 1024,
            "timezone": read_settings().get("timezone", "auto"),
            "top_user_now": {"active": False, "threshold_mbps": 1.0, "active_peer_count": 0,
                             "active_peer_keys": [], "active_peer_threshold_mbps": 0.01,
                             "last_event": {}},
            "online_peers": [],
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
    return {
        "interface": "xray",
        "peers": peers_list,
        "peer_count": len(peers_list),
        "online_peer_count": 0,
        "enabled_peer_count": sum(1 for p in peers_list if p["enabled"]),
        "disabled_peer_count": sum(1 for p in peers_list if not p["enabled"]),
        "online_threshold_seconds": 1800,
        "active_peer_count": 0,
        "top_user_now": {"active": False, "threshold_mbps": 1.0, "active_peer_count": 0,
                         "active_peer_keys": [], "active_peer_threshold_mbps": 0.01,
                         "last_event": {}},
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
    try:
        sync_xray_config()
    except Exception as e:
        print(f"[xray] sync after create: {e}")
    log_activity("create", name, client_id, address, {"backup": backup_path})
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
    try:
        sync_xray_config()
    except Exception as e:
        print(f"[xray] sync after delete: {e}")
    log_activity("delete", name, client_id, address, {"backup": backup_path})
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
    try:
        sync_xray_config()
    except Exception as e:
        print(f"[xray] sync after disable: {e}")
    log_activity("disable", name, client_id, address, {"backup": backup_path})
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
    try:
        sync_xray_config()
    except Exception as e:
        print(f"[xray] sync after enable: {e}")
    log_activity("enable", name, client_id, address, {"backup": backup_path})
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

@app.get("/peer/{client_id}/traffic/days")
def peer_traffic_days(
    client_id: str, x_api_token: Optional[str] = Header(default=None)
) -> Dict[str, Any]:
    return {"days": []}

@app.get("/peer/{client_id}/traffic/hours")
def peer_traffic_hours(
    client_id: str,
    date: Optional[str] = Query(default=None),
    x_api_token: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    return {"hours": []}

@app.get("/traffic/global/hours")
def global_traffic_hours(
    x_api_token: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    return {"hours": []}

@app.get("/traffic/global/days")
def global_traffic_days(
    x_api_token: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    return {"days": []}

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
