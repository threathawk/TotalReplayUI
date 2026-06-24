"""
SSH local port forward for Splunk HEC and Management REST API (paramiko-based).
"""

from __future__ import annotations

import select
import socket
import threading
from pathlib import Path
from typing import Any, Callable, Optional

import paramiko

from ssh_connect import build_ssh_connect_kwargs, open_ssh_client
from splunk_transport import resolve_hec_host, resolve_mgmt_host

LogFn = Optional[Callable[[str], None]]

_forwards: dict[str, dict[str, Any]] = {}
_tunnel_lock = threading.Lock()

SSH_CONNECT_TIMEOUT = 20
CHANNEL_OPEN_TIMEOUT = 15


def tunnel_status() -> dict[str, Any]:
    with _tunnel_lock:
        hec = _forwards.get("hec", {})
        mgmt = _forwards.get("mgmt", {})
        return {
            "connected": bool(hec.get("connected") or mgmt.get("connected")),
            "hec": dict(hec),
            "mgmt": dict(mgmt),
            "local_port": hec.get("local_port"),
            "mgmt_local_port": mgmt.get("local_port"),
            "error": hec.get("error") or mgmt.get("error"),
        }


def close_tunnel() -> None:
    with _tunnel_lock:
        for key in list(_forwards.keys()):
            _close_forward(key)


def _close_forward(key: str) -> None:
    fwd = _forwards.pop(key, None)
    if not fwd:
        return
    stop = fwd.get("stop")
    if stop is not None:
        stop.set()
    server = fwd.get("server")
    if server is not None:
        try:
            server.close()
        except OSError:
            pass
    client = fwd.get("client")
    if client is not None:
        try:
            client.close()
        except Exception:
            pass


def _say(log: LogFn, msg: str) -> None:
    if log:
        log(msg)


def _connect_ssh(cfg: dict, log: LogFn = None) -> paramiko.SSHClient:
    merged = dict(cfg)
    if not (merged.get("ssh_host") or "").strip():
        merged["ssh_host"] = (merged.get("splunk_host") or "").strip()
    kwargs = build_ssh_connect_kwargs(merged)
    host = kwargs["hostname"]
    port = kwargs["port"]
    user = kwargs["username"]
    _say(log, f"SSH: connecting to {user}@{host}:{port} (timeout {SSH_CONNECT_TIMEOUT}s)...")
    client = open_ssh_client(merged)
    _say(log, "SSH: session established")
    return client


def _relay_channels(src: socket.socket, dest: paramiko.Channel) -> None:
    try:
        while True:
            r, _, _ = select.select([src, dest], [], [], 1.0)
            if src in r:
                data = src.recv(4096)
                if not data:
                    break
                dest.send(data)
            if dest in r:
                data = dest.recv(4096)
                if not data:
                    break
                src.send(data)
    except Exception:
        pass
    finally:
        try:
            dest.close()
        except Exception:
            pass
        try:
            src.close()
        except OSError:
            pass


def _accept_loop(
    server: socket.socket,
    transport: paramiko.Transport,
    remote_host: str,
    remote_port: int,
    stop: threading.Event,
) -> None:
    server.settimeout(1.0)
    while not stop.is_set():
        try:
            client_sock, _ = server.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        try:
            chan = transport.open_channel(
                "direct-tcpip",
                (remote_host, remote_port),
                client_sock.getpeername(),
                timeout=CHANNEL_OPEN_TIMEOUT,
            )
        except Exception:
            try:
                client_sock.close()
            except OSError:
                pass
            continue
        if chan is None:
            try:
                client_sock.close()
            except OSError:
                pass
            continue
        threading.Thread(
            target=_relay_channels,
            args=(client_sock, chan),
            daemon=True,
        ).start()


def _remote_bind_host(cfg: dict, key: str) -> str:
    override = (cfg.get("ssh_remote_host") or "").strip()
    if override:
        return override
    if key == "mgmt":
        return resolve_mgmt_host(cfg)
    return resolve_hec_host(cfg)


def ensure_port_forward(
    cfg: dict,
    remote_port: int,
    *,
    key: str = "hec",
    log: LogFn = None,
) -> tuple[bool, str, Optional[int]]:
    """
    Forward a local port to remote_bind_host:remote_port through SSH.
    key: 'hec' (8088) or 'mgmt' (8089) — separate listeners.
    """
    if not cfg.get("ssh_enabled"):
        _close_forward(key)
        return True, "direct", None

    ssh_host = (cfg.get("ssh_host") or resolve_hec_host(cfg) or "").strip()
    ssh_user = (cfg.get("ssh_user") or "").strip()
    ssh_port = int(cfg.get("ssh_port") or 22)
    remote_bind_host = _remote_bind_host(cfg, key)
    sig = (ssh_host, ssh_port, ssh_user, remote_bind_host, remote_port, key)

    with _tunnel_lock:
        existing = _forwards.get(key, {})
        if existing.get("connected") and existing.get("signature") == sig:
            port = existing.get("local_port")
            _say(log, f"SSH: reusing {key} tunnel on 127.0.0.1:{port}")
            return True, "tunnel active", port

    _close_forward(key)

    try:
        client = _connect_ssh(cfg, log=log)
        transport = client.get_transport()
        if transport is None or not transport.is_active():
            raise RuntimeError("SSH transport is not active")

        _say(
            log,
            f"SSH: {key} forward 127.0.0.1:* → {remote_bind_host}:{remote_port}",
        )

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        server.listen(32)
        local_port = server.getsockname()[1]

        stop = threading.Event()
        thread = threading.Thread(
            target=_accept_loop,
            args=(server, transport, remote_bind_host, remote_port, stop),
            daemon=True,
        )
        thread.start()

        with _tunnel_lock:
            _forwards[key] = {
                "connected": True,
                "error": None,
                "local_port": local_port,
                "signature": sig,
                "server": server,
                "client": client,
                "stop": stop,
                "thread": thread,
            }

        _say(log, f"SSH: {key} tunnel on 127.0.0.1:{local_port}")
        return True, f"tunnel → 127.0.0.1:{local_port}", local_port
    except Exception as e:
        _close_forward(key)
        with _tunnel_lock:
            _forwards[key] = {"connected": False, "error": str(e), "local_port": None}
        return False, f"SSH tunnel failed: {e}", None


def ensure_tunnel(cfg: dict, log: LogFn = None) -> tuple[bool, str, Optional[int]]:
    """HEC forward (port from splunk_port, default 8088)."""
    port = int(cfg.get("splunk_port") or 8088)
    return ensure_port_forward(cfg, port, key="hec", log=log)


def ensure_mgmt_tunnel(cfg: dict, log: LogFn = None) -> tuple[bool, str, Optional[int]]:
    """Management REST forward (splunk_mgmt_port, default 8089)."""
    port = int(cfg.get("splunk_mgmt_port") or 8089)
    return ensure_port_forward(cfg, port, key="mgmt", log=log)
