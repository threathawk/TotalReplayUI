"""Shared Paramiko SSH connection helpers for remote_client and ssh_tunnel."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

import paramiko

SSH_CONNECT_TIMEOUT = 30


def load_private_key(key_path: str) -> paramiko.PKey:
    from paramiko import ECDSAKey, Ed25519Key, RSAKey

    path = Path(key_path).expanduser()
    if not path.exists():
        raise FileNotFoundError(
            f"SSH key not found: {path} "
            "(path must exist on the machine running this web app)"
        )
    for key_cls in (Ed25519Key, RSAKey, ECDSAKey):
        try:
            return key_cls.from_private_key_file(str(path))
        except Exception:
            continue
    raise ValueError(f"Could not load SSH private key: {path}")


def default_ssh_key_paths() -> list[Path]:
    ssh_dir = Path.home() / ".ssh"
    names = ("id_ed25519", "id_rsa", "id_ecdsa")
    return [ssh_dir / n for n in names if (ssh_dir / n).exists()]


def ssh_credentials_hint(cfg: dict) -> Optional[str]:
    """Return an error message when SSH auth is likely missing."""
    host = (cfg.get("ssh_host") or "").strip()
    user = (cfg.get("ssh_user") or "").strip()
    if not host:
        return "SSH host is required."
    if not user:
        return "SSH username is required."
    password = (cfg.get("ssh_password") or "").strip()
    key_path = (cfg.get("ssh_key_path") or "").strip()
    if password or key_path:
        return None
    if default_ssh_key_paths():
        return None
    return (
        "SSH password or private key path is required. "
        "Key path must be on the host where this app runs (e.g. /home/ubuntu/.ssh/id_rsa), "
        "not on the remote lab VM. Re-enter the password and click Save settings."
    )


def build_ssh_connect_kwargs(cfg: dict) -> dict[str, Any]:
    host = (cfg.get("ssh_host") or "").strip()
    user = (cfg.get("ssh_user") or "").strip()
    port = int(cfg.get("ssh_port") or 22)
    password = (cfg.get("ssh_password") or "").strip() or None
    key_path = (cfg.get("ssh_key_path") or "").strip()

    hint = ssh_credentials_hint(cfg)
    if hint:
        raise ValueError(hint)

    kwargs: dict[str, Any] = {
        "hostname": host,
        "port": port,
        "username": user,
        "timeout": SSH_CONNECT_TIMEOUT,
        "banner_timeout": SSH_CONNECT_TIMEOUT,
        "auth_timeout": SSH_CONNECT_TIMEOUT,
    }
    if key_path:
        kwargs["pkey"] = load_private_key(key_path)
        kwargs["allow_agent"] = True
        kwargs["look_for_keys"] = False
        if password:
            kwargs["password"] = password
    elif password:
        kwargs["password"] = password
        kwargs["allow_agent"] = False
        kwargs["look_for_keys"] = False
    else:
        kwargs["allow_agent"] = True
        kwargs["look_for_keys"] = True
    return kwargs


def open_ssh_client(cfg: dict) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(**build_ssh_connect_kwargs(cfg))
    return client
