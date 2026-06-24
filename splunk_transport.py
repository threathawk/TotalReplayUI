"""Splunk connection helpers: scheme selection, TLS, and readable network errors."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

import requests


def normalize_splunk_host(host: str) -> str:
    """Strip scheme/path/port if user pasted a full Splunk or HEC URL into host field."""
    h = (host or "").strip()
    if not h:
        return ""
    if "://" in h:
        parsed = urlparse(h if "://" in h else f"https://{h}")
        h = (parsed.hostname or "").strip()
    h = h.split("/")[0].strip()
    return h


def resolve_hec_host(cfg: dict) -> str:
    return normalize_splunk_host(
        str(cfg.get("splunk_hec_host") or cfg.get("splunk_host") or "").strip()
    )


def resolve_mgmt_host(cfg: dict) -> str:
    return normalize_splunk_host(
        str(cfg.get("splunk_mgmt_host") or cfg.get("splunk_host") or "").strip()
    )


DEFAULT_INDEX_PLANNER_SEARCH = (
    "| tstats count where earliest=-365d latest=now index=* "
    "by index sourcetype | fields - count"
)


def mgmt_use_https(cfg: dict) -> bool:
    """
    Management API (8089) scheme. Defaults to HTTPS — Splunk resets plain HTTP on 8089.
    HEC (8088) still uses the global ``use_https`` setting in app.py.
    """
    if "splunk_mgmt_use_https" in cfg:
        return bool(cfg["splunk_mgmt_use_https"])
    return True


def mgmt_verify_tls(cfg: dict) -> bool:
    return bool(cfg.get("verify_tls"))


def mgmt_scheme_candidates(cfg: dict) -> list[str]:
    """Ordered schemes to try for port 8089."""
    if mgmt_use_https(cfg):
        return ["https"]
    return ["http", "https"]


def is_connection_reset(exc: BaseException) -> bool:
    msg = str(exc).lower()
    if "connection reset" in msg or "connection aborted" in msg:
        return True
    cause = getattr(exc, "__cause__", None)
    if cause is not None and cause is not exc:
        return is_connection_reset(cause)
    if isinstance(exc, ConnectionResetError):
        return True
    return False


def format_request_error(exc: BaseException, url: str, *, tried_https: bool = False) -> str:
    """Turn low-level socket errors into actionable Splunk guidance."""
    if is_connection_reset(exc) and url.startswith("http://"):
        return (
            f"Connection reset by Splunk at {url}. "
            "Port 8089 usually requires HTTPS — enable "
            "'HTTPS for management API (8089)' in Settings (uncheck only if your Splunk uses plain HTTP)."
        )
    if isinstance(exc, requests.exceptions.SSLError):
        return (
            f"TLS handshake failed for {url}. "
            "Try disabling 'Verify TLS' for self-signed certificates, or match HTTP/HTTPS to your Splunk setup."
        )
    if tried_https and is_connection_reset(exc):
        return (
            f"Connection reset by Splunk at {url}. "
            "Check host, port 8089, firewall, and SSH tunnel (if enabled)."
        )
    return str(exc)


def is_jwt_token(token: str) -> bool:
    t = (token or "").strip()
    return t.startswith("eyJ") and t.count(".") >= 2
