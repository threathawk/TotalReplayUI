"""Splunk REST API: search jobs for index/sourcetype inventory (uses saved HEC + REST settings)."""

from __future__ import annotations

import json
import time
import xml.etree.ElementTree as ET
from typing import Any, Callable, Optional

import requests
import urllib3

from ssh_tunnel import ensure_mgmt_tunnel
from splunk_transport import (
    DEFAULT_INDEX_PLANNER_SEARCH,
    format_request_error,
    is_connection_reset,
    is_jwt_token,
    mgmt_scheme_candidates,
    mgmt_use_https,
    mgmt_verify_tls,
    resolve_hec_host,
    resolve_mgmt_host,
)

TSTATS_SEARCH = DEFAULT_INDEX_PLANNER_SEARCH
CONNECT_TIMEOUT_SEC = 15
JOB_POLL_INTERVAL_SEC = 3
DEFAULT_SEARCH_TIMEOUT_SEC = 900
INVENTORY_SEARCH_TIMEOUT_SEC = 900


def splunk_connection_summary(cfg: dict) -> dict[str, Any]:
    """Describe how sync/replay will reach Splunk from saved Settings."""
    hec_host = resolve_hec_host(cfg)
    mgmt_host = resolve_mgmt_host(cfg)
    hec_port = int(cfg.get("splunk_port") or 8088)
    mgmt_port = int(cfg.get("splunk_mgmt_port") or 8089)
    hec_scheme = "https" if cfg.get("use_https") else "http"
    mgmt_scheme = "https" if mgmt_use_https(cfg) else "http"
    tunnel = bool(cfg.get("ssh_enabled"))
    has_mgmt_token = bool((cfg.get("splunk_mgmt_token") or "").strip())
    has_hec_token = bool((cfg.get("hec_token") or "").strip())
    has_user = bool((cfg.get("splunk_username") or "").strip() and cfg.get("splunk_password"))
    return {
        "splunk_host": hec_host,
        "splunk_hec_host": hec_host,
        "splunk_mgmt_host": mgmt_host,
        "hec_url": f"{hec_scheme}://{hec_host}:{hec_port}/services/collector/raw" if hec_host else "",
        "mgmt_url": f"{mgmt_scheme}://{mgmt_host}:{mgmt_port}" if mgmt_host else "",
        "mgmt_port": mgmt_port,
        "hec_port": hec_port,
        "mgmt_use_https": mgmt_use_https(cfg),
        "ssh_tunnel": tunnel,
        "auth_via_mgmt_token": has_mgmt_token,
        "auth_via_hec_token": has_hec_token,
        "auth_via_username": has_user,
        "use_https": bool(cfg.get("use_https")),
    }


def _mgmt_host_port(cfg: dict, log_fn=None) -> tuple[str, int]:
    host = resolve_mgmt_host(cfg)
    if not host:
        raise ValueError("Splunk management API host is not configured in Settings")
    mgmt_port = int(cfg.get("splunk_mgmt_port") or 8089)

    if cfg.get("ssh_enabled"):
        ok, msg, local_port = ensure_mgmt_tunnel(cfg, log=log_fn)
        if not ok or local_port is None:
            raise RuntimeError(msg or "SSH management tunnel failed")
        if log_fn:
            log_fn(
                f"Splunk REST: via SSH tunnel → 127.0.0.1:{local_port} "
                f"(remote :{mgmt_port})"
            )
        return "127.0.0.1", local_port

    if log_fn:
        log_fn(f"Splunk REST: direct {host}:{mgmt_port}")
    return host, mgmt_port


def _mgmt_base_urls(cfg: dict, log_fn=None) -> list[str]:
    """Base URLs to try (scheme may fallback http → https)."""
    host, port = _mgmt_host_port(cfg, log_fn=log_fn)
    return [f"{scheme}://{host}:{port}" for scheme in mgmt_scheme_candidates(cfg)]


def _auth_header_variants(cfg: dict) -> list[tuple[str, dict[str, str]]]:
    """
    Auth for management port (8089): dedicated mgmt token first, then user/pass, then HEC token.
    """
    mgmt_token = (cfg.get("splunk_mgmt_token") or "").strip()
    hec_token = (cfg.get("hec_token") or "").strip()
    user = (cfg.get("splunk_username") or "").strip()
    password = cfg.get("splunk_password") or ""
    variants: list[tuple[str, dict[str, str]]] = []

    def _add_token_variants(token: str, prefix: str) -> None:
        if is_jwt_token(token):
            variants.append(
                (f"{prefix} (Bearer JWT)", {"Authorization": f"Bearer {token}"})
            )
        else:
            variants.append(
                (f"{prefix} (Splunk scheme)", {"Authorization": f"Splunk {token}"})
            )
            variants.append(
                (f"{prefix} (Bearer)", {"Authorization": f"Bearer {token}"})
            )

    if mgmt_token:
        _add_token_variants(mgmt_token, "Management API token")
    if user and password:
        variants.append(("username/password (session key)", {}))
    if hec_token and hec_token != mgmt_token:
        _add_token_variants(hec_token, "HEC token fallback")
    return variants


def _login_session_key(cfg: dict, base: str, verify: bool) -> str:
    user = (cfg.get("splunk_username") or "").strip()
    password = cfg.get("splunk_password") or ""
    r = requests.post(
        f"{base}/services/auth/login",
        data={"username": user, "password": password},
        verify=verify,
        timeout=30,
    )
    if r.status_code != 200:
        raise RuntimeError(f"Splunk login failed: HTTP {r.status_code} {r.text[:300]}")
    root = ET.fromstring(r.text)
    sk = root.findtext(".//sessionKey")
    if not sk:
        raise RuntimeError("Splunk login did not return a session key")
    return sk.strip()


def _request_timeout(read_sec: int) -> tuple[int, int]:
    return (CONNECT_TIMEOUT_SEC, read_sec)


def _splunk_cloud_rest_hint(url: str) -> str:
    if "splunkcloud.com" not in (url or "").lower():
        return ""
    return (
        " Splunk Cloud: port 8089 must be allowlisted for your IP "
        "(ACS search-api/ipallowlists or Splunk Support). "
        "Large tstats searches can take several minutes."
    )


def _normalize_search(search: str) -> str:
    s = (search or "").strip()
    if not s:
        return ""
    return s if s.startswith("|") else f"search {s}"


def _parse_job_sid(body: Any, raw_text: str = "") -> str:
    if isinstance(body, dict):
        sid = body.get("sid")
        if sid:
            return str(sid).strip()
        for ent in body.get("entry") or []:
            if not isinstance(ent, dict):
                continue
            name = ent.get("name")
            if name:
                return str(name).strip()
            content = ent.get("content") or {}
            if isinstance(content, dict) and content.get("sid"):
                return str(content["sid"]).strip()
    if raw_text:
        try:
            root = ET.fromstring(raw_text)
            sid = root.findtext(".//sid") or root.findtext(".//name")
            if sid:
                return sid.strip()
        except ET.ParseError:
            pass
    return ""


def _create_search_job(
    base: str,
    headers: dict[str, str],
    search: str,
    verify: bool,
    *,
    log_fn=None,
) -> str:
    if not verify:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    r = requests.post(
        f"{base}/services/search/jobs",
        headers=headers,
        data={
            "search": _normalize_search(search),
            "exec_mode": "normal",
            "output_mode": "json",
        },
        verify=verify,
        timeout=_request_timeout(120),
    )
    if r.status_code not in (200, 201):
        raise RuntimeError(f"HTTP {r.status_code}: {(r.text or '')[:400]}")
    sid = ""
    try:
        sid = _parse_job_sid(r.json(), r.text)
    except json.JSONDecodeError:
        sid = _parse_job_sid({}, r.text)
    if not sid:
        raise RuntimeError(f"Search job created but no sid in response: {(r.text or '')[:300]}")
    if log_fn:
        log_fn(f"  Search job created (sid={sid[:24]}...)")
    return sid


def _wait_for_search_job(
    base: str,
    headers: dict[str, str],
    sid: str,
    verify: bool,
    *,
    log_fn=None,
    timeout_sec: int,
) -> None:
    deadline = time.monotonic() + timeout_sec
    last_state = ""
    logged_wait = False
    while time.monotonic() < deadline:
        r = requests.get(
            f"{base}/services/search/jobs/{sid}",
            headers=headers,
            params={"output_mode": "json"},
            verify=verify,
            timeout=_request_timeout(60),
        )
        if r.status_code != 200:
            raise RuntimeError(f"Job status HTTP {r.status_code}: {(r.text or '')[:300]}")
        content: dict[str, Any] = {}
        try:
            data = r.json()
            entries = data.get("entry") or []
            if entries and isinstance(entries[0], dict):
                raw_content = entries[0].get("content")
                if isinstance(raw_content, dict):
                    content = raw_content
        except json.JSONDecodeError:
            pass

        is_done = content.get("isDone") in (True, "1", 1, "true")
        dispatch = str(content.get("dispatchState") or content.get("status") or "")
        if dispatch and dispatch != last_state:
            if log_fn:
                log_fn(f"  Search state: {dispatch}")
            last_state = dispatch
        elif log_fn and not logged_wait:
            log_fn("  Search queued/running (tstats on Splunk Cloud may take several minutes)...")
            logged_wait = True

        if is_done:
            if content.get("isFailed") in (True, "1", 1, "true"):
                messages = content.get("messages") or content.get("msg") or "search failed"
                raise RuntimeError(f"Splunk search failed: {messages}")
            if log_fn:
                result_count = content.get("resultCount") or content.get("eventCount") or "?"
                log_fn(f"  Search complete (results={result_count})")
            return
        time.sleep(JOB_POLL_INTERVAL_SEC)

    raise RuntimeError(
        f"Splunk search timed out after {timeout_sec}s (job {sid}). "
        "Try a narrower time range (e.g. earliest=-1h) or add | head 10000 to your SPL."
        + _splunk_cloud_rest_hint(base)
    )


def _fetch_search_job_results(
    base: str,
    headers: dict[str, str],
    sid: str,
    verify: bool,
    *,
    log_fn=None,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    offset = 0
    page = 50000
    while True:
        r = requests.get(
            f"{base}/services/search/jobs/{sid}/results",
            headers=headers,
            params={"output_mode": "json", "count": page, "offset": offset},
            verify=verify,
            timeout=_request_timeout(180),
        )
        if r.status_code != 200:
            raise RuntimeError(f"Results HTTP {r.status_code}: {(r.text or '')[:300]}")
        try:
            data = r.json()
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Invalid JSON from Splunk results: {e}") from e
        batch = data.get("results") or []
        if not batch:
            break
        for row in batch:
            if isinstance(row, dict):
                rows.append(row)
        if log_fn and len(batch) >= page:
            log_fn(f"  Fetched {len(rows)} rows...")
        if len(batch) < page:
            break
        offset += len(batch)
    if log_fn:
        log_fn(f"  Parsed {len(rows)} result row(s)")
    return rows


def _run_search_job(
    base: str,
    headers: dict[str, str],
    search: str,
    verify: bool,
    *,
    log_fn=None,
    timeout_sec: int,
) -> list[dict[str, Any]]:
    sid = _create_search_job(base, headers, search, verify, log_fn=log_fn)
    _wait_for_search_job(
        base, headers, sid, verify, log_fn=log_fn, timeout_sec=timeout_sec,
    )
    return _fetch_search_job_results(base, headers, sid, verify, log_fn=log_fn)


def _post_mgmt_search(
    base: str,
    headers: dict[str, str],
    search_data: dict[str, str],
    verify: bool,
    timeout_sec: int,
) -> requests.Response:
    if not verify:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    return requests.post(
        f"{base}/services/search/jobs/export",
        headers=headers,
        data=search_data,
        verify=verify,
        timeout=_request_timeout(timeout_sec),
        stream=True,
    )


def run_search(
    cfg: dict,
    search: str,
    *,
    log_fn=None,
    timeout_sec: int = DEFAULT_SEARCH_TIMEOUT_SEC,
) -> list[dict[str, Any]]:
    """Run SPL via async search job (poll + fetch). More reliable than export on Splunk Cloud."""
    verify = mgmt_verify_tls(cfg)
    bases = _mgmt_base_urls(cfg, log_fn=log_fn)
    variants = _auth_header_variants(cfg)
    if not variants:
        raise ValueError(
            "Save a Management API token (port 8089) in Settings, "
            "or optional Splunk username/password, "
            "or a HEC token with search permission."
        )

    if log_fn:
        log_fn(f"Splunk REST: {_normalize_search(search)[:80]}...")

    last_error = ""
    for base in bases:
        tried_https_fallback = len(bases) > 1 and base.startswith("https://")
        for label, extra_headers in variants:
            headers = dict(extra_headers)
            if not headers and "username" in label:
                try:
                    sk = _login_session_key(cfg, base, verify)
                    headers = {"Authorization": f"Splunk {sk}"}
                    label = "username/password session"
                except Exception as e:
                    last_error = format_request_error(e, base) + _splunk_cloud_rest_hint(base)
                    if log_fn:
                        log_fn(f"  Auth {label}: FAIL ({last_error})")
                    continue

            if log_fn:
                log_fn(f"  {base} — Auth: {label}...")

            try:
                rows = _run_search_job(
                    base,
                    headers,
                    search,
                    verify,
                    log_fn=log_fn,
                    timeout_sec=timeout_sec,
                )
            except requests.RequestException as e:
                last_error = format_request_error(
                    e, base, tried_https=tried_https_fallback,
                ) + _splunk_cloud_rest_hint(base)
                if log_fn:
                    log_fn(f"  Network error: {last_error}")
                if is_connection_reset(e) and base.startswith("http://"):
                    if log_fn:
                        log_fn("  Retrying with HTTPS...")
                    break
                continue
            except RuntimeError as e:
                last_error = str(e)
                if log_fn:
                    log_fn(f"  FAIL: {last_error}")
                continue

            if log_fn:
                log_fn(f"  Done ({label}) — {len(rows)} row(s)")
            return rows

    raise RuntimeError(
        (last_error or "Splunk REST authentication failed.")
        + " Enable HTTPS for management API (8089), verify host/port, and check your token."
        + _splunk_cloud_rest_hint(bases[0] if bases else "")
    )


def test_rest_connection(cfg: dict, *, log_fn=None) -> dict[str, Any]:
    """Quick REST check using saved HEC/REST settings (no full tstats)."""
    try:
        bases = _mgmt_base_urls(cfg, log_fn=log_fn)
        summary = splunk_connection_summary(cfg)
        run_search(
            cfg,
            "| tstats count WHERE earliest=-1h latest=now index=* | head 1",
            log_fn=log_fn,
            timeout_sec=60,
        )
        return {"ok": True, "mgmt_url": bases[0], **summary}
    except Exception as e:
        return {"ok": False, "error": str(e), **splunk_connection_summary(cfg)}


def fetch_index_sourcetypes(
    cfg: dict,
    *,
    search: Optional[str] = None,
    log_fn=None,
) -> list[dict[str, str]]:
    """Return [{index, sourcetype}, ...] from Splunk search (default: tstats inventory)."""
    spl = (search or cfg.get("index_planner_search") or TSTATS_SEARCH).strip()
    if not spl:
        spl = TSTATS_SEARCH
    if log_fn:
        conn = splunk_connection_summary(cfg)
        log_fn(
            f"Splunk sync: HEC host={conn['splunk_hec_host']} "
            f"REST {conn['mgmt_url']} "
            f"({'SSH tunnel' if conn['ssh_tunnel'] else 'direct'}) "
            f"auth={('mgmt token' if conn['auth_via_mgmt_token'] else 'HEC token' if conn['auth_via_hec_token'] else 'user/pass')}"
        )
        log_fn(f"Splunk search: {spl[:120]}{'...' if len(spl) > 120 else ''}")
    raw = run_search(cfg, spl, log_fn=log_fn, timeout_sec=INVENTORY_SEARCH_TIMEOUT_SEC)
    pairs: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for row in raw:
        idx = (row.get("index") or row.get("Index") or "").strip()
        st = (row.get("sourcetype") or row.get("Sourcetype") or "").strip()
        if not idx or not st or idx.startswith("_"):
            continue
        key = (idx, st)
        if key in seen:
            continue
        seen.add(key)
        pairs.append({"index": idx, "sourcetype": st})
    pairs.sort(key=lambda x: (x["index"].lower(), x["sourcetype"].lower()))
    return pairs


def _get_mgmt_json(
    cfg: dict,
    path: str,
    *,
    log_fn: Optional[Callable[[str], None]] = None,
    timeout_sec: int = 60,
) -> dict[str, Any]:
    """Authenticated GET on Splunk management API (8089)."""
    verify = mgmt_verify_tls(cfg)
    bases = _mgmt_base_urls(cfg, log_fn=log_fn)
    variants = _auth_header_variants(cfg)
    if not variants:
        raise ValueError(
            "Save a Management API token (port 8089) in Settings, "
            "or optional Splunk username/password, "
            "or a HEC token with index listing permission."
        )

    if not path.startswith("/"):
        path = "/" + path
    last_error = ""

    for base in bases:
        tried_https_fallback = len(bases) > 1 and base.startswith("https://")
        url = f"{base}{path}"
        for label, extra_headers in variants:
            headers = dict(extra_headers)
            if not headers and "username" in label:
                try:
                    sk = _login_session_key(cfg, base, verify)
                    headers = {"Authorization": f"Splunk {sk}"}
                    label = "username/password session"
                except Exception as e:
                    last_error = format_request_error(e, base)
                    if log_fn:
                        log_fn(f"  Auth {label}: FAIL ({last_error})")
                    continue

            if log_fn:
                log_fn(f"  GET {url} — {label}...")

            try:
                if not verify:
                    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                r = requests.get(
                    url, headers=headers, verify=verify,
                    timeout=_request_timeout(timeout_sec),
                )
            except requests.RequestException as e:
                last_error = format_request_error(e, base, tried_https=tried_https_fallback)
                if log_fn and is_connection_reset(e) and base.startswith("http://"):
                    log_fn("  Retrying with HTTPS...")
                continue

            if r.status_code != 200:
                last_error = f"HTTP {r.status_code}: {(r.text or '')[:300]}"
                if log_fn:
                    log_fn(f"  FAIL: {last_error}")
                continue

            try:
                return r.json()
            except json.JSONDecodeError as e:
                last_error = f"Invalid JSON from Splunk: {e}"
                if log_fn:
                    log_fn(f"  FAIL: {last_error}")
                continue

    raise RuntimeError(
        last_error or "Splunk REST request failed. Check management API settings."
    )


def fetch_splunk_index_names(
    cfg: dict,
    *,
    log_fn: Optional[Callable[[str], None]] = None,
) -> list[str]:
    """List index names from Splunk REST API /services/data/indexes."""
    if log_fn:
        log_fn("Splunk REST: listing indexes (/services/data/indexes)...")
    data = _get_mgmt_json(
        cfg,
        "/services/data/indexes?count=-1&search=disabled%3D0&output_mode=json",
        log_fn=log_fn,
    )
    names: list[str] = []
    for ent in data.get("entry") or []:
        if not isinstance(ent, dict):
            continue
        n = (ent.get("name") or "").strip()
        if n and not n.startswith("_"):
            names.append(n)
    return sorted(set(names), key=str.lower)
