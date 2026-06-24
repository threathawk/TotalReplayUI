"""
Total Replay Web Console
------------------------
Flask UI for Splunk attack_data / TOTAL-REPLAY: local or remote (SSH) catalogs,
attack test panel, remote CLI replay, and HEC ingest.
"""

import os
import io
import re
import json
import time
import uuid
import queue
import sqlite3
import threading
import datetime as dt
from pathlib import Path
from typing import Any, Callable, Optional
from datetime import datetime, timezone

import yaml
import requests
from flask import Flask, request, jsonify, Response, render_template, stream_with_context
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.date import DateTrigger
from apscheduler.triggers.cron import CronTrigger

from ssh_connect import ssh_credentials_hint
from ssh_tunnel import close_tunnel, ensure_tunnel, tunnel_status
from splunk_client import fetch_splunk_index_names, test_rest_connection
from splunk_transport import (
    DEFAULT_INDEX_PLANNER_SEARCH,
    normalize_splunk_host,
    resolve_hec_host,
    resolve_mgmt_host,
)
from local_replay import (
    build_cached_catalog_local,
    local_paths,
    run_total_replay_local,
    sync_paths_from_local_config,
)
from detection_inventory import (
    aggregate_sourcetype_inventory,
    replay_items_for_sourcetypes,
)
from route_planner import (
    build_routing_matrix,
    preview_replay_routing,
    splunk_inventory_index,
    suggest_for_detection_sourcetype,
)
from index_mapping import (
    auto_match_mappings,
    collect_detection_sourcetypes_from_config,
    delete_mapping,
    init_mapping_tables,
    list_indexes,
    get_mapping_map,
    list_mappings,
    list_splunk_pairs,
    lookup_pair,
    resolve_index_and_sourcetype,
    resolve_index_for_item,
    sync_splunk_inventory,
    upsert_mapping,
    get_meta as mapping_get_meta,
)
from remote_client import (
    ensure_remote_total_replay_dir,
    close_ssh_session,
    ensure_ssh_client,
    is_remote_mode,
    remote_catalog_cached,
    remote_catalog_detections,
    remote_catalog_files,
    remote_detection_attack_data,
    remote_detection_catalog_full,
    run_total_replay_remote,
    ssh_fetch_file_bytes,
    ssh_session_status,
    sync_paths_from_remote_config,
    test_hec_from_remote,
    test_remote_ssh,
)


# ---------------------------------------------------------------------------
# Paths & globals
# ---------------------------------------------------------------------------

APP_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("TOTALREPLAY_DATA_DIR", str(APP_DIR / "data")))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "totalreplay.db"
CONFIG_PATH = Path(os.environ.get("TOTALREPLAY_CONFIG", str(DATA_DIR / "config.json")))
DOWNLOAD_CACHE = DATA_DIR / "downloads"
DOWNLOAD_CACHE.mkdir(exist_ok=True)

# Per-replay job event queues for Server-Sent Events (job_id -> Queue)
_log_queues: dict[str, "queue.Queue[str]"] = {}
_log_queues_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def db_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with db_conn() as c:
        c.executescript(
            """
            CREATE TABLE IF NOT EXISTS history (
                id            TEXT PRIMARY KEY,
                started_at    TEXT NOT NULL,
                finished_at   TEXT,
                status        TEXT NOT NULL,         -- running|success|partial|failed
                index_name    TEXT NOT NULL,
                splunk_host   TEXT NOT NULL,
                items_json    TEXT NOT NULL,         -- list of {label, status, message}
                summary       TEXT
            );

            CREATE TABLE IF NOT EXISTS schedules (
                id            TEXT PRIMARY KEY,
                name          TEXT NOT NULL,
                created_at    TEXT NOT NULL,
                trigger_type  TEXT NOT NULL,         -- date|cron
                trigger_spec  TEXT NOT NULL,         -- JSON: {run_date} or {cron fields}
                selection_json TEXT NOT NULL,        -- {mode, items, index}
                last_run_at   TEXT,
                last_status   TEXT
            );
            """
        )
        init_mapping_tables(c)


def load_config() -> dict:
    if CONFIG_PATH.exists():
        return json.loads(CONFIG_PATH.read_text())
    return {
        "splunk_host": "",
        "splunk_hec_host": "",
        "splunk_mgmt_host": "",
        "splunk_port": 8088,
        "hec_token": "",
        "use_https": False,
        "verify_tls": False,
        "default_index": "test",
        "security_content_path": "",
        "attack_data_path": "",
        "ssh_enabled": False,
        "ssh_host": "",
        "ssh_port": 22,
        "ssh_user": "",
        "ssh_password": "",
        "ssh_key_path": "",
        "ssh_remote_host": "",
        "connection_mode": "local",
        "remote_total_replay_dir": "",
        "remote_security_content_path": "",
        "remote_attack_data_path": "",
        "remote_python_cmd": "python3",
        "local_total_replay_dir": "",
        "local_python_cmd": "python3",
        "replay_engine": "hec",
        "splunk_mgmt_port": 8089,
        "splunk_mgmt_use_https": True,
        "splunk_mgmt_token": "",
        "splunk_username": "",
        "splunk_password": "",
        "use_index_mapping": True,
        "hec_force_time_now": False,
        "hec_add_data_source_field": True,
        "index_planner_search": DEFAULT_INDEX_PLANNER_SEARCH,
    }


def save_config(cfg: dict) -> None:
    CONFIG_PATH.write_text(json.dumps(cfg, indent=2))


def normalize_connection_mode(value) -> str:
    """Persist connection_mode as 'local' or 'remote'."""
    mode = str(value or "local").strip().lower()
    if mode in ("remote", "ssh", "true", "1"):
        return "remote"
    return "local"


_REQUEST_CONFIG_KEYS = (
    "connection_mode",
    "ssh_host",
    "ssh_port",
    "ssh_user",
    "ssh_password",
    "ssh_key_path",
    "remote_total_replay_dir",
    "remote_security_content_path",
    "remote_attack_data_path",
    "remote_python_cmd",
)


def merge_config_from_body(cfg: dict, body: Optional[dict]) -> dict:
    """Apply unsaved Settings form values (e.g. before Test SSH)."""
    merged = dict(cfg)
    if not body:
        return merged
    for key in _REQUEST_CONFIG_KEYS:
        if key not in body:
            continue
        val = body[key]
        if key == "ssh_password" and not str(val or "").strip():
            continue
        if key == "connection_mode":
            merged[key] = normalize_connection_mode(val)
        elif key == "ssh_port":
            merged[key] = int(val) if val else 22
        else:
            merged[key] = val
    return merged


def config_meta() -> dict[str, Any]:
    path = CONFIG_PATH.resolve()
    parent = path.parent
    return {
        "path": str(path),
        "exists": path.exists(),
        "writable": os.access(parent, os.W_OK),
    }


def apply_splunk_cloud_defaults(cfg: dict) -> dict:
    """
    Splunk Cloud HEC uses HTTPS on port 443 (not plain HTTP :8088).
    Auto-apply when hostname looks like *.splunkcloud.com.
    """
    hec_host = normalize_splunk_host(
        str(cfg.get("splunk_hec_host") or cfg.get("splunk_host") or "").strip()
    )
    mgmt_host = normalize_splunk_host(
        str(cfg.get("splunk_mgmt_host") or cfg.get("splunk_host") or "").strip()
    )
    if hec_host:
        cfg["splunk_hec_host"] = hec_host
        cfg["splunk_host"] = hec_host
    if mgmt_host:
        cfg["splunk_mgmt_host"] = mgmt_host
    if hec_host and "splunkcloud.com" in hec_host.lower():
        cfg["use_https"] = True
        port = int(cfg.get("splunk_port") or 8088)
        if port == 8088:
            cfg["splunk_port"] = 443
        if cfg.get("verify_tls") is None:
            cfg["verify_tls"] = True
    if mgmt_host and "splunkcloud.com" in mgmt_host.lower():
        cfg["splunk_mgmt_use_https"] = True
        if cfg.get("verify_tls") is None:
            cfg["verify_tls"] = True
    return cfg


def _format_hec_request_error(exc: BaseException, cfg: dict) -> str:
    err = str(exc)
    host = resolve_hec_host(cfg)
    if "nodename nor servname" in err.lower() or "failed to resolve" in err.lower() or "name or service not known" in err.lower():
        return (
            f"DNS lookup failed for Splunk host '{host}'. "
            "Check the HEC hostname in Splunk Cloud (Settings → Data Inputs → HTTP Event Collector). "
            "Use only the hostname (e.g. http-inputs-<stack>.splunkcloud.com), enable HTTPS, port 443. "
            "Ensure this machine has internet/DNS access and any required VPN is connected."
        )
    if cfg.get("ssh_enabled") and "timed out" in err.lower():
        err += (
            f" — Splunk at {host}:{cfg.get('splunk_port')} may be unreachable "
            f"from SSH host {cfg.get('ssh_host')}. Try unchecking 'SSH tunnel for HEC' if "
            "your machine can reach Splunk directly."
        )
    return err


def validate_hec_token(token: str) -> tuple[bool, Optional[str]]:
    """Return (ok, error_message). Rejects URLs and obvious non-tokens."""
    t = (token or "").strip()
    if not t:
        return False, "HEC token is required"
    if "://" in t or t.startswith("http"):
        return False, "This looks like a Splunk URL, not an HEC token. Use the token UUID from Settings → Data Inputs → HTTP Event Collector."
    if len(t) < 16:
        return False, "HEC token is too short. Paste the full token UUID from Splunk."
    if " " in t:
        return False, "HEC token must not contain spaces."
    return True, None


def _hec_auth_test(
    cfg: dict,
    index_name: Optional[str] = None,
    log_fn: Optional[Callable[[str], None]] = None,
) -> dict:
    """POST a tiny event to /services/collector/raw to verify token + index."""
    tok = (cfg.get("hec_token") or "").strip()
    ok_tok, tok_err = validate_hec_token(tok)
    if not ok_tok:
        return {"ok": False, "error": tok_err, "token_valid": False}

    index_name = index_name or cfg.get("default_index") or "test"
    try:
        url = _hec_url(cfg, log_fn=log_fn)
    except RuntimeError as e:
        return {"ok": False, "error": str(e), "token_valid": False}

    if log_fn:
        log_fn(f"HEC: POST test event to {url.split('?')[0]} (timeout 12s)...")

    headers = {"Authorization": f"Splunk {tok}"}
    params = {
        "index": index_name,
        "sourcetype": "_json",
        "source": "totalreplay-ui-test",
        "host": "hec-test",
    }
    try:
        r = requests.post(
            url, headers=headers, params=params, data=b'{"event":"totalreplay hec test"}',
            verify=bool(cfg.get("verify_tls")), timeout=12,
        )
    except requests.RequestException as e:
        return {"ok": False, "error": _format_hec_request_error(e, cfg), "token_valid": False}

    if r.status_code == 200:
        return {"ok": True, "status": 200, "token_valid": True, "index": index_name}

    hint = ""
    if r.status_code == 403:
        hint = (
            "403 Forbidden: invalid HEC token, token disabled, or index not allowed. "
            f"In Splunk, open the HEC token settings and allow index '{index_name}'."
        )
    elif r.status_code == 401:
        hint = "401 Unauthorized: HEC token is wrong or missing."

    return {
        "ok": False,
        "status": r.status_code,
        "error": hint or r.text.strip()[:300],
        "token_valid": r.status_code != 403,
        "body": r.text[:200],
    }


# ---------------------------------------------------------------------------
# Catalog builders
# ---------------------------------------------------------------------------

def _normalize_tag_list(val: Any) -> list[str]:
    if val is None:
        return []
    items = val if isinstance(val, list) else [val]
    out: list[str] = []
    for x in items:
        s = str(x).strip()
        if s:
            out.append(s)
    return out


def analytic_stories_from_detection(doc: dict) -> list[str]:
    """
    Splunk security_content analytic stories (use cases) from detection YAML.
    Reads tags.analytic_story and top-level analytic_story when present.
    """
    if not isinstance(doc, dict):
        return []
    stories: list[str] = []
    for src in (doc.get("tags"), doc):
        if not isinstance(src, dict):
            continue
        for key in ("analytic_story", "analytic_stories"):
            stories.extend(_normalize_tag_list(src.get(key)))
    return sorted(set(stories), key=str.lower)


def mitre_fields_from_tags(tags: Any) -> dict[str, list[str]]:
    """Extract MITRE technique and tactic IDs from security_content detection tags."""
    if not isinstance(tags, dict):
        tags = {}
    techniques: list[str] = []
    tactics: list[str] = []
    for key in ("mitre_attack_id", "mitre_attack_technique_id", "mitre_technique_id"):
        techniques.extend(_normalize_tag_list(tags.get(key)))
    for key in ("mitre_attack_tactic_id", "mitre_tactic_id", "mitre_attack_tactic"):
        tactics.extend(_normalize_tag_list(tags.get(key)))
    techniques = sorted(set(techniques), key=str.lower)
    tactics = sorted(set(tactics), key=str.lower)
    return {
        "mitre_techniques": techniques,
        "mitre_tactics": tactics,
        "mitre_attack_id": techniques,
    }


def sourcetypes_from_detection_tests(tests: list) -> list[str]:
    """Unique replay sourcetypes from detection test attack_data."""
    seen: list[str] = []
    for t in tests:
        if not isinstance(t, dict):
            continue
        for a in t.get("attack_data") or []:
            if isinstance(a, dict) and a.get("sourcetype"):
                st = str(a["sourcetype"]).strip()
                if st and st not in seen:
                    seen.append(st)
    return seen


def build_detection_catalog(security_content_path: str) -> list[dict]:
    """
    Walk security_content/detections/**/*.yml.
    Return entries that have tests with attack_data references.
    Each entry: {name, id, file, tests: [{name, attack_data: [{source, sourcetype, data}]}]}.
    """
    if not security_content_path.strip():
        return []
    root = Path(os.path.expanduser(security_content_path)).resolve()
    if not root.exists():
        return []

    detections_root = root if root.name == "detections" else root / "detections"
    if not detections_root.exists():
        # Fallback: search anywhere under the path
        detections_root = root

    results: list[dict] = []
    for yml in detections_root.rglob("*.yml"):
        try:
            doc = yaml.safe_load(yml.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(doc, dict):
            continue
        name = doc.get("name")
        det_id = doc.get("id")
        if not name or not det_id:
            continue

        tests = doc.get("tests") or []
        normalized_tests = []
        for t in tests:
            if not isinstance(t, dict):
                continue
            att = t.get("attack_data") or []
            if not att:
                continue
            normalized_tests.append({
                "name": t.get("name", ""),
                "attack_data": [
                    {
                        "source": a.get("source", ""),
                        "sourcetype": a.get("sourcetype", ""),
                        "data": a.get("data", ""),
                    }
                    for a in att if isinstance(a, dict) and a.get("data")
                ],
            })

        if not normalized_tests:
            continue

        tags = doc.get("tags") if isinstance(doc.get("tags"), dict) else {}
        mitre = mitre_fields_from_tags(tags)
        stories = analytic_stories_from_detection(doc)
        results.append({
            "name": name,
            "id": det_id,
            "file": str(yml.relative_to(root)),
            "analytic_story": stories,
            "use_cases": stories,
            **mitre,
            "sourcetypes": sourcetypes_from_detection_tests(normalized_tests),
            "tests": normalized_tests,
        })

    results.sort(key=lambda r: r["name"].lower())
    return results


def build_file_catalog(attack_data_path: str) -> list[dict]:
    """
    Walk attack_data/datasets/**/* for replayable log files.
    Includes .log, .json, .txt, .csv files (configurable list).
    Excludes Git LFS pointer stubs by checking file size > LFS_POINTER_MAX.
    """
    if not attack_data_path.strip():
        return []
    root = Path(os.path.expanduser(attack_data_path)).resolve()
    if not root.exists():
        return []

    datasets_root = root / "datasets" if (root / "datasets").exists() else root
    LFS_POINTER_MAX = 200  # bytes; real logs are always larger
    EXTS = {".log", ".json", ".txt", ".csv", ".xml"}

    items: list[dict] = []
    for p in datasets_root.rglob("*"):
        if not p.is_file():
            continue
        if p.suffix.lower() not in EXTS:
            continue
        try:
            size = p.stat().st_size
        except OSError:
            continue

        is_lfs_pointer = False
        if size <= LFS_POINTER_MAX:
            try:
                head = p.read_bytes()[:80]
                if head.startswith(b"version https://git-lfs"):
                    is_lfs_pointer = True
            except Exception:
                pass

        rel = p.relative_to(root)
        # Look for a sibling yml that describes this dataset, to infer source/sourcetype
        meta = _find_dataset_meta(p)
        items.append({
            "path": str(rel),
            "abs_path": str(p),
            "size": size,
            "is_lfs_pointer": is_lfs_pointer,
            "source": meta.get("source", ""),
            "sourcetype": meta.get("sourcetype", ""),
        })

    items.sort(key=lambda r: r["path"].lower())
    return items


def _find_dataset_meta(log_file: Path) -> dict:
    """Look for a .yml alongside the log file that lists this file in attack_data entries."""
    for yml in log_file.parent.glob("*.yml"):
        try:
            doc = yaml.safe_load(yml.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(doc, dict):
            continue
        for entry in (doc.get("attack_data") or []):
            if not isinstance(entry, dict):
                continue
            fname = entry.get("file_name") or ""
            if fname and log_file.name == Path(fname).name:
                return {
                    "source": entry.get("source", ""),
                    "sourcetype": entry.get("sourcetype", ""),
                }
    return {}


# ---------------------------------------------------------------------------
# Replay engine
# ---------------------------------------------------------------------------

def _emit(job_id: str, msg: str) -> None:
    with _log_queues_lock:
        q = _log_queues.get(job_id)
    if q is not None:
        q.put(msg)


def _splunk_endpoint(
    cfg: dict,
    log_fn: Optional[Callable[[str], None]] = None,
) -> tuple[bool, str, Optional[str], Optional[int]]:
    """Resolve host/port for HEC; start SSH tunnel when configured."""
    if cfg.get("ssh_enabled"):
        ok, msg, local_port = ensure_tunnel(cfg, log=log_fn)
        if not ok:
            return False, msg, None, None
        if local_port is not None:
            return True, msg, "127.0.0.1", local_port
    else:
        close_tunnel()
    cfg = apply_splunk_cloud_defaults(dict(cfg))
    host = resolve_hec_host(cfg)
    port = int(cfg.get("splunk_port") or 8088)
    if not host:
        return False, "Splunk HEC host not configured", None, None
    return True, "direct", host, port


def _hec_url(
    cfg: dict,
    path_suffix: str = "/services/collector/raw",
    log_fn: Optional[Callable[[str], None]] = None,
) -> str:
    ok, msg, host, port = _splunk_endpoint(cfg, log_fn=log_fn)
    if not ok or host is None or port is None:
        raise RuntimeError(msg or "Splunk endpoint unavailable")
    scheme = "https" if cfg.get("use_https") else "http"
    return f"{scheme}://{host}:{port}{path_suffix}"


_RE_XML_SYSTEM_TIME = re.compile(r"TimeCreated\s+SystemTime=['\"]([^'\"]+)['\"]", re.I)
_RE_XML_UTC_TIME = re.compile(r"<Data\s+Name=['\"]UtcTime['\"]>([^<]+)</Data>", re.I)
_RE_ISO_PREFIX = re.compile(r"^\s*(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)")
_RE_XML_EVENT_BLOCK = re.compile(r"(<Event\b[\s\S]*?</Event>)", re.I)
_RE_XML_EVENT_START = re.compile(r"(?=<Event\b)", re.I)


def _parse_time_to_epoch(ts: str) -> Optional[float]:
    s = (ts or "").strip()
    if not s:
        return None
    try:
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        return datetime.fromisoformat(s).timestamp()
    except Exception:
        pass
    # Common TOTAL-REPLAY / Sysmon UtcTime format: "YYYY-MM-DD HH:MM:SS.mmm"
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc).timestamp()
        except Exception:
            continue
    return None


def _best_effort_event_time(line: str) -> Optional[float]:
    """Extract event time from common log formats (best-effort)."""
    if not line:
        return None
    m = _RE_ISO_PREFIX.search(line)
    if m:
        return _parse_time_to_epoch(m.group(1))
    m = _RE_XML_SYSTEM_TIME.search(line)
    if m:
        return _parse_time_to_epoch(m.group(1))
    m = _RE_XML_UTC_TIME.search(line)
    if m:
        return _parse_time_to_epoch(m.group(1))
    return None


def _split_xml_windows_events(text: str) -> list[str]:
    """Split Sysmon/Windows XML where records are separated by </Event>."""
    s = (text or "").strip()
    if not s or "<Event" not in s or "</Event>" not in s:
        return []
    parts = re.split(r"</Event\s*>", s, flags=re.I)
    out: list[str] = []
    for part in parts:
        part = part.strip()
        if not part or not re.search(r"<\s*Event\b", part, re.I):
            continue
        if not part.lower().endswith("</event>"):
            part = part + "</Event>"
        out.append(part)
    return out


def _split_payload_records(text: str) -> list[str]:
    """
    Split incoming payload into per-event records.

    Handles:
    - Windows XML events (<Event>...</Event>), including concatenated blocks
    - line-delimited logs
    - JSON arrays (each element -> one event)
    """
    s = (text or "").strip()
    if not s:
        return []

    xml_records = _split_xml_windows_events(s)
    if xml_records:
        return xml_records

    # JSON array payload
    if s.startswith("["):
        try:
            parsed = json.loads(s)
            if isinstance(parsed, list):
                return [
                    json.dumps(item, separators=(",", ":")) if not isinstance(item, str) else item
                    for item in parsed
                ]
        except Exception:
            pass

    # Regex XML blocks (backup)
    if "<Event" in s and "</Event>" in s:
        blocks = [m.strip() for m in _RE_XML_EVENT_BLOCK.findall(s) if m.strip()]
        if blocks:
            return blocks

    # Default: one non-empty line = one event
    return [ln for ln in text.splitlines() if ln.strip()]


def _build_hec_event_json_lines(
    payload: bytes,
    *,
    index_name: str,
    source: str,
    sourcetype: str,
    host_label: str,
    force_time_now: bool,
    add_data_source_field: bool,
) -> list[str]:
    """Build one Splunk HEC /event JSON object per log record."""
    try:
        text = payload.decode("utf-8", errors="replace")
    except Exception:
        text = ""
    now = time.time()
    fields = {"data_source": "totalreplay"} if add_data_source_field else None

    records = _split_payload_records(text)
    out_lines: list[str] = []
    for i, ln in enumerate(records):
        evt_host = f"{host_label}-{i + 1}" if len(records) > 1 else host_label
        evt: dict[str, Any] = {
            "event": ln,
            "index": index_name,
            "sourcetype": sourcetype or "_json",
            "source": source or "totalreplay-ui",
            "host": evt_host,
        }
        if fields:
            evt["fields"] = fields
        if force_time_now:
            evt["time"] = now
        else:
            t = _best_effort_event_time(ln)
            if t is not None:
                evt["time"] = t
        out_lines.append(json.dumps(evt, separators=(",", ":")))

    if not out_lines:
        evt: dict[str, Any] = {
            "event": "",
            "index": index_name,
            "sourcetype": sourcetype or "_json",
            "source": source or "totalreplay-ui",
            "host": host_label,
        }
        if fields:
            evt["fields"] = fields
        if force_time_now:
            evt["time"] = now
        out_lines = [json.dumps(evt, separators=(",", ":"))]
    return out_lines


def _download_to_cache(url: str, job_id: str) -> Path:
    """Download an attack_data URL into the local cache (idempotent)."""
    # Use the URL path as the cache key
    safe = url.replace("https://", "").replace("http://", "").replace("/", "_")
    dest = DOWNLOAD_CACHE / safe
    if dest.exists() and dest.stat().st_size > 200:
        _emit(job_id, f"  cache hit: {dest.name}")
        return dest
    _emit(job_id, f"  downloading {url}")
    r = requests.get(url, stream=True, timeout=60)
    r.raise_for_status()
    with open(dest, "wb") as f:
        for chunk in r.iter_content(chunk_size=64 * 1024):
            if chunk:
                f.write(chunk)
    _emit(job_id, f"  downloaded {dest.stat().st_size} bytes")
    return dest


def _detection_catalog_for_cfg(cfg: dict) -> list[dict]:
    if is_remote_mode(cfg):
        try:
            return remote_catalog_detections(cfg).get("items") or []
        except Exception:
            return []
    return build_detection_catalog(cfg.get("security_content_path", ""))


def enrich_replay_items(items: list[dict], catalog: Optional[list[dict]]) -> list[dict]:
    """Attach detection name, MITRE IDs, and analytic stories for history/logs."""
    by_id = {d["id"]: d for d in (catalog or []) if d.get("id")}
    out: list[dict] = []
    for it in items:
        row = dict(it)
        det_id = row.get("detection_id") or row.get("id")
        det = by_id.get(det_id) if det_id else None
        if det:
            row["detection_name"] = row.get("detection_name") or det.get("name")
            row["mitre_techniques"] = det.get("mitre_techniques") or det.get("mitre_attack_id") or []
            row["mitre_tactics"] = det.get("mitre_tactics") or []
            stories = det.get("use_cases") or det.get("analytic_story") or []
            row["analytic_story"] = stories if isinstance(stories, list) else [stories]
            row["use_cases"] = row["analytic_story"]
            row["sourcetypes"] = det.get("sourcetypes") or []
        else:
            row.setdefault("mitre_techniques", [])
            row.setdefault("mitre_tactics", [])
            row.setdefault("analytic_story", [])
        out.append(row)
    return out


def _parse_cli_event_count(lines: list[str]) -> int:
    """Best-effort event count from TOTAL-REPLAY CLI stdout."""
    total = 0
    patterns = [
        re.compile(r"(\d+)\s+events?\b", re.I),
        re.compile(r"sent\s+(\d+)\b", re.I),
        re.compile(r"indexed\s+(\d+)\b", re.I),
        re.compile(r"(\d+)\s+event(?:s)?\s+(?:to|into)\b", re.I),
        re.compile(r"successfully\s+sent\s+(\d+)\b", re.I),
    ]
    for line in lines:
        for pat in patterns:
            for m in pat.finditer(line):
                try:
                    total += int(m.group(1))
                except ValueError:
                    pass
    return total


def _result_row_from_input(
    it: dict,
    status: str,
    message: str,
    events_forwarded: Optional[int] = None,
) -> dict:
    stories = it.get("analytic_story") or []
    if isinstance(stories, str):
        stories = [stories] if stories else []
    tech = it.get("mitre_techniques") or it.get("mitre_attack_id") or []
    tac = it.get("mitre_tactics") or []
    name = it.get("detection_name") or it.get("name") or it.get("detection_id") or "?"
    return {
        "label": name,
        "detection_name": name,
        "detection_id": it.get("detection_id") or it.get("id"),
        "status": status,
        "message": message,
        "events_forwarded": events_forwarded,
        "mitre_techniques": tech,
        "mitre_tactics": tac,
        "analytic_story": stories,
        "use_cases": ", ".join(str(s) for s in stories if s),
        "sourcetypes": it.get("sourcetypes") or [],
    }


def _build_cli_detection_results(
    items: list[dict],
    status: str,
    code: int,
    cli_output: str,
) -> tuple[list[dict], int]:
    events_total = _parse_cli_event_count(cli_output.splitlines())
    msg = f"TOTAL-REPLAY CLI exit {code}"
    if events_total:
        msg += f"; ~{events_total} events to Splunk (from CLI output)"
    per_events = events_total if len(items) == 1 else None
    rows = [
        _result_row_from_input(it, status, msg, per_events)
        for it in items
    ]
    return rows, events_total


def _normalize_history_results(
    input_items: list[dict],
    results: list[dict],
    job_status: str,
) -> list[dict]:
    """Expand generic CLI rows into per-detection results with MITRE/use-case metadata."""
    if not input_items:
        return results
    if len(results) == 1:
        lab = (results[0].get("label") or "").strip().lower()
        if lab in ("remote cli", "local cli"):
            st = results[0].get("status") or job_status
            msg = results[0].get("message") or ""
            ev = results[0].get("events_forwarded")
            return [_result_row_from_input(it, st, msg, ev) for it in input_items]
    by_id = {
        (r.get("detection_id") or ""): r
        for r in results
        if r.get("detection_id")
    }
    by_label = {(r.get("label") or r.get("detection_name") or ""): r for r in results}
    merged: list[dict] = []
    for it in input_items:
        det_id = it.get("detection_id") or ""
        name = it.get("detection_name") or it.get("name") or ""
        base = by_id.get(det_id) or by_label.get(name)
        if base:
            row = _result_row_from_input(
                it,
                base.get("status") or job_status,
                base.get("message") or "",
                base.get("events_forwarded"),
            )
        else:
            row = _result_row_from_input(it, job_status, "no per-item result")
        merged.append(row)
    return merged if merged else results


def _replay_titles_from_items(items: list[dict]) -> list[str]:
    return [
        str(it.get("detection_name") or it.get("name") or it.get("detection_id") or "?").strip()
        for it in items
    ]


def _estimate_hec_event_count(payload: bytes) -> int:
    """Approximate Splunk events in a HEC payload (line-delimited logs or JSON array)."""
    if not payload:
        return 0
    try:
        text = payload.decode("utf-8", errors="replace").strip()
    except Exception:
        return 1
    if not text:
        return 0
    if text.startswith("["):
        try:
            parsed = json.loads(text)
            if isinstance(parsed, list):
                return len(parsed)
        except json.JSONDecodeError:
            pass
    lines = [ln for ln in text.splitlines() if ln.strip()]
    return len(lines) if lines else 1


def _sum_events_from_results(results: list[dict]) -> int:
    return sum(int(r.get("events_forwarded") or 0) for r in results)


def _history_summary_from_result(result: dict, detail: dict) -> str:
    succ = int(result.get("succ") or detail.get("succ") or 0)
    fail = int(result.get("fail") or detail.get("fail") or 0)
    ev = int(result.get("total_events") or detail.get("total_events") or 0)
    titles = detail.get("replay_titles") or _replay_titles_from_items(
        detail.get("input_items") or []
    )
    parts: list[str] = []
    if titles:
        if len(titles) == 1:
            parts.append(titles[0])
        else:
            parts.append(f"{titles[0]} +{len(titles) - 1} more")
    parts.extend([f"{succ} ok", f"{fail} failed"])
    if ev > 0:
        parts.append(f"{ev} events to Splunk")
    if result.get("error"):
        parts.append(str(result["error"])[:80])
    return " · ".join(parts)


def _persist_history_result(job_id: str, result: dict) -> None:
    """Merge replay outcome into history row without losing request metadata."""
    with db_conn() as c:
        row = c.execute("SELECT items_json FROM history WHERE id=?", (job_id,)).fetchone()
    request_meta: dict[str, Any] = {}
    if row:
        try:
            parsed = json.loads(row["items_json"] or "{}")
            if isinstance(parsed, dict):
                request_meta = parsed
        except (json.JSONDecodeError, TypeError):
            pass

    input_items = (
        request_meta.get("input_items")
        or request_meta.get("items")
        or []
    )
    raw_results = result.get("items") or []
    job_status = result.get("status", "failed")
    results = _normalize_history_results(input_items, raw_results, job_status)
    total_events = int(result.get("total_events") or 0)
    if not total_events:
        total_events = _sum_events_from_results(results)
    detail = {
        "engine": request_meta.get("engine"),
        "mode": request_meta.get("mode", "detections"),
        "input_items": input_items,
        "replay_titles": _replay_titles_from_items(input_items),
        "sequential": bool(request_meta.get("sequential")),
        "stop_on_error": bool(request_meta.get("stop_on_error")),
        "use_index_mapping": request_meta.get("use_index_mapping"),
        "results": results,
        "succ": int(result.get("succ") or 0),
        "fail": int(result.get("fail") or 0),
        "total_events": total_events,
        "error": result.get("error"),
    }
    summary = _history_summary_from_result(result, detail)
    with db_conn() as c:
        c.execute(
            "UPDATE history SET finished_at=?, status=?, items_json=?, summary=? WHERE id=?",
            (
                dt.datetime.utcnow().isoformat(),
                result.get("status", "failed"),
                json.dumps(detail),
                summary,
                job_id,
            ),
        )


def _post_to_hec(cfg: dict, index_name: str, source: str, sourcetype: str,
                 host_label: str, payload: bytes,
                 log_fn: Optional[Callable[[str], None]] = None) -> tuple[bool, str, int]:
    ok, msg, _, _ = _splunk_endpoint(cfg, log_fn=log_fn)
    if not ok:
        return False, msg, 0
    force_now = bool(cfg.get("hec_force_time_now", False))
    add_field = bool(cfg.get("hec_add_data_source_field", False))

    try:
        url = _hec_url(cfg, path_suffix="/services/collector/event", log_fn=log_fn)
    except RuntimeError as e:
        return False, str(e), 0
    headers = {
        "Authorization": f"Splunk {cfg['hec_token']}",
        "Content-Type": "application/json",
    }
    event_lines = _build_hec_event_json_lines(
        payload,
        index_name=index_name,
        source=source,
        sourcetype=sourcetype,
        host_label=host_label,
        force_time_now=force_now,
        add_data_source_field=add_field,
    )
    if log_fn:
        log_fn(f"HEC: split payload into {len(event_lines)} event(s); posting each separately")
    sent = 0
    last_err = ""
    for i, line in enumerate(event_lines, 1):
        try:
            r = requests.post(
                url,
                headers=headers,
                data=(line + "\n").encode("utf-8"),
                verify=bool(cfg.get("verify_tls")),
                timeout=60,
            )
        except requests.RequestException as e:
            return False, _format_hec_request_error(e, cfg), sent
        if r.status_code == 200:
            sent += 1
            if log_fn and len(event_lines) <= 20:
                log_fn(f"  HEC event {i}/{len(event_lines)} OK")
            continue
        last_err = f"HTTP {r.status_code}: {r.text.strip()[:200]}"
        if log_fn:
            log_fn(f"  HEC event {i}/{len(event_lines)} FAIL: {last_err}")
        return False, last_err, sent
    if sent == 0:
        return False, "no events sent", 0
    return True, f"ok ({sent} events)", sent


def replay_items_remote_hec(
    job_id: str,
    mode: str,
    items: list[dict],
    index_name: str,
    *,
    finalize: bool = True,
    use_index_mapping: bool = False,
    detection_catalog: Optional[list[dict]] = None,
    cfg_override: Optional[dict] = None,
) -> dict:
    """Replay by fetching payloads over SSH and posting to Splunk HEC from the web app."""
    cfg = cfg_override or load_config()
    if not resolve_hec_host(cfg) or not cfg.get("hec_token"):
        return {"status": "failed", "error": "Splunk host or HEC token not configured"}

    results: list[dict] = []
    succ = fail = 0

    for it in items:
        label = it.get("detection_name") or it.get("name") or it.get("path") or "?"
        _emit(job_id, f">> {label}")
        targets: list[tuple[str, str, str, bool]] = []

        if mode == "detections":
            det_id = it.get("detection_id") or ""
            _emit(job_id, "  Loading attack_data URLs from remote security_content...")
            attack_entries = remote_detection_attack_data(cfg, det_id) if det_id else []
            for a in attack_entries:
                if a.get("data"):
                    targets.append((a.get("source", ""), a.get("sourcetype", ""), a["data"], True))
            if not targets:
                msg = "no attack_data for detection (check security_content on remote host)"
                _emit(job_id, f"  FAIL: {msg}")
                results.append({"label": label, "status": "failed", "message": msg})
                fail += 1
                continue
        elif mode == "cached":
            log_path = it.get("log_path") or ""
            if not log_path:
                msg = "no log path in cache entry"
                _emit(job_id, f"  FAIL: {msg}")
                results.append({"label": label, "status": "failed", "message": msg})
                fail += 1
                continue
            targets.append((
                it.get("source", ""),
                it.get("sourcetype", ""),
                log_path,
                False,
            ))
        else:
            targets.append((
                it.get("source", ""),
                it.get("sourcetype", ""),
                it.get("abs_path", ""),
                False,
            ))

        if not targets:
            msg = "no attack_data entries"
            _emit(job_id, f"  FAIL: {msg}")
            results.append({"label": label, "status": "failed", "message": msg})
            fail += 1
            continue

        item_ok = True
        item_events = 0
        host_label = str(uuid.uuid4())
        for source, sourcetype, ref, is_url in targets:
            try:
                if is_url:
                    _emit(job_id, f"  Fetching {Path(ref).name}...")
                    local = _download_to_cache(ref, job_id)
                    payload = local.read_bytes()
                    ref_name = Path(ref).name
                else:
                    _emit(job_id, f"  Reading remote file {Path(ref).name}...")
                    payload = ssh_fetch_file_bytes(cfg, ref)
                    ref_name = Path(ref).name
                if len(payload) < 200 and payload.startswith(b"version https://git-lfs"):
                    raise RuntimeError("file is a Git LFS pointer (run git lfs pull on remote)")
                idx, rep_st = resolve_index_and_sourcetype(
                    sourcetype, index_name, use_index_mapping,
                )
                if use_index_mapping and idx != index_name:
                    _emit(job_id, f"  Mapped index: {idx} (sourcetype {rep_st})")
                _emit(job_id, f"  Sending {ref_name} to Splunk HEC...")
                ok, msg, n_events = _post_to_hec(
                    cfg, idx, source, rep_st, host_label, payload,
                    log_fn=lambda m: _emit(job_id, m),
                )
                if ok:
                    item_events += n_events
                    _emit(job_id, f"  OK: {ref_name}: {msg} (~{n_events} events)")
                else:
                    _emit(job_id, f"  FAIL: {ref_name}: {msg}")
                    item_ok = False
            except Exception as e:
                _emit(job_id, f"  FAIL: {Path(ref).name}: {e}")
                item_ok = False

        row = {
            "label": label,
            "detection_id": it.get("detection_id"),
            "detection_name": it.get("detection_name") or label,
            "events_forwarded": item_events if item_ok else 0,
        }
        if item_ok:
            succ += 1
            row["status"] = "success"
            row["message"] = f"all targets sent via HEC ({item_events} events)"
            results.append(row)
        else:
            fail += 1
            row["status"] = "failed"
            row["message"] = "one or more targets failed"
            results.append(row)

    final = "success" if fail == 0 else ("partial" if succ > 0 else "failed")
    total_events = _sum_events_from_results(results)
    _emit(job_id, f"\n done: {succ} ok, {fail} failed ({total_events} events to Splunk)")
    if finalize:
        _emit(job_id, "__END__")
    return {"status": final, "items": results, "succ": succ, "fail": fail, "total_events": total_events}


def replay_local_cli(
    job_id: str,
    mode: str,
    items: list[dict],
    index_name: str,
    *,
    finalize: bool = True,
    use_index_mapping: bool = False,
    detection_catalog: Optional[list[dict]] = None,
    cfg_override: Optional[dict] = None,
) -> dict:
    # cfg_override is accepted for API compatibility with HEC engines; CLI ignores it.
    cfg = load_config()
    cli_mode = mode
    if mode == "detections":
        cli_mode = "detections"
    elif mode == "cached":
        cli_mode = "cached"
    else:
        return {
            "status": "failed",
            "error": "Local TOTAL-REPLAY CLI supports Detection and Cached modes. Use Web HEC for raw files.",
            "items": [],
            "succ": 0,
            "fail": len(items),
        }

    cli_index = index_name
    if use_index_mapping and len(items) == 1:
        cli_index = resolve_index_for_item(
            cfg, mode, items[0], index_name, True, catalog_detections=detection_catalog,
        )
        if cli_index != index_name:
            _emit(job_id, f"  Mapped index for CLI: {cli_index}")
    try:
        code, cli_out = run_total_replay_local(
            cfg, cli_mode, items, cli_index,
            on_line=lambda line: _emit(job_id, line),
        )
    except Exception as e:
        _emit(job_id, f"local replay failed: {e}")
        if finalize:
            _emit(job_id, "__END__")
        return {"status": "failed", "items": [], "error": str(e), "succ": 0, "fail": len(items)}

    status = "success" if code == 0 else "failed"
    cli_items, total_events = _build_cli_detection_results(items, status, code, cli_out)
    succ = sum(1 for r in cli_items if r.get("status") == "success")
    fail = len(cli_items) - succ
    _emit(job_id, f"\n local CLI exit code: {code}" + (f", ~{total_events} events" if total_events else ""))
    if finalize:
        _emit(job_id, "__END__")
    return {
        "status": status,
        "items": cli_items,
        "succ": succ,
        "fail": fail,
        "total_events": total_events,
    }


def replay_remote_cli(
    job_id: str,
    mode: str,
    items: list[dict],
    index_name: str,
    *,
    finalize: bool = True,
    use_index_mapping: bool = False,
    detection_catalog: Optional[list[dict]] = None,
    cfg_override: Optional[dict] = None,
) -> dict:
    # cfg_override is accepted for API compatibility with HEC engines; CLI ignores it.
    cfg = load_config()
    cli_mode = mode
    if mode == "detections":
        cli_mode = "detections"
    elif mode == "cached":
        cli_mode = "cached"
    else:
        return {
            "status": "failed",
            "error": "Remote TOTAL-REPLAY CLI supports Detection and Cached modes. Use Web HEC for raw files.",
            "items": [],
            "succ": 0,
            "fail": len(items),
        }

    cli_index = index_name
    if use_index_mapping and len(items) == 1:
        cli_index = resolve_index_for_item(
            cfg, mode, items[0], index_name, True, catalog_detections=detection_catalog,
        )
        if cli_index != index_name:
            _emit(job_id, f"  Mapped index for CLI: {cli_index}")
    try:
        ssh_host = (cfg.get("ssh_host") or "").strip()
        ssh_user = (cfg.get("ssh_user") or "").strip()
        _emit(job_id, f"Connecting SSH to {ssh_user}@{ssh_host}...")
        ensure_ssh_client(cfg)
        _emit(job_id, "Checking total_replay.py on remote host...")
        tr_dir = ensure_remote_total_replay_dir(cfg)
        _emit(job_id, f"OK: {tr_dir}/total_replay.py")
        code, cli_out = run_total_replay_remote(
            cfg, cli_mode, items, cli_index,
            on_line=lambda line: _emit(job_id, line),
        )
    except Exception as e:
        _emit(job_id, f"remote replay failed: {e}")
        if finalize:
            _emit(job_id, "__END__")
        return {"status": "failed", "items": [], "error": str(e), "succ": 0, "fail": len(items)}

    status = "success" if code == 0 else "failed"
    cli_items, total_events = _build_cli_detection_results(items, status, code, cli_out)
    succ = sum(1 for r in cli_items if r.get("status") == "success")
    fail = len(cli_items) - succ
    _emit(job_id, f"\n remote CLI exit code: {code}" + (f", ~{total_events} events" if total_events else ""))
    if finalize:
        _emit(job_id, "__END__")
    return {
        "status": status,
        "items": cli_items,
        "succ": succ,
        "fail": fail,
        "total_events": total_events,
    }


def replay_items(
    job_id: str,
    mode: str,
    items: list[dict],
    index_name: str,
    *,
    finalize: bool = True,
    use_index_mapping: bool = False,
    detection_catalog: Optional[list[dict]] = None,
    cfg_override: Optional[dict] = None,
) -> dict:
    """
    items shape depends on mode:
      detections: [{"detection_name": "...", "detection_id": "..."}]
      files:      [{"path": "datasets/...", "abs_path": "/abs/...", "source": "...", "sourcetype": "..."}]
    """
    cfg = cfg_override or load_config()
    if not resolve_hec_host(cfg) or not cfg.get("hec_token"):
        return {"status": "failed", "error": "Splunk host or HEC token not configured"}

    results: list[dict] = []
    succ = fail = 0
    catalog = detection_catalog
    if catalog is None and mode == "detections":
        catalog = build_detection_catalog(cfg.get("security_content_path", ""))

    for it in items:
        label = it.get("detection_name") or it.get("path") or "?"
        _emit(job_id, f">> {label}")

        # Build list of (source, sourcetype, url_or_path) tuples
        targets: list[tuple[str, str, str, bool]] = []  # (source, sourcetype, ref, is_url)

        if mode == "detections":
            sc_path = cfg.get("security_content_path", "")
            if catalog is None:
                catalog = build_detection_catalog(sc_path)
            det = next((d for d in catalog if d["id"] == it.get("detection_id")), None)
            if det is None:
                msg = "detection not found in catalog"
                _emit(job_id, f"  FAIL: {msg}")
                results.append({"label": label, "status": "failed", "message": msg})
                fail += 1
                continue
            for t in det["tests"]:
                for a in t["attack_data"]:
                    targets.append((a["source"], a["sourcetype"], a["data"], True))
        else:
            targets.append((it.get("source", ""), it.get("sourcetype", ""),
                            it.get("abs_path", ""), False))

        if not targets:
            msg = "no attack_data entries"
            _emit(job_id, f"  FAIL: {msg}")
            results.append({"label": label, "status": "failed", "message": msg})
            fail += 1
            continue

        item_ok = True
        item_events = 0
        host_label = str(uuid.uuid4())
        for source, sourcetype, ref, is_url in targets:
            try:
                if is_url:
                    _emit(job_id, f"  Fetching {Path(ref).name}...")
                    local = _download_to_cache(ref, job_id)
                else:
                    local = Path(ref)
                    if not local.exists():
                        raise FileNotFoundError(local)
                payload = local.read_bytes()
                if len(payload) < 200 and payload.startswith(b"version https://git-lfs"):
                    raise RuntimeError("file is a Git LFS pointer (run `git lfs pull`)")
                idx, rep_st = resolve_index_and_sourcetype(
                    sourcetype, index_name, use_index_mapping,
                )
                if use_index_mapping and idx != index_name:
                    _emit(job_id, f"  Mapped index: {idx} (sourcetype {rep_st})")
                _emit(job_id, f"  Sending {Path(ref).name} to Splunk HEC...")
                ok, msg, n_events = _post_to_hec(
                    cfg, idx, source, rep_st, host_label, payload,
                    log_fn=lambda m: _emit(job_id, m),
                )
                if ok:
                    item_events += n_events
                    _emit(job_id, f"  OK: {Path(ref).name}: {msg} (~{n_events} events)")
                else:
                    _emit(job_id, f"  FAIL: {Path(ref).name}: {msg}")
                    item_ok = False
            except Exception as e:
                _emit(job_id, f"  FAIL: {Path(ref).name}: {e}")
                item_ok = False

        row = {
            "label": label,
            "detection_id": it.get("detection_id"),
            "detection_name": it.get("detection_name") or label,
            "events_forwarded": item_events if item_ok else 0,
        }
        if item_ok:
            succ += 1
            row["status"] = "success"
            row["message"] = f"all targets sent ({item_events} events)"
            results.append(row)
        else:
            fail += 1
            row["status"] = "failed"
            row["message"] = "one or more targets failed"
            results.append(row)

    final = "success" if fail == 0 else ("partial" if succ > 0 else "failed")
    total_events = _sum_events_from_results(results)
    _emit(job_id, f"\n done: {succ} ok, {fail} failed ({total_events} events to Splunk)")
    if finalize:
        _emit(job_id, "__END__")
    return {"status": final, "items": results, "succ": succ, "fail": fail, "total_events": total_events}


def replay_items_sequential(
    job_id: str,
    mode: str,
    items: list[dict],
    index_name: str,
    replay_fn: Callable[..., dict],
    *,
    stop_on_error: bool = False,
    use_index_mapping: bool = False,
    detection_catalog: Optional[list[dict]] = None,
    cfg_override: Optional[dict] = None,
) -> dict:
    """Run each selected item one after another with progress in the live log."""
    total = len(items)
    results: list[dict] = []
    succ = fail = 0
    total_events = 0

    for i, it in enumerate(items, 1):
        label = (
            it.get("detection_name") or it.get("name")
            or it.get("path") or "?"
        )
        _emit(job_id, f"\n--- [{i}/{total}] {label} ---")
        item_index = index_name
        if use_index_mapping:
            cfg = cfg_override or load_config()
            item_index = resolve_index_for_item(
                cfg, mode, it, index_name, True, catalog_detections=detection_catalog,
            )
            if item_index != index_name:
                _emit(job_id, f"  Index mapping: {item_index}")
        try:
            one = replay_fn(
                job_id, mode, [it], item_index, finalize=False,
                use_index_mapping=use_index_mapping,
                detection_catalog=detection_catalog,
                cfg_override=cfg_override,
            )
        except Exception as e:
            _emit(job_id, f"  FAIL: crashed: {e}")
            results.append({"label": label, "status": "failed", "message": str(e)})
            fail += 1
            if stop_on_error:
                break
            continue

        total_events += int(one.get("total_events") or 0)
        for row in one.get("items", []):
            results.append(row)
            if row.get("status") == "success":
                succ += 1
            else:
                fail += 1
        if one.get("status") == "success" and not one.get("items"):
            succ += 1
            results.append({"label": label, "status": "success", "message": "ok"})
        elif one.get("status") != "success" and not one.get("items"):
            fail += 1
            results.append({
                "label": label,
                "status": "failed",
                "message": one.get("error") or one.get("message") or "failed",
            })
        if stop_on_error and fail > 0 and i < total:
            _emit(job_id, "  stopping sequence (stop on error enabled)")
            break

    final = "success" if fail == 0 else ("partial" if succ > 0 else "failed")
    if not total_events:
        total_events = _sum_events_from_results(results)
    _emit(job_id, f"\n sequence done: {succ} ok, {fail} failed ({total} total, {total_events} events)")
    _emit(job_id, "__END__")
    return {"status": final, "items": results, "succ": succ, "fail": fail, "total_events": total_events}


def run_replay_job(
    mode: str,
    items: list[dict],
    index_name: str,
    engine: Optional[str] = None,
    *,
    sequential: bool = False,
    stop_on_error: bool = False,
    use_index_mapping: Optional[bool] = None,
    hec_force_time_now: Optional[bool] = None,
    hec_add_data_source_field: Optional[bool] = None,
) -> str:
    """Launch a replay in a background thread, return job_id."""
    job_id = str(uuid.uuid4())
    q: queue.Queue[str] = queue.Queue()
    with _log_queues_lock:
        _log_queues[job_id] = q

    cfg = load_config()
    cfg_job = dict(cfg)
    if hec_force_time_now is not None:
        cfg_job["hec_force_time_now"] = bool(hec_force_time_now)
    if hec_add_data_source_field is not None:
        cfg_job["hec_add_data_source_field"] = bool(hec_add_data_source_field)
    if use_index_mapping is None:
        use_index_mapping = bool(cfg_job.get("use_index_mapping", True))
    if engine is None:
        engine = cfg_job.get("replay_engine", "hec")
    detection_catalog: Optional[list[dict]] = None
    if mode == "detections":
        detection_catalog = _detection_catalog_for_cfg(cfg_job)
    enriched_items = (
        enrich_replay_items(items, detection_catalog)
        if mode == "detections"
        else [dict(it) for it in items]
    )
    if is_remote_mode(cfg_job) and engine == "remote_cli":
        replay_fn = replay_remote_cli
    elif is_remote_mode(cfg_job) and engine == "hec":
        replay_fn = replay_items_remote_hec
    elif not is_remote_mode(cfg_job) and engine == "local_cli":
        replay_fn = replay_local_cli
    else:
        replay_fn = replay_items

    # Record start
    with db_conn() as c:
        c.execute(
            "INSERT INTO history (id, started_at, status, index_name, splunk_host, items_json) "
            "VALUES (?, ?, 'running', ?, ?, ?)",
            (job_id, dt.datetime.utcnow().isoformat(), index_name,
             resolve_hec_host(cfg),
             json.dumps({
                 "engine": engine,
                 "mode": mode,
                 "items": enriched_items,
                 "input_items": enriched_items,
                 "replay_titles": _replay_titles_from_items(enriched_items),
                 "sequential": sequential,
                 "stop_on_error": stop_on_error,
                 "use_index_mapping": use_index_mapping,
                 "hec_force_time_now": bool(cfg_job.get("hec_force_time_now", False)),
                 "hec_add_data_source_field": bool(cfg_job.get("hec_add_data_source_field", True)),
             })),
        )

    def _worker() -> None:
        seq_note = " (sequential)" if sequential and len(items) > 1 else ""
        map_note = " index-mapping=on" if use_index_mapping else ""
        titles = _replay_titles_from_items(enriched_items)
        title_note = f" — {titles[0]}" if len(titles) == 1 else (f" — {len(titles)} detections" if titles else "")
        _emit(job_id, f"Job started (engine={engine}, mode={mode}, items={len(enriched_items)}{seq_note}{map_note}){title_note}")
        if engine in ("remote_cli", "local_cli"):
            _emit(
                job_id,
                "NOTE: CLI delivery sends via total_replay.py on the host. "
                "For separate Splunk events + data_source=totalreplay, use engine=hec (Web UI HEC).",
            )
        elif engine == "hec":
            _emit(job_id, "HEC mode: each XML <Event> block is posted as its own Splunk event.")
        try:
            ok_tok, tok_err = validate_hec_token(cfg_job.get("hec_token", ""))
            if not ok_tok:
                _emit(job_id, f"FAIL: {tok_err}")
                _emit(job_id, "__END__")
                result = {"status": "failed", "items": [], "error": tok_err}
            else:
                if engine in ("hec", "remote_cli", "local_cli") or cfg_job.get("ssh_enabled"):
                    _emit(job_id, "Checking Splunk HEC connectivity...")
                    hec = _hec_auth_test(cfg_job, index_name, log_fn=lambda m: _emit(job_id, m))
                    if not hec.get("ok"):
                        _emit(job_id, f"FAIL: HEC check failed: {hec.get('error') or hec.get('body')}")
                        _emit(job_id, "__END__")
                        result = {
                            "status": "failed",
                            "items": [],
                            "error": hec.get("error") or "HEC check failed",
                        }
                    else:
                        _emit(job_id, f"OK: HEC reachable (index {index_name})")
                        if sequential and len(enriched_items) > 1:
                            result = replay_items_sequential(
                                job_id, mode, enriched_items, index_name, replay_fn,
                                stop_on_error=stop_on_error,
                                use_index_mapping=use_index_mapping,
                                detection_catalog=detection_catalog,
                                cfg_override=cfg_job,
                            )
                        else:
                            result = replay_fn(
                                job_id, mode, enriched_items, index_name,
                                use_index_mapping=use_index_mapping,
                                detection_catalog=detection_catalog,
                                cfg_override=cfg_job,
                            )
                else:
                    if sequential and len(enriched_items) > 1:
                        result = replay_items_sequential(
                            job_id, mode, enriched_items, index_name, replay_fn,
                            stop_on_error=stop_on_error,
                            use_index_mapping=use_index_mapping,
                            detection_catalog=detection_catalog,
                            cfg_override=cfg_job,
                        )
                    else:
                        result = replay_fn(
                            job_id, mode, enriched_items, index_name,
                            use_index_mapping=use_index_mapping,
                            detection_catalog=detection_catalog,
                            cfg_override=cfg_job,
                        )
        except Exception as e:
            _emit(job_id, f"job crashed: {e}")
            _emit(job_id, "__END__")
            result = {"status": "failed", "items": [], "error": str(e)}

        _persist_history_result(job_id, result)

        # Hold the queue for 5 min so late SSE connections can drain it
        time.sleep(300)
        with _log_queues_lock:
            _log_queues.pop(job_id, None)

    t = threading.Thread(target=_worker, daemon=True)
    t.start()
    # Brief yield so the first log line is queued before the client opens SSE.
    time.sleep(0.05)
    return job_id


# ---------------------------------------------------------------------------
# Scheduler
# ---------------------------------------------------------------------------

scheduler = BackgroundScheduler()
scheduler.start()


def _schedule_callback(schedule_id: str) -> None:
    with db_conn() as c:
        row = c.execute("SELECT * FROM schedules WHERE id=?", (schedule_id,)).fetchone()
    if row is None:
        return
    sel = json.loads(row["selection_json"])
    job_id = run_replay_job(
        sel["mode"], sel["items"], sel["index"], engine=sel.get("engine"),
    )
    with db_conn() as c:
        c.execute(
            "UPDATE schedules SET last_run_at=?, last_status=? WHERE id=?",
            (dt.datetime.utcnow().isoformat(), f"launched job {job_id[:8]}", schedule_id),
        )


def _load_schedules_on_start() -> None:
    with db_conn() as c:
        rows = c.execute("SELECT * FROM schedules").fetchall()
    for row in rows:
        try:
            _register_apscheduler_job(dict(row))
        except Exception as e:
            print(f"[scheduler] failed to register {row['id']}: {e}")


def _register_apscheduler_job(row: dict) -> None:
    spec = json.loads(row["trigger_spec"])
    if row["trigger_type"] == "date":
        run_date = dt.datetime.fromisoformat(spec["run_date"])
        if run_date < dt.datetime.now():
            return  # don't re-register past one-shots
        trigger = DateTrigger(run_date=run_date)
    elif row["trigger_type"] == "cron":
        trigger = CronTrigger(**spec)
    else:
        return
    scheduler.add_job(
        _schedule_callback, trigger=trigger, args=[row["id"]],
        id=row["id"], replace_existing=True,
    )


# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/config", methods=["GET", "POST"])
def api_config():
    if request.method == "GET":
        cfg = load_config()
        cfg_redacted = dict(cfg)
        if not cfg_redacted.get("splunk_hec_host") and cfg_redacted.get("splunk_host"):
            cfg_redacted["splunk_hec_host"] = cfg_redacted["splunk_host"]
        if not cfg_redacted.get("index_planner_search"):
            cfg_redacted["index_planner_search"] = DEFAULT_INDEX_PLANNER_SEARCH
        if cfg_redacted.get("hec_token"):
            tok = cfg_redacted["hec_token"]
            cfg_redacted["hec_token_preview"] = (tok[:4] + "..." + tok[-4:]) if len(tok) > 8 else "set"
            ok_tok, tok_err = validate_hec_token(tok)
            cfg_redacted["hec_token_valid"] = ok_tok
            if not ok_tok:
                cfg_redacted["hec_token_warning"] = tok_err
            cfg_redacted.pop("hec_token", None)
        mgmt_tok = (cfg_redacted.get("splunk_mgmt_token") or "").strip()
        if mgmt_tok:
            cfg_redacted["splunk_mgmt_token_preview"] = (
                (mgmt_tok[:4] + "..." + mgmt_tok[-4:]) if len(mgmt_tok) > 8 else "set"
            )
            ok_mt, mt_err = validate_hec_token(mgmt_tok)
            cfg_redacted["splunk_mgmt_token_valid"] = ok_mt
            if not ok_mt:
                cfg_redacted["splunk_mgmt_token_warning"] = mt_err
            cfg_redacted.pop("splunk_mgmt_token", None)
        if cfg_redacted.get("ssh_password"):
            cfg_redacted.pop("ssh_password", None)
            cfg_redacted["ssh_password_set"] = True
        cfg_redacted["ssh_tunnel"] = tunnel_status()
        cfg_redacted["ssh_session"] = ssh_session_status()
        cfg_redacted["remote_mode"] = is_remote_mode(cfg)
        cfg_redacted["config_meta"] = config_meta()
        if is_remote_mode(cfg):
            cfg_redacted["ssh_config_hint"] = ssh_credentials_hint(cfg)
        return jsonify(cfg_redacted)
    cfg = load_config()
    body = request.get_json(force=True)
    ssh_fields_changed = any(
        k in body for k in (
            "ssh_enabled", "ssh_host", "ssh_port", "ssh_user", "ssh_password",
            "ssh_key_path", "ssh_remote_host", "splunk_host", "splunk_hec_host",
            "splunk_mgmt_host", "splunk_port",
            "connection_mode", "remote_total_replay_dir",
        )
    )
    for k in (
        "splunk_host", "splunk_hec_host", "splunk_mgmt_host", "splunk_port", "hec_token", "use_https", "verify_tls",
        "default_index", "security_content_path", "attack_data_path",
        "ssh_enabled", "ssh_host", "ssh_port", "ssh_user", "ssh_password",
        "ssh_key_path", "ssh_remote_host",
        "connection_mode", "remote_total_replay_dir",
        "remote_security_content_path", "remote_attack_data_path",
        "remote_python_cmd", "local_total_replay_dir", "local_python_cmd",
        "replay_engine", "splunk_mgmt_port", "splunk_mgmt_use_https", "splunk_mgmt_token",
        "splunk_username", "splunk_password",
        "use_index_mapping",
        "hec_force_time_now", "hec_add_data_source_field",
        "index_planner_search",
    ):
        if k in body:
            cfg[k] = body[k]
    if "splunk_hec_host" in body:
        cfg["splunk_hec_host"] = normalize_splunk_host(str(body.get("splunk_hec_host") or ""))
        cfg["splunk_host"] = cfg["splunk_hec_host"]
    elif "splunk_host" in body:
        cfg["splunk_host"] = normalize_splunk_host(str(body.get("splunk_host") or ""))
        cfg["splunk_hec_host"] = cfg["splunk_host"]
    if "splunk_mgmt_host" in body:
        cfg["splunk_mgmt_host"] = normalize_splunk_host(str(body.get("splunk_mgmt_host") or ""))
    cfg = apply_splunk_cloud_defaults(cfg)
    if "connection_mode" in body:
        cfg["connection_mode"] = normalize_connection_mode(body.get("connection_mode"))
    if is_remote_mode(cfg):
        ssh_err = ssh_credentials_hint(cfg)
        if ssh_err:
            return jsonify({
                "ok": False,
                "error": f"{ssh_err} Settings are stored in {CONFIG_PATH.resolve()}.",
            }), 400
    mgmt_tok = (cfg.get("splunk_mgmt_token") or "").strip()
    if "splunk_mgmt_token" in body and mgmt_tok:
        ok_mt, mt_err = validate_hec_token(mgmt_tok)
        if not ok_mt:
            return jsonify({
                "ok": False,
                "error": f"Management API token (8089): {mt_err}",
            }), 400
    if "hec_token" in body:
        hec_tok = (body.get("hec_token") or "").strip()
        if hec_tok:
            ok_tok, tok_err = validate_hec_token(hec_tok)
            if not ok_tok:
                return jsonify({
                    "ok": False,
                    "error": f"{tok_err} Enter the correct token in the HEC token field and click Save settings.",
                }), 400
            cfg["hec_token"] = hec_tok
    save_config(cfg)
    if ssh_fields_changed:
        close_tunnel()
        close_ssh_session()
    return jsonify({
        "ok": True,
        "connection_mode": cfg.get("connection_mode", "local"),
        "remote_mode": is_remote_mode(cfg),
    })


@app.route("/api/test-connection", methods=["POST"])
def api_test_connection():
    cfg = load_config()
    ok, tunnel_msg, _, _ = _splunk_endpoint(cfg)
    if not ok:
        return jsonify({"ok": False, "error": tunnel_msg}), 200

    hec = _hec_auth_test(cfg)
    if cfg.get("ssh_enabled"):
        hec["tunnel"] = tunnel_status()
        hec["tunnel_message"] = tunnel_msg
    return jsonify(hec), 200


@app.route("/api/ssh/status", methods=["GET"])
def api_ssh_status():
    return jsonify(tunnel_status())


@app.route("/api/ssh/disconnect", methods=["POST"])
def api_ssh_disconnect():
    close_tunnel()
    close_ssh_session()
    return jsonify({"ok": True, "tunnel": tunnel_status(), "ssh": ssh_session_status()})


@app.route("/api/remote/test", methods=["POST"])
def api_remote_test():
    body = request.get_json(silent=True) or {}
    cfg = merge_config_from_body(load_config(), body)
    if not is_remote_mode(cfg):
        return jsonify({
            "ok": False,
            "error": (
                "Connection mode is not Remote. Select Remote server (SSH) and save, "
                "or click Test SSH after selecting Remote."
            ),
        }), 200
    ssh_err = ssh_credentials_hint(cfg)
    if ssh_err:
        return jsonify({"ok": False, "error": ssh_err}), 200
    return jsonify(test_remote_ssh(cfg))


@app.route("/api/remote/test-hec", methods=["POST"])
def api_remote_test_hec():
    cfg = load_config()
    if not is_remote_mode(cfg):
        return jsonify({"ok": False, "error": "Remote mode is not enabled"}), 200
    ok_tok, tok_err = validate_hec_token(cfg.get("hec_token", ""))
    if not ok_tok:
        return jsonify({"ok": False, "error": tok_err}), 200
    try:
        ensure_ssh_client(cfg)
        index_name = request.get_json(silent=True) or {}
        idx = (index_name.get("index") if isinstance(index_name, dict) else None) or cfg.get("default_index", "test")
        return jsonify(test_hec_from_remote(cfg, idx))
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 200


@app.route("/api/local/sync-paths", methods=["POST"])
def api_local_sync_paths():
    cfg = load_config()
    if is_remote_mode(cfg):
        return jsonify({"ok": False, "error": "Connection mode is not Local"}), 200
    try:
        synced = sync_paths_from_local_config(cfg)
        cfg.update(synced)
        save_config(cfg)
        return jsonify({"ok": True, "paths": synced})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 200


@app.route("/api/remote/sync-paths", methods=["POST"])
def api_remote_sync_paths():
    body = request.get_json(silent=True) or {}
    cfg = merge_config_from_body(load_config(), body)
    if not is_remote_mode(cfg):
        return jsonify({"ok": False, "error": "Connection mode is not Remote"}), 200
    ssh_err = ssh_credentials_hint(cfg)
    if ssh_err:
        return jsonify({"ok": False, "error": ssh_err}), 200
    try:
        synced = sync_paths_from_remote_config(cfg)
        cfg.update(synced)
        save_config(cfg)
        return jsonify({"ok": True, "paths": synced})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 200


@app.route("/api/catalog/detections")
def api_catalog_detections():
    cfg = load_config()
    if is_remote_mode(cfg):
        try:
            ensure_ssh_client(cfg)
            return jsonify(remote_catalog_detections(cfg))
        except Exception as e:
            return jsonify({"count": 0, "items": [], "error": str(e)})
    cat = build_detection_catalog(cfg.get("security_content_path", ""))
    return jsonify({"count": len(cat), "items": cat})


@app.route("/api/catalog/files")
def api_catalog_files():
    cfg = load_config()
    if is_remote_mode(cfg):
        try:
            ensure_ssh_client(cfg)
            return jsonify(remote_catalog_files(cfg))
        except Exception as e:
            return jsonify({"count": 0, "items": [], "error": str(e)})
    cat = build_file_catalog(cfg.get("attack_data_path", ""))
    return jsonify({"count": len(cat), "items": cat})


@app.route("/api/catalog/cached")
def api_catalog_cached():
    cfg = load_config()
    if is_remote_mode(cfg):
        try:
            return jsonify(remote_catalog_cached(cfg))
        except Exception as e:
            return jsonify({"count": 0, "items": [], "error": str(e)})
    tr = local_paths(cfg).get("total_replay") or ""
    if not tr:
        return jsonify({
            "count": 0,
            "items": [],
            "error": "Set local TOTAL-REPLAY directory in Settings to browse cached replays",
        })
    return jsonify(build_cached_catalog_local(tr))


_detection_catalog_cache: dict[str, dict[str, Any]] = {}
_CATALOG_CACHE_TTL_SEC = 300


def _full_detection_catalog(cfg: dict) -> tuple[list[dict], Optional[str]]:
    key = "|".join([
        str(cfg.get("connection_mode") or "local"),
        str(cfg.get("remote_security_content_path") or ""),
        str(cfg.get("security_content_path") or ""),
    ])
    import time
    now = time.time()
    cached = _detection_catalog_cache.get(key)
    if cached and (now - cached.get("ts", 0)) < _CATALOG_CACHE_TTL_SEC:
        return cached.get("catalog") or [], cached.get("err")

    if is_remote_mode(cfg):
        try:
            catalog, err = remote_detection_catalog_full(cfg), None
        except Exception as e:
            catalog, err = [], str(e)
    else:
        sc = (
            cfg.get("remote_security_content_path")
            or cfg.get("security_content_path")
            or ""
        ).strip()
        if not sc:
            catalog, err = [], "security_content path is not configured in Settings"
        else:
            catalog, err = build_detection_catalog(sc), None

    _detection_catalog_cache[key] = {"catalog": catalog, "err": err, "ts": now}
    return catalog, err


@app.route("/api/detections/sourcetypes", methods=["GET"])
def api_detections_sourcetype_inventory():
    """Extract all sourcetypes from replayable detections with mapping info."""
    cfg = load_config()
    catalog, err = _full_detection_catalog(cfg)
    if err and not catalog:
        return jsonify({"ok": False, "error": err, "sourcetypes": []}), 200
    inv = aggregate_sourcetype_inventory(catalog)
    inv["ok"] = True
    if err:
        inv["warning"] = err
    return jsonify(inv)


@app.route("/api/detections/rerun", methods=["POST"])
def api_detections_sourcetype_rerun():
    """Rerun all detections that use the selected sourcetypes."""
    body = request.get_json(force=True) or {}
    sourcetypes = body.get("sourcetypes") or []
    if not sourcetypes:
        return jsonify({"ok": False, "error": "Select at least one sourcetype"}), 400
    cfg = load_config()
    catalog, err = _full_detection_catalog(cfg)
    if err and not catalog:
        return jsonify({"ok": False, "error": err}), 400
    items = replay_items_for_sourcetypes(catalog, sourcetypes)
    if not items:
        return jsonify({
            "ok": False,
            "error": "No detections found for the selected sourcetypes",
        }), 400
    ok_tok, tok_err = validate_hec_token(cfg.get("hec_token", ""))
    if not ok_tok:
        return jsonify({"ok": False, "error": tok_err}), 400
    index_name = body.get("index") or cfg.get("default_index", "test")
    engine = body.get("engine")
    sequential = bool(body.get("sequential", True))
    stop_on_error = bool(body.get("stop_on_error", False))
    use_map = body.get("use_index_mapping")
    if use_map is None:
        use_map = cfg.get("use_index_mapping", True)
    job_id = run_replay_job(
        "detections",
        items,
        index_name,
        engine=engine,
        sequential=sequential,
        stop_on_error=stop_on_error,
        use_index_mapping=bool(use_map),
    )
    return jsonify({
        "ok": True,
        "job_id": job_id,
        "count": len(items),
        "sourcetypes": sourcetypes,
        "sequential": sequential,
    })


@app.route("/api/replay", methods=["POST"])
def api_replay():
    body = request.get_json(force=True)
    mode = body.get("mode", "detections")
    items = body.get("items", [])
    index_name = body.get("index") or load_config().get("default_index", "test")
    if not items:
        return jsonify({"ok": False, "error": "no items selected"}), 400
    cfg = load_config()
    ok_tok, tok_err = validate_hec_token(cfg.get("hec_token", ""))
    if not ok_tok:
        return jsonify({"ok": False, "error": tok_err}), 400
    engine = body.get("engine")
    sequential = bool(body.get("sequential", False))
    stop_on_error = bool(body.get("stop_on_error", False))
    use_map = body.get("use_index_mapping")
    if use_map is None:
        use_map = load_config().get("use_index_mapping", True)
    hec_force_now = body.get("hec_force_time_now")
    hec_add_ds = body.get("hec_add_data_source_field")
    job_id = run_replay_job(
        mode, items, index_name, engine=engine,
        sequential=sequential, stop_on_error=stop_on_error,
        use_index_mapping=bool(use_map),
        hec_force_time_now=(bool(hec_force_now) if hec_force_now is not None else None),
        hec_add_data_source_field=(bool(hec_add_ds) if hec_add_ds is not None else None),
    )
    return jsonify({"ok": True, "job_id": job_id, "sequential": sequential, "count": len(items)})


@app.route("/api/replay/stream/<job_id>")
def api_replay_stream(job_id: str):
    @stream_with_context
    def gen():
        with _log_queues_lock:
            q = _log_queues.get(job_id)
        if q is None:
            yield "data: (job already finished or unknown)\n\n"
            yield "data: __END__\n\n"
            return
        while True:
            try:
                msg = q.get(timeout=30)
            except queue.Empty:
                yield ": keepalive\n\n"
                continue
            yield f"data: {msg}\n\n"
            if msg == "__END__":
                break
    return Response(gen(), mimetype="text/event-stream")


def _hydrate_history_items_json(items_json: str, job_status: str, catalog: list[dict]) -> str:
    """Fill missing MITRE/use-case fields when reading history (incl. legacy CLI rows)."""
    try:
        raw = json.loads(items_json or "{}")
    except (json.JSONDecodeError, TypeError):
        return items_json
    if isinstance(raw, list):
        return items_json
    if not isinstance(raw, dict):
        return items_json
    inp = raw.get("input_items") or raw.get("items") or []
    if catalog and inp:
        inp = enrich_replay_items(inp, catalog)
    res = raw.get("results") or []
    if inp:
        res = _normalize_history_results(inp, res, job_status or "unknown")
    raw["input_items"] = inp
    raw["items"] = inp
    raw["results"] = res
    raw["replay_titles"] = raw.get("replay_titles") or _replay_titles_from_items(inp)
    if not raw.get("total_events"):
        raw["total_events"] = _sum_events_from_results(res)
    return json.dumps(raw)


@app.route("/api/history")
def api_history():
    cfg = load_config()
    catalog = _detection_catalog_for_cfg(cfg) if cfg else []
    with db_conn() as c:
        rows = c.execute(
            "SELECT * FROM history ORDER BY started_at DESC LIMIT 100"
        ).fetchall()
    items = []
    for r in rows:
        d = dict(r)
        d["items_json"] = _hydrate_history_items_json(
            d.get("items_json") or "{}",
            d.get("status") or "",
            catalog,
        )
        items.append(d)
    return jsonify({"items": items})


@app.route("/api/history/<job_id>")
def api_history_one(job_id: str):
    with db_conn() as c:
        row = c.execute("SELECT * FROM history WHERE id=?", (job_id,)).fetchone()
    if row is None:
        return jsonify({"error": "not found"}), 404
    d = dict(row)
    d["items"] = json.loads(d.pop("items_json"))
    return jsonify(d)


@app.route("/api/schedules", methods=["GET", "POST"])
def api_schedules():
    if request.method == "GET":
        with db_conn() as c:
            rows = c.execute("SELECT * FROM schedules ORDER BY created_at DESC").fetchall()
        return jsonify({"items": [dict(r) for r in rows]})

    body = request.get_json(force=True)
    sid = str(uuid.uuid4())
    name = body.get("name") or "Scheduled replay"
    trigger_type = body.get("trigger_type", "date")  # date|cron
    trigger_spec = body.get("trigger_spec", {})
    selection = {
        "mode": body.get("mode", "detections"),
        "items": body.get("items", []),
        "index": body.get("index", load_config().get("default_index", "test")),
        "engine": body.get("engine", load_config().get("replay_engine", "hec")),
    }
    with db_conn() as c:
        c.execute(
            "INSERT INTO schedules (id, name, created_at, trigger_type, trigger_spec, selection_json) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (sid, name, dt.datetime.utcnow().isoformat(),
             trigger_type, json.dumps(trigger_spec), json.dumps(selection)),
        )
        row = c.execute("SELECT * FROM schedules WHERE id=?", (sid,)).fetchone()
    try:
        _register_apscheduler_job(dict(row))
    except Exception as e:
        return jsonify({"ok": False, "error": f"schedule registered in DB but not in scheduler: {e}"}), 200
    return jsonify({"ok": True, "id": sid})


def _splunk_sync_precheck(cfg: dict) -> Optional[str]:
    """Validate saved Splunk HEC + REST settings before index sync."""
    if not resolve_mgmt_host(cfg):
        return "Splunk management API host is not configured. Save Settings first."
    mgmt_token = (cfg.get("splunk_mgmt_token") or "").strip()
    hec_token = (cfg.get("hec_token") or "").strip()
    user = (cfg.get("splunk_username") or "").strip()
    if mgmt_token:
        ok_mt, mt_err = validate_hec_token(mgmt_token)
        if not ok_mt:
            return f"Management API token (8089): {mt_err}"
        return None
    if hec_token:
        ok_tok, tok_err = validate_hec_token(hec_token)
        if not ok_tok:
            return tok_err
        return None
    if user and cfg.get("splunk_password"):
        return None
    return (
        "Save a Management API token (port 8089) in Settings, "
        "or a HEC token with search permission, "
        "or optional Splunk username/password for REST."
    )


@app.route("/api/splunk/test-rest", methods=["POST"])
def api_splunk_test_rest():
    cfg = load_config()
    err = _splunk_sync_precheck(cfg)
    if err:
        return jsonify({"ok": False, "error": err}), 200
    result = test_rest_connection(cfg, log_fn=None)
    if cfg.get("ssh_enabled"):
        result["tunnel"] = tunnel_status()
    return jsonify(result), 200


@app.route("/api/splunk/sync-indexes", methods=["POST"])
def api_splunk_sync_indexes():
    cfg = load_config()
    err = _splunk_sync_precheck(cfg)
    if err:
        return jsonify({"ok": False, "error": err}), 400
    body = request.get_json(silent=True) or {}
    search_override = (body.get("search") or "").strip() or None
    job_id = str(uuid.uuid4())
    q: queue.Queue[str] = queue.Queue()
    with _log_queues_lock:
        _log_queues[job_id] = q

    def _worker() -> None:
        try:
            result = sync_splunk_inventory(
                cfg,
                search=search_override,
                log_fn=lambda m: _emit(job_id, m),
            )
            _emit(job_id, f"OK: stored {result['count']} index/sourcetype pairs")
            _emit(job_id, "__END__")
        except Exception as e:
            _emit(job_id, f"FAIL: {e}")
            _emit(job_id, "__END__")

    threading.Thread(target=_worker, daemon=True).start()
    return jsonify({"ok": True, "job_id": job_id})


@app.route("/api/splunk/indexes")
def api_splunk_indexes():
    """Live Splunk index list from management REST API (8089)."""
    cfg = load_config()
    err = _splunk_sync_precheck(cfg)
    if err:
        return jsonify({"ok": False, "error": err, "indexes": []}), 200
    default_index = (cfg.get("default_index") or "test").strip()
    try:
        indexes = fetch_splunk_index_names(cfg)
        if default_index and default_index not in indexes:
            indexes = sorted(set(indexes + [default_index]), key=str.lower)
        return jsonify({
            "ok": True,
            "indexes": indexes,
            "default_index": default_index,
            "source": "splunk_api",
        })
    except Exception as e:
        cached = list_indexes()
        if cached:
            if default_index and default_index not in cached:
                cached = sorted(set(cached + [default_index]), key=str.lower)
            return jsonify({
                "ok": True,
                "indexes": cached,
                "default_index": default_index,
                "source": "cache",
                "warning": str(e),
            })
        return jsonify({"ok": False, "error": str(e), "indexes": []}), 200


@app.route("/api/splunk/index-sourcetypes")
def api_splunk_index_sourcetypes():
    q = request.args.get("q", "").strip()
    idx = request.args.get("index", "").strip()
    return jsonify({
        "items": list_splunk_pairs(q=q, index_filter=idx),
        "last_sync_at": mapping_get_meta("last_sync_at"),
        "count": mapping_get_meta("last_sync_count"),
        "indexes": list_indexes(),
    })


@app.route("/api/splunk/detection-sourcetypes")
def api_detection_sourcetypes():
    cfg = load_config()
    items = collect_detection_sourcetypes_from_config(cfg)
    mapped = {m["detection_sourcetype"] for m in list_mappings()}
    return jsonify({
        "items": [
            {"sourcetype": s, "mapped": s in mapped} for s in items
        ],
    })


@app.route("/api/splunk/mappings", methods=["GET", "POST"])
def api_splunk_mappings():
    if request.method == "GET":
        return jsonify({"items": list_mappings()})
    body = request.get_json(force=True)
    try:
        row = upsert_mapping(
            body.get("detection_sourcetype", ""),
            body.get("replay_sourcetype", ""),
            body.get("target_index", ""),
            notes=body.get("notes", ""),
            auto_matched=bool(body.get("auto_matched", False)),
        )
        return jsonify({"ok": True, "mapping": row})
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@app.route("/api/splunk/mappings/<int:mid>", methods=["DELETE"])
def api_splunk_mapping_delete(mid: int):
    if delete_mapping(mid):
        return jsonify({"ok": True})
    return jsonify({"ok": False, "error": "not found"}), 404


@app.route("/api/splunk/mappings/auto-match", methods=["POST"])
def api_splunk_auto_match():
    try:
        return jsonify(auto_match_mappings())
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@app.route("/api/splunk/routing-cache")
def api_splunk_routing_cache():
    """Fast lookup payload for Attack Test index suggestions (SQLite only, no catalog walk)."""
    cfg = load_config()
    return jsonify({
        "ok": True,
        "default_index": cfg.get("default_index", "test"),
        "splunk_synced": bool(mapping_get_meta("last_sync_at")),
        "last_sync_at": mapping_get_meta("last_sync_at"),
        "mappings": get_mapping_map(),
        "inventory": splunk_inventory_index(),
        "indexes": list_indexes(),
    })


@app.route("/api/splunk/routing-matrix", methods=["GET"])
def api_splunk_routing_matrix():
    """Compare replay detection sourcetypes vs Splunk inventory + manual mappings."""
    cfg = load_config()
    catalog, err = _full_detection_catalog(cfg)
    if err and not catalog:
        return jsonify({"ok": False, "error": err, "rows": []}), 200
    data = build_routing_matrix(
        catalog, default_index=cfg.get("default_index", "test"),
    )
    data["splunk_indexes"] = list_indexes()
    data["mapping_count"] = len(list_mappings())
    if err:
        data["warning"] = err
    return jsonify(data)


@app.route("/api/splunk/apply-routing-suggestions", methods=["POST"])
def api_apply_routing_suggestions():
    """Save Splunk-matched suggestions as sourcetype_mappings (unmapped replay STs only)."""
    body = request.get_json(force=True) or {}
    only_unmapped = body.get("only_unmapped", True)
    cfg = load_config()
    catalog, err = _full_detection_catalog(cfg)
    if err and not catalog:
        return jsonify({"ok": False, "error": err}), 400
    matrix = build_routing_matrix(catalog, default_index=cfg.get("default_index", "test"))
    created = skipped = 0
    for row in matrix.get("rows") or []:
        if only_unmapped and row.get("manual_index"):
            skipped += 1
            continue
        if row.get("status") not in ("splunk_match", "splunk_ambiguous_st") or not row.get("in_splunk"):
            skipped += 1
            continue
        upsert_mapping(
            row["replay_sourcetype"],
            row.get("suggested_replay_sourcetype") or row["replay_sourcetype"],
            row["suggested_index"],
            auto_matched=True,
            notes="from Splunk inventory via Index Planner",
        )
        created += 1
    return jsonify({"ok": True, "created": created, "skipped": skipped})


@app.route("/api/replay/preview", methods=["POST"])
def api_replay_preview():
    """Suggest Splunk indexes per selected replay item before running."""
    body = request.get_json(force=True) or {}
    cfg = load_config()
    mode = body.get("mode", "detections")
    items = body.get("items") or []
    if not items:
        return jsonify({"ok": False, "error": "no items selected"}), 400
    fallback = body.get("index") or cfg.get("default_index", "test")
    use_map = body.get("use_index_mapping")
    if use_map is None:
        use_map = cfg.get("use_index_mapping", True)
    catalog = None
    if mode == "detections" and use_map:
        catalog, _ = _full_detection_catalog(cfg)
    result = preview_replay_routing(
        mode, items,
        default_index=fallback,
        use_mapping=bool(use_map),
        catalog_detections=catalog,
    )
    return jsonify(result)


@app.route("/api/splunk/resolve-index", methods=["POST"])
def api_resolve_index():
    body = request.get_json(force=True) or {}
    cfg = load_config()
    mode = body.get("mode", "detections")
    item = body.get("item") or {}
    fallback = body.get("index") or cfg.get("default_index", "test")
    use_map = body.get("use_index_mapping", True)
    catalog = None
    if mode == "detections" and use_map:
        catalog, _ = _full_detection_catalog(cfg)
    preview = preview_replay_routing(
        mode, [item], default_index=fallback,
        use_mapping=bool(use_map), catalog_detections=catalog,
    )
    row = preview["items"][0] if preview.get("items") else {}
    return jsonify({
        "index": row.get("resolved_index") or fallback,
        "fallback": fallback,
        "routing": row,
        "splunk_synced": preview.get("splunk_synced"),
    })


@app.route("/api/splunk/suggest-sourcetype", methods=["POST"])
def api_suggest_sourcetype():
    body = request.get_json(force=True) or {}
    st = (body.get("sourcetype") or "").strip()
    if not st:
        return jsonify({"ok": False, "error": "sourcetype required"}), 400
    cfg = load_config()
    sug = suggest_for_detection_sourcetype(st, default_index=cfg.get("default_index", "test"))
    return jsonify({"ok": True, **sug})


@app.route("/api/schedules/<sid>", methods=["DELETE"])
def api_schedules_delete(sid: str):
    with db_conn() as c:
        c.execute("DELETE FROM schedules WHERE id=?", (sid,))
    try:
        scheduler.remove_job(sid)
    except Exception:
        pass
    return jsonify({"ok": True})


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------

init_db()
_load_schedules_on_start()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5055, debug=False, threaded=True)
