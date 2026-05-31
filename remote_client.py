"""
SSH client for remote TOTAL-REPLAY server: catalog browsing and CLI execution.
See: https://github.com/splunk/attack_data/tree/master/total_replay
"""

from __future__ import annotations

import json
import os
import shlex
import threading
import uuid
from pathlib import Path
from typing import Any, Callable, Optional

import paramiko
import yaml

from ssh_connect import build_ssh_connect_kwargs, open_ssh_client
from total_replay_cli import build_total_replay_shell_command

_ssh_client: Optional[paramiko.SSHClient] = None
_ssh_lock = threading.Lock()
_ssh_meta: dict[str, Any] = {"connected": False, "error": None, "host": None}


def config_file_path() -> Path:
    app_dir = Path(__file__).resolve().parent
    data_dir = Path(os.environ.get("TOTALREPLAY_DATA_DIR", str(app_dir / "data")))
    return Path(os.environ.get("TOTALREPLAY_CONFIG", str(data_dir / "config.json")))


def ssh_session_status() -> dict[str, Any]:
    with _ssh_lock:
        meta = dict(_ssh_meta)
        if _ssh_client is not None:
            transport = _ssh_client.get_transport()
            meta["connected"] = transport is not None and transport.is_active()
        else:
            meta["connected"] = False
        return meta


def close_ssh_session() -> None:
    global _ssh_client
    with _ssh_lock:
        if _ssh_client is not None:
            try:
                _ssh_client.close()
            except Exception:
                pass
            _ssh_client = None
        _ssh_meta.update(connected=False, error=None, host=None)


def ensure_ssh_client(cfg: dict) -> paramiko.SSHClient:
    global _ssh_client
    kwargs = build_ssh_connect_kwargs(cfg)
    host = kwargs["hostname"]
    port = kwargs["port"]
    user = kwargs["username"]
    sig = (host, port, user)
    with _ssh_lock:
        if _ssh_client is not None:
            transport = _ssh_client.get_transport()
            if transport and transport.is_active() and _ssh_meta.get("signature") == sig:
                return _ssh_client
            close_ssh_session()

        client = open_ssh_client(cfg)
        _ssh_client = client
        _ssh_meta.update(connected=True, error=None, host=host, signature=sig)
        return client


def ssh_exec(
    cfg: dict,
    command: str,
    timeout: int = 600,
    on_line: Optional[Callable[[str], None]] = None,
    *,
    use_pty: bool = True,
) -> tuple[int, str, str]:
    """Run a remote command; optionally stream stdout lines to on_line."""
    client = ensure_ssh_client(cfg)
    stdin, stdout, stderr = client.exec_command(command, timeout=timeout, get_pty=use_pty)
    out_chunks: list[str] = []
    err_chunks: list[str] = []

    while True:
        if stdout.channel.recv_ready():
            chunk = stdout.channel.recv(4096).decode("utf-8", errors="replace")
            out_chunks.append(chunk)
            if on_line:
                for line in chunk.splitlines():
                    on_line(line)
        if stderr.channel.recv_stderr_ready():
            chunk = stderr.channel.recv_stderr(4096).decode("utf-8", errors="replace")
            err_chunks.append(chunk)
            if on_line:
                for line in chunk.splitlines():
                    on_line(line)
        if stdout.channel.exit_status_ready():
            while stdout.channel.recv_ready():
                chunk = stdout.channel.recv(4096).decode("utf-8", errors="replace")
                out_chunks.append(chunk)
                if on_line:
                    for line in chunk.splitlines():
                        on_line(line)
            while stderr.channel.recv_stderr_ready():
                chunk = stderr.channel.recv_stderr(4096).decode("utf-8", errors="replace")
                err_chunks.append(chunk)
                if on_line:
                    for line in chunk.splitlines():
                        on_line(line)
            break

    code = stdout.channel.recv_exit_status()
    # Drain any remaining buffered stdout (large catalog JSON over non-PTY channels).
    if not use_pty:
        while stdout.channel.recv_ready():
            out_chunks.append(stdout.channel.recv(65536).decode("utf-8", errors="replace"))
        while stderr.channel.recv_stderr_ready():
            err_chunks.append(stderr.channel.recv_stderr(65536).decode("utf-8", errors="replace"))
    return code, "".join(out_chunks), "".join(err_chunks)


def _write_catalog_result_block() -> str:
    """Append to remote scripts: write JSON result to TR_CATALOG_OUT path."""
    return """
out_path = os.environ.get("TR_CATALOG_OUT")
result = {"count": len(items), "items": items}
if out_path:
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f)
else:
    print(json.dumps(result))
"""


def _run_remote_catalog_script(cfg: dict, script_body: str, timeout: int = 600) -> dict:
    """Run catalog builder on remote host; read JSON from a temp file (avoids huge stdout)."""
    token = uuid.uuid4().hex
    remote_path = f"/tmp/totalreplay_catalog_{token}.json"
    py = _python_cmd(cfg)
    env = f"TR_CATALOG_OUT={shlex.quote(remote_path)}"
    cmd = f"{env} {py} -c {shlex.quote(script_body)}"
    code, out, err = ssh_exec(cfg, cmd, timeout=timeout, use_pty=False)
    if code != 0:
        raise RuntimeError((err or out or "remote catalog script failed").strip()[:500])
    try:
        raw = ssh_fetch_file_bytes(cfg, remote_path)
    finally:
        ssh_exec(cfg, f"rm -f {shlex.quote(remote_path)}", timeout=30, use_pty=False)
    try:
        return json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError as e:
        raise RuntimeError(
            f"invalid JSON from remote catalog file ({len(raw)} bytes): {e}"
        )


def ssh_read_file(cfg: dict, remote_path: str) -> str:
    code, out, err = ssh_exec(cfg, f"cat {shlex.quote(remote_path)}", timeout=120)
    if code != 0:
        raise RuntimeError(err or out or f"failed to read {remote_path}")
    return out


def is_remote_mode(cfg: dict) -> bool:
    mode = str(cfg.get("connection_mode") or "local").strip().lower()
    return mode in ("remote", "ssh", "true", "1")


def remote_paths(cfg: dict) -> dict[str, str]:
    tr = (cfg.get("remote_total_replay_dir") or "").strip()
    sc = (cfg.get("remote_security_content_path") or cfg.get("security_content_path") or "").strip()
    ad = (cfg.get("remote_attack_data_path") or cfg.get("attack_data_path") or "").strip()
    return {"total_replay": tr, "security_content": sc, "attack_data": ad}


def _remote_path_exists(cfg: dict, remote_path: str, *, is_file: bool = True) -> bool:
    flag = "-f" if is_file else "-d"
    code, _, _ = ssh_exec(
        cfg,
        f"test {flag} {shlex.quote(remote_path)}",
        timeout=30,
        use_pty=False,
    )
    return code == 0


def discover_remote_total_replay_dir(cfg: dict) -> str:
    """Find total_replay.py on the SSH host (common lab paths, then find)."""
    candidates = [
        "/root/splunk-projects/attack_data/total_replay",
        "/opt/attack_data/total_replay",
        "/opt/splunk-projects/attack_data/total_replay",
        "/root/attack_data/total_replay",
    ]
    configured = (cfg.get("remote_total_replay_dir") or "").strip().rstrip("/")
    if configured and configured not in candidates:
        candidates.insert(0, configured)

    for tr in candidates:
        if tr and _remote_path_exists(cfg, f"{tr.rstrip('/')}/total_replay.py"):
            return tr.rstrip("/")

    code, out, _ = ssh_exec(
        cfg,
        "find /root /opt /home -maxdepth 7 -name total_replay.py 2>/dev/null | head -8",
        timeout=90,
        use_pty=False,
    )
    if code == 0 and out.strip():
        for line in out.strip().splitlines():
            script = line.strip()
            if script.endswith("/total_replay.py"):
                return str(Path(script).parent)
    return ""


def ensure_remote_total_replay_dir(cfg: dict) -> str:
    """
    Return a remote TOTAL-REPLAY directory that contains total_replay.py.
    Auto-discovers on the SSH host when the saved path is missing or wrong locally.
    """
    tr = (cfg.get("remote_total_replay_dir") or "").strip().rstrip("/")
    if tr and _remote_path_exists(cfg, f"{tr}/total_replay.py"):
        return tr

    found = discover_remote_total_replay_dir(cfg)
    if found:
        if found != tr:
            updates = {"remote_total_replay_dir": found}
            _persist_config_updates(cfg, updates)
        return found

    if tr:
        raise ValueError(
            f"total_replay.py not found on the remote SSH host under {tr}. "
            "Open Settings → set the correct TOTAL-REPLAY directory, or click "
            "'Load paths from remote config.yml' after fixing the path on the server."
        )
    raise ValueError(
        "Remote TOTAL-REPLAY directory is not configured. "
        "Set it in Settings (path on the SSH host, not this machine)."
    )


def _path_usable(path: str) -> bool:
    p = (path or "").strip()
    if not p:
        return False
    low = p.lower()
    if "path/to" in low or "/your/" in low or "your/" in low:
        return False
    return True


def _infer_paths_script(tr_path: str) -> str:
    tp = json.dumps(tr_path)
    return f"""
import json, os
from pathlib import Path
tr = Path(os.path.expanduser({tp}))
ad = ""
sc = ""
if tr.name == "total_replay":
    ad_parent = tr.parent
    if (ad_parent / "datasets").is_dir() or ad_parent.name == "attack_data":
        ad = str(ad_parent)
    search = []
    if ad:
        search.append(Path(ad).parent / "security_content" / "detections")
        search.append(Path(ad).parent / "security_content")
    search.extend([
        Path("/root/splunk-projects/security_content/detections"),
        Path("/root/splunk-projects/security_content"),
        tr.parent.parent / "security_content" / "detections",
    ])
    for cand in search:
        c = Path(os.path.expanduser(str(cand)))
        if c.is_dir():
            sc = str(c)
            break
print(json.dumps({{"attack_data": ad, "security_content": sc}}))
"""


def _infer_paths_on_remote(cfg: dict, tr: str) -> dict[str, str]:
    code, out, err = ssh_exec(
        cfg, f"{_python_cmd(cfg)} -c {shlex.quote(_infer_paths_script(tr))}",
        timeout=60, use_pty=False,
    )
    if code != 0:
        return {"security_content": "", "attack_data": ""}
    line = out.strip().split("\n")[-1] if out.strip() else "{}"
    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        return {"security_content": "", "attack_data": ""}
    return {
        "security_content": (data.get("security_content") or "").strip(),
        "attack_data": (data.get("attack_data") or "").strip(),
    }


def resolve_remote_paths(cfg: dict) -> tuple[dict[str, str], Optional[dict[str, str]]]:
    """
    Resolve security_content and attack_data paths for remote mode.
    Returns (resolved paths, config updates to persist) or (paths, None).
    """
    tr = ensure_remote_total_replay_dir(cfg)
    paths = remote_paths(cfg)
    paths["total_replay"] = tr
    sc, ad = paths["security_content"], paths["attack_data"]
    updates: dict[str, str] = {}

    if tr:
        try:
            settings = load_remote_total_replay_settings(cfg)
            sc_cfg = (settings.get("security_content_detection_path") or "").strip()
            ad_cfg = (settings.get("attack_data_dir_path") or "").strip()
            if _path_usable(sc_cfg) and not _path_usable(sc):
                sc = sc_cfg
            if _path_usable(ad_cfg) and not _path_usable(ad):
                ad = ad_cfg
        except Exception:
            pass

    if tr and (not _path_usable(sc) or not _path_usable(ad)):
        inferred = _infer_paths_on_remote(cfg, tr)
        if not _path_usable(sc) and _path_usable(inferred.get("security_content", "")):
            sc = inferred["security_content"]
        if not _path_usable(ad) and _path_usable(inferred.get("attack_data", "")):
            ad = inferred["attack_data"]

    resolved = {"total_replay": tr, "security_content": sc, "attack_data": ad}

    if _path_usable(sc) and sc != (cfg.get("remote_security_content_path") or "").strip():
        updates["remote_security_content_path"] = sc
        updates["security_content_path"] = sc
    if _path_usable(ad) and ad != (cfg.get("remote_attack_data_path") or "").strip():
        updates["remote_attack_data_path"] = ad
        updates["attack_data_path"] = ad

    return resolved, (updates if updates else None)


def _persist_config_updates(cfg: dict, updates: dict[str, str]) -> None:
    cfg.update(updates)
    path = config_file_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(cfg, indent=2))


def ensure_remote_paths(
    cfg: dict,
    *,
    require_security_content: bool = True,
    require_attack_data: bool = False,
) -> dict[str, str]:
    """Resolve paths (auto-detect on remote host); persist when discovered."""
    paths, updates = resolve_remote_paths(cfg)
    if updates:
        _persist_config_updates(cfg, updates)
    if not paths["total_replay"]:
        raise ValueError("Remote TOTAL-REPLAY directory is not configured in Settings")
    if require_security_content and not _path_usable(paths["security_content"]):
        raise ValueError(
            "security_content path not set. In Settings: set the remote security_content path, "
            "click 'Load paths from remote configuration/config.yml', or set "
            "security_content_detection_path in total_replay/configuration/config.yml "
            "(e.g. /root/splunk-projects/security_content/detections)."
        )
    if require_attack_data and not _path_usable(paths["attack_data"]):
        raise ValueError(
            "attack_data path not set. Set attack_data_dir_path in remote config.yml "
            "or enter the path in Settings."
        )
    return paths


def load_remote_total_replay_settings(cfg: dict) -> dict[str, Any]:
    paths = remote_paths(cfg)
    tr = paths["total_replay"]
    if not tr:
        raise ValueError("Remote TOTAL-REPLAY directory is not configured")
    raw = ssh_read_file(cfg, f"{tr.rstrip('/')}/configuration/config.yml")
    doc = yaml.safe_load(raw) or {}
    return doc.get("settings") or {}


def sync_paths_from_remote_config(cfg: dict) -> dict[str, str]:
    tr = ensure_remote_total_replay_dir(cfg)
    resolved, _ = resolve_remote_paths(cfg)
    return {
        "remote_total_replay_dir": tr,
        "remote_security_content_path": resolved["security_content"],
        "remote_attack_data_path": resolved["attack_data"],
        "security_content_path": resolved["security_content"],
        "attack_data_path": resolved["attack_data"],
    }


def _python_cmd(cfg: dict) -> str:
    return (cfg.get("remote_python_cmd") or "python3").strip() or "python3"


_REMOTE_STORY_EXTRACT = """
def _extract_stories(doc):
    tags = doc.get("tags") if isinstance(doc.get("tags"), dict) else {}
    seen = []
    for src in (tags, doc):
        if not isinstance(src, dict):
            continue
        for key in ("analytic_story", "analytic_stories"):
            v = src.get(key) or []
            if isinstance(v, list):
                for x in v:
                    s = str(x).strip()
                    if s and s not in seen:
                        seen.append(s)
            elif v:
                s = str(v).strip()
                if s and s not in seen:
                    seen.append(s)
    return sorted(seen, key=str.lower)
"""


def _catalog_detections_script(sc_path: str) -> str:
    sp = json.dumps(sc_path)
    return f"""
import json, os, yaml
from pathlib import Path
{_REMOTE_STORY_EXTRACT}
sc = os.path.expanduser({sp})
root = Path(sc)
if not root.exists():
    print(json.dumps({{"items": [], "error": "path not found"}}))
    raise SystemExit(0)
det_root = root if root.name == "detections" else root / "detections"
if not det_root.exists():
    det_root = root
items = []
for yml in det_root.rglob("*.yml"):
    try:
        doc = yaml.safe_load(yml.read_text(encoding="utf-8"))
    except Exception:
        continue
    if not isinstance(doc, dict):
        continue
    name, det_id = doc.get("name"), doc.get("id")
    if not name or not det_id:
        continue
    tests = doc.get("tests") or []
    has_data = any(
        isinstance(t, dict) and (t.get("attack_data") or [])
        for t in tests
    )
    if not has_data:
        continue
    tags = doc.get("tags") if isinstance(doc.get("tags"), dict) else {{}}
    techniques = []
    tactics = []
    for key in ("mitre_attack_id", "mitre_attack_technique_id", "mitre_technique_id"):
        v = tags.get(key) or []
        if isinstance(v, list):
            techniques.extend([str(x).strip() for x in v if x])
        elif v:
            techniques.append(str(v).strip())
    for key in ("mitre_attack_tactic_id", "mitre_tactic_id", "mitre_attack_tactic"):
        v = tags.get(key) or []
        if isinstance(v, list):
            tactics.extend([str(x).strip() for x in v if x])
        elif v:
            tactics.append(str(v).strip())
    techniques = sorted(set(techniques))
    tactics = sorted(set(tactics))
    data_refs = 0
    sourcetypes = []
    seen_st = set()
    for t in tests:
        if isinstance(t, dict):
            for a in (t.get("attack_data") or []):
                if isinstance(a, dict) and a.get("data"):
                    data_refs += 1
                if isinstance(a, dict) and a.get("sourcetype"):
                    st = str(a.get("sourcetype")).strip()
                    if st and st not in seen_st:
                        seen_st.add(st)
                        sourcetypes.append(st)
    stories = _extract_stories(doc)
    items.append({{
        "name": name,
        "id": det_id,
        "file": str(yml.relative_to(root)),
        "yml_path": str(yml),
        "analytic_story": stories,
        "use_cases": stories,
        "mitre_techniques": techniques,
        "mitre_tactics": tactics,
        "mitre_attack_id": techniques,
        "tests_count": len(tests),
        "attack_data_count": data_refs,
        "sourcetypes": sourcetypes,
    }})
items.sort(key=lambda x: x["name"].lower())
""" + _write_catalog_result_block()


def _catalog_detections_full_script(sc_path: str) -> str:
    """Like catalog detections but includes tests/attack_data metadata for sourcetype inventory."""
    sp = json.dumps(sc_path)
    return f"""
import json, os, yaml
from pathlib import Path
{_REMOTE_STORY_EXTRACT}
sc = os.path.expanduser({sp})
root = Path(sc)
if not root.exists():
    print(json.dumps({{"items": [], "error": "path not found"}}))
    raise SystemExit(0)
det_root = root if root.name == "detections" else root / "detections"
if not det_root.exists():
    det_root = root
items = []
for yml in det_root.rglob("*.yml"):
    try:
        doc = yaml.safe_load(yml.read_text(encoding="utf-8"))
    except Exception:
        continue
    if not isinstance(doc, dict):
        continue
    name, det_id = doc.get("name"), doc.get("id")
    if not name or not det_id:
        continue
    tests_raw = doc.get("tests") or []
    normalized = []
    for t in tests_raw:
        if not isinstance(t, dict):
            continue
        att = t.get("attack_data") or []
        if not att:
            continue
        normalized.append({{
            "name": t.get("name", ""),
            "attack_data": [
                {{
                    "source": a.get("source", "") if isinstance(a, dict) else "",
                    "sourcetype": a.get("sourcetype", "") if isinstance(a, dict) else "",
                    "data": a.get("data", "") if isinstance(a, dict) else "",
                }}
                for a in att if isinstance(a, dict) and a.get("data")
            ],
        }})
    if not normalized:
        continue
    tags = doc.get("tags") if isinstance(doc.get("tags"), dict) else {{}}
    techniques = []
    tactics = []
    for key in ("mitre_attack_id", "mitre_attack_technique_id", "mitre_technique_id"):
        v = tags.get(key) or []
        if isinstance(v, list):
            techniques.extend([str(x).strip() for x in v if x])
        elif v:
            techniques.append(str(v).strip())
    for key in ("mitre_attack_tactic_id", "mitre_tactic_id", "mitre_attack_tactic"):
        v = tags.get(key) or []
        if isinstance(v, list):
            tactics.extend([str(x).strip() for x in v if x])
        elif v:
            tactics.append(str(v).strip())
    stories = _extract_stories(doc)
    items.append({{
        "name": name,
        "id": det_id,
        "file": str(yml.relative_to(root)),
        "analytic_story": stories,
        "use_cases": stories,
        "mitre_techniques": sorted(set(techniques)),
        "mitre_tactics": sorted(set(tactics)),
        "mitre_attack_id": sorted(set(techniques)),
        "tests": normalized,
    }})
items.sort(key=lambda x: x["name"].lower())
""" + _write_catalog_result_block()


def remote_detection_catalog_full(cfg: dict) -> list[dict]:
    paths = ensure_remote_paths(cfg)
    data = _run_remote_catalog_script(
        cfg, _catalog_detections_full_script(paths["security_content"]), timeout=900,
    )
    if data.get("error"):
        raise RuntimeError(data["error"])
    return data.get("items") or []


def _catalog_files_script(ad_path: str) -> str:
    ap = json.dumps(ad_path)
    return f"""
import json, os
from pathlib import Path
root = Path(os.path.expanduser({ap}))
if not root.exists():
    print(json.dumps({{"items": [], "error": "path not found"}}))
    raise SystemExit(0)
datasets = root / "datasets" if (root / "datasets").exists() else root
exts = {{".log", ".json", ".txt", ".csv", ".xml"}}
items = []
for p in datasets.rglob("*"):
    if not p.is_file() or p.suffix.lower() not in exts:
        continue
    try:
        size = p.stat().st_size
    except OSError:
        continue
    is_lfs = False
    if size <= 200:
        try:
            if p.read_bytes()[:40].startswith(b"version https://git-lfs"):
                is_lfs = True
        except Exception:
            pass
    items.append({{
        "path": str(p.relative_to(root)),
        "abs_path": str(p),
        "size": size,
        "is_lfs_pointer": is_lfs,
        "source": "",
        "sourcetype": "",
    }})
items.sort(key=lambda x: x["path"].lower())
""" + _write_catalog_result_block()


def _catalog_cached_script(tr_path: str) -> str:
    tp = json.dumps(tr_path)
    return f"""
import json, os, yaml
from pathlib import Path
tr = Path(os.path.expanduser({tp}))
cache_dirs = []
cfg = tr / "configuration" / "config.yml"
cache_name = "replayed_yaml_cache"
if cfg.exists():
    try:
        s = yaml.safe_load(cfg.read_text()) or {{}}
        cache_name = (s.get("settings") or {{}}).get("replayed_yaml_cache_dir_name") or cache_name
    except Exception:
        pass
for base in [tr / "output", tr / cache_name, tr / "output" / cache_name]:
    if base.exists():
        cache_dirs.append(base)
items = []
seen = set()
for base in cache_dirs:
    for yml in base.rglob("*.yml"):
        key = str(yml)
        if key in seen:
            continue
        seen.add(key)
        try:
            doc = yaml.safe_load(yml.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(doc, dict) or not doc.get("name"):
            continue
        items.append({{
            "name": doc.get("name", ""),
            "id": doc.get("id", ""),
            "cache_path": str(yml),
            "log_path": doc.get("attack_data_output_file_path", ""),
            "sourcetype": doc.get("attack_data_sourcetype", ""),
            "source": doc.get("attack_data_source", ""),
            "analytic_story": doc.get("analytic_story") or [],
        }})
items.sort(key=lambda x: (x.get("name") or "").lower())
""" + _write_catalog_result_block()


def _detection_attack_data_script(sc_path: str, detection_id: str) -> str:
    sp = json.dumps(sc_path)
    did = json.dumps(detection_id)
    return f"""
import json, os, yaml
from pathlib import Path
sc = os.path.expanduser({sp})
target_id = {did}
root = Path(sc)
det_root = root if root.name == "detections" else root / "detections"
if not det_root.exists():
    det_root = root
items = []
for yml in det_root.rglob("*.yml"):
    try:
        doc = yaml.safe_load(yml.read_text(encoding="utf-8"))
    except Exception:
        continue
    if not isinstance(doc, dict) or doc.get("id") != target_id:
        continue
    for t in doc.get("tests") or []:
        if not isinstance(t, dict):
            continue
        for a in t.get("attack_data") or []:
            if isinstance(a, dict) and a.get("data"):
                items.append({{
                    "source": a.get("source", ""),
                    "sourcetype": a.get("sourcetype", ""),
                    "data": a.get("data", ""),
                }})
    break
result = {{"id": target_id, "attack_data": items}}
out_path = os.environ.get("TR_CATALOG_OUT")
if out_path:
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f)
else:
    print(json.dumps(result))
"""


def remote_detection_attack_data(cfg: dict, detection_id: str) -> list[dict]:
    paths = ensure_remote_paths(cfg)
    sc = paths["security_content"]
    data = _run_remote_catalog_script(cfg, _detection_attack_data_script(sc, detection_id), timeout=120)
    return data.get("attack_data") or []


def remote_catalog_detections(cfg: dict) -> dict:
    try:
        paths = ensure_remote_paths(cfg)
    except ValueError as e:
        return {"count": 0, "items": [], "error": str(e)}
    return _run_remote_catalog_script(cfg, _catalog_detections_script(paths["security_content"]), timeout=900)


def remote_catalog_files(cfg: dict) -> dict:
    try:
        paths = ensure_remote_paths(cfg, require_security_content=False, require_attack_data=True)
    except ValueError as e:
        return {"count": 0, "items": [], "error": str(e)}
    return _run_remote_catalog_script(cfg, _catalog_files_script(paths["attack_data"]), timeout=900)


def remote_catalog_cached(cfg: dict) -> dict:
    try:
        tr = ensure_remote_total_replay_dir(cfg)
    except ValueError as e:
        return {"count": 0, "items": [], "error": str(e)}
    return _run_remote_catalog_script(cfg, _catalog_cached_script(tr), timeout=600)


def test_remote_ssh(cfg: dict) -> dict[str, Any]:
    try:
        ensure_ssh_client(cfg)
        result: dict[str, Any] = {"ok": True, "ssh": ssh_session_status()}
        try:
            tr = ensure_remote_total_replay_dir(cfg)
            result["total_replay_dir"] = tr
            result["total_replay_script_ok"] = True
        except Exception as e:
            result["total_replay_script_ok"] = False
            result["total_replay_error"] = str(e)
        if remote_paths(cfg)["total_replay"] or result.get("total_replay_dir"):
            try:
                resolved, updates = resolve_remote_paths(cfg)
                if updates:
                    _persist_config_updates(cfg, updates)
                result["paths"] = resolved
                result["synced_paths"] = {
                    "remote_security_content_path": resolved["security_content"],
                    "remote_attack_data_path": resolved["attack_data"],
                    "security_content_path": resolved["security_content"],
                    "attack_data_path": resolved["attack_data"],
                }
                result["remote_config_ok"] = _path_usable(resolved["security_content"])
                if not result["remote_config_ok"]:
                    result["remote_config_error"] = (
                        "Could not resolve security_content path. "
                        "Set security_content_detection_path in remote config.yml "
                        "or enter the path manually in Settings."
                    )
            except Exception as e:
                result["remote_config_ok"] = False
                result["remote_config_error"] = str(e)
        else:
            result["paths"] = remote_paths(cfg)
        return result
    except Exception as e:
        close_ssh_session()
        return {"ok": False, "error": str(e)}


def test_hec_from_remote(cfg: dict, index_name: str = "test") -> dict[str, Any]:
    """Run a HEC POST from the remote SSH host (same path as TOTAL-REPLAY CLI)."""
    host = (cfg.get("splunk_host") or "").strip()
    token = (cfg.get("hec_token") or "").strip()
    port = int(cfg.get("splunk_port") or 8088)
    scheme = "https" if cfg.get("use_https") else "http"
    if not host or not token:
        return {"ok": False, "error": "Splunk host and HEC token must be configured"}
    if "://" in token or token.startswith("http"):
        return {
            "ok": False,
            "error": "HEC token is a URL, not a Splunk token UUID. Update Settings → HEC token.",
        }
    idx = shlex.quote(index_name)
    url = f"{scheme}://{host}:{port}/services/collector/raw?index={idx}&sourcetype=_json&source=totalreplay-remote-test"
    cmd = (
        f"curl -sS -o /tmp/tr_hec_test.out -w '%{{http_code}}' "
        f"-X POST {shlex.quote(url)} "
        f"-H {shlex.quote(f'Authorization: Splunk {token}')} "
        f"-d 'test event from totalreplay-ui'"
    )
    code, out, err = ssh_exec(cfg, cmd, timeout=30, use_pty=False)
    http_code = (out.strip()[-3:] if out.strip() else "") or "000"
    try:
        body = ssh_read_file(cfg, "/tmp/tr_hec_test.out")[:300]
    except Exception:
        body = err or ""
    ok = http_code == "200"
    hint = ""
    if http_code == "403":
        hint = (
            f"403 from remote host to {host}:{port}: invalid token or index '{index_name}' "
            "not allowed on this HEC token. In Splunk: Settings → Data Inputs → "
            "HTTP Event Collector → edit token → add index to Allowed Indexes."
        )
    return {
        "ok": ok,
        "http_code": http_code,
        "error": hint or (body if not ok else None),
        "from_host": _ssh_meta.get("host"),
        "splunk_url": url.split("?")[0],
    }


def build_total_replay_command(cfg: dict, mode: str, items: list[dict], index_name: str) -> str:
    tr = ensure_remote_total_replay_dir(cfg)
    return build_total_replay_shell_command(
        tr, _python_cmd(cfg), cfg, mode, items, index_name,
    )


def ssh_fetch_file_bytes(cfg: dict, remote_path: str) -> bytes:
    client = ensure_ssh_client(cfg)
    with client.open_sftp() as sftp:
        with sftp.file(remote_path, "rb") as f:
            return f.read()


def run_total_replay_remote(
    cfg: dict,
    mode: str,
    items: list[dict],
    index_name: str,
    on_line: Callable[[str], None],
) -> tuple[int, str]:
    ensure_ssh_client(cfg)
    cmd = build_total_replay_command(cfg, mode, items, index_name)
    on_line(f"$ {cmd}")
    code, out, err = ssh_exec(cfg, cmd, timeout=3600, on_line=on_line)
    if err.strip():
        on_line(err.strip())
    return code, out
