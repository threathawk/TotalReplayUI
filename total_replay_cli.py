"""Build shell commands for Splunk TOTAL-REPLAY CLI (local or remote host)."""

from __future__ import annotations

import shlex
from pathlib import Path
from typing import Any

from splunk_transport import resolve_hec_host


def build_total_replay_shell_command(
    tr_dir: str,
    python_cmd: str,
    cfg: dict[str, Any],
    mode: str,
    items: list[dict],
    index_name: str,
) -> str:
    """Build a shell command. Path validation is done by local_replay or remote_client."""
    tr = (tr_dir or "").strip().rstrip("/")
    if not tr:
        raise ValueError("TOTAL-REPLAY directory is not configured")

    py = (python_cmd or "python3").strip() or "python3"
    parts = [f"cd {shlex.quote(tr)}"]

    host = resolve_hec_host(cfg)
    token = (cfg.get("hec_token") or "").strip()
    if "://" in token or token.startswith("http"):
        raise ValueError(
            "HEC token in Settings is not valid (looks like a URL). "
            "Paste the Splunk HEC token UUID from Settings → Data Inputs → HTTP Event Collector."
        )
    if host:
        parts.append(f"export SPLUNK_HOST={shlex.quote(host)}")
    if token:
        parts.append(f"export SPLUNK_HEC_TOKEN={shlex.quote(token)}")

    if mode == "detections":
        names = [
            it.get("detection_name") or it.get("name")
            for it in items
            if it.get("detection_name") or it.get("name")
        ]
        if not names:
            raise ValueError("No detection names selected")
        arg = ",".join(names)
        parts.append(f"{py} total_replay.py -n {shlex.quote(arg)} -i {shlex.quote(index_name)}")
    elif mode == "guids":
        guids = [
            it.get("detection_id") or it.get("id")
            for it in items
            if it.get("detection_id") or it.get("id")
        ]
        if not guids:
            raise ValueError("No detection GUIDs selected")
        arg = ",".join(guids)
        parts.append(f"{py} total_replay.py -g {shlex.quote(arg)} -i {shlex.quote(index_name)}")
    elif mode == "cached":
        cache_dirs = sorted({it.get("cache_dir") or "" for it in items if it.get("cache_dir")})
        if len(cache_dirs) != 1 or not cache_dirs[0]:
            paths_list = [it.get("cache_path") for it in items if it.get("cache_path")]
            if not paths_list:
                raise ValueError("No cached replay paths selected")
            cache_dir = str(Path(paths_list[0]).expanduser().parent)
        else:
            cache_dir = cache_dirs[0]
        parts.append(
            f"{py} total_replay.py -ld {shlex.quote(cache_dir)} -i {shlex.quote(index_name)}"
        )
    else:
        raise ValueError(f"Unsupported CLI mode: {mode}")

    return " && ".join(parts)
