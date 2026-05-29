"""Run TOTAL-REPLAY on the same machine as the web UI (no SSH)."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any, Callable, Optional

import yaml

from total_replay_cli import build_total_replay_shell_command

_CONFIG_PATH = Path(__file__).resolve().parent / "data" / "config.json"


def _path_usable(p: str) -> bool:
    return bool((p or "").strip()) and Path(os.path.expanduser(p)).expanduser().exists()


def local_paths(cfg: dict) -> dict[str, str]:
    tr = (cfg.get("local_total_replay_dir") or "").strip()
    if not tr:
        ad = (cfg.get("attack_data_path") or "").strip()
        if ad:
            cand = Path(os.path.expanduser(ad)).resolve() / "total_replay"
            if (cand / "total_replay.py").exists():
                tr = str(cand)
    return {
        "total_replay": tr,
        "security_content": (cfg.get("security_content_path") or "").strip(),
        "attack_data": (cfg.get("attack_data_path") or "").strip(),
    }


def load_local_total_replay_settings(tr_dir: str) -> dict[str, Any]:
    tr = Path(os.path.expanduser(tr_dir)).resolve()
    cfg_file = tr / "configuration" / "config.yml"
    if not cfg_file.exists():
        return {}
    doc = yaml.safe_load(cfg_file.read_text(encoding="utf-8")) or {}
    return doc.get("settings") or {}


def resolve_local_paths(cfg: dict) -> tuple[dict[str, str], Optional[dict[str, str]]]:
    paths = local_paths(cfg)
    tr = paths["total_replay"]
    sc, ad = paths["security_content"], paths["attack_data"]
    updates: dict[str, str] = {}

    if tr:
        settings = load_local_total_replay_settings(tr)
        sc_cfg = (settings.get("security_content_detection_path") or "").strip()
        ad_cfg = (settings.get("attack_data_dir_path") or "").strip()
        if _path_usable(sc_cfg) and not _path_usable(sc):
            sc = sc_cfg
        if _path_usable(ad_cfg) and not _path_usable(ad):
            ad = ad_cfg

    resolved = {"total_replay": tr, "security_content": sc, "attack_data": ad}
    if _path_usable(sc) and sc != (cfg.get("security_content_path") or "").strip():
        updates["security_content_path"] = sc
    if _path_usable(ad) and ad != (cfg.get("attack_data_path") or "").strip():
        updates["attack_data_path"] = ad
    if _path_usable(tr) and tr != (cfg.get("local_total_replay_dir") or "").strip():
        updates["local_total_replay_dir"] = tr

    return resolved, (updates if updates else None)


def sync_paths_from_local_config(cfg: dict) -> dict[str, str]:
    resolved, _ = resolve_local_paths(cfg)
    return {
        "local_total_replay_dir": resolved["total_replay"],
        "security_content_path": resolved["security_content"],
        "attack_data_path": resolved["attack_data"],
    }


def _local_python_cmd(cfg: dict) -> str:
    return (cfg.get("local_python_cmd") or cfg.get("remote_python_cmd") or "python3").strip() or "python3"


def build_cached_catalog_local(tr_dir: str) -> dict[str, Any]:
    tr = Path(os.path.expanduser(tr_dir)).resolve()
    if not tr.exists():
        return {"count": 0, "items": [], "error": f"path not found: {tr}"}

    cache_name = "replayed_yaml_cache"
    cfg_file = tr / "configuration" / "config.yml"
    if cfg_file.exists():
        try:
            s = yaml.safe_load(cfg_file.read_text(encoding="utf-8")) or {}
            cache_name = (s.get("settings") or {}).get("replayed_yaml_cache_dir_name") or cache_name
        except Exception:
            pass

    cache_dirs: list[Path] = []
    for base in [tr / "output", tr / cache_name, tr / "output" / cache_name]:
        if base.exists():
            cache_dirs.append(base)

    items: list[dict] = []
    seen: set[str] = set()
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
            items.append({
                "name": doc.get("name", ""),
                "id": doc.get("id", ""),
                "cache_path": str(yml),
                "log_path": doc.get("attack_data_output_file_path", ""),
                "sourcetype": doc.get("attack_data_sourcetype", ""),
                "source": doc.get("attack_data_source", ""),
                "analytic_story": doc.get("analytic_story") or [],
            })
    items.sort(key=lambda x: (x.get("name") or "").lower())
    return {"count": len(items), "items": items}


def run_total_replay_local(
    cfg: dict,
    mode: str,
    items: list[dict],
    index_name: str,
    on_line: Callable[[str], None],
) -> tuple[int, str]:
    paths = local_paths(cfg)
    tr = paths["total_replay"]
    if not tr:
        raise ValueError(
            "Local TOTAL-REPLAY directory is not set. In Settings → Local filesystem, "
            "set TOTAL-REPLAY directory or attack_data path that contains total_replay/."
        )
    script = Path(tr).expanduser() / "total_replay.py"
    if not script.is_file():
        raise ValueError(f"total_replay.py not found on this machine under {tr}")
    cmd = build_total_replay_shell_command(
        tr, _local_python_cmd(cfg), cfg, mode, items, index_name,
    )
    on_line(f"$ {cmd}")
    proc = subprocess.Popen(
        cmd,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        errors="replace",
    )
    out_chunks: list[str] = []
    assert proc.stdout is not None
    for line in proc.stdout:
        out_chunks.append(line)
        on_line(line.rstrip("\n\r"))
    code = proc.wait()
    return code, "".join(out_chunks)
