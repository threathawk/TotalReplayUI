"""Index / sourcetype mapping store and resolution for replays."""

from __future__ import annotations

import datetime as dt
import json
import sqlite3
from pathlib import Path
from typing import Any, Optional

import yaml

from splunk_client import fetch_index_sourcetypes

DB_PATH = Path(__file__).resolve().parent / "data" / "totalreplay.db"


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_mapping_tables(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS splunk_index_sourcetypes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            index_name TEXT NOT NULL,
            sourcetype TEXT NOT NULL,
            synced_at TEXT NOT NULL,
            UNIQUE(index_name, sourcetype)
        );

        CREATE TABLE IF NOT EXISTS sourcetype_mappings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            detection_sourcetype TEXT NOT NULL UNIQUE,
            replay_sourcetype TEXT NOT NULL,
            target_index TEXT NOT NULL,
            auto_matched INTEGER NOT NULL DEFAULT 0,
            notes TEXT DEFAULT '',
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS splunk_sync_meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        """
    )


def _set_meta(key: str, value: str) -> None:
    with _conn() as c:
        c.execute(
            "INSERT INTO splunk_sync_meta (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )


def get_meta(key: str) -> Optional[str]:
    with _conn() as c:
        row = c.execute("SELECT value FROM splunk_sync_meta WHERE key=?", (key,)).fetchone()
    return row["value"] if row else None


def sync_splunk_inventory(cfg: dict, *, log_fn=None) -> dict[str, Any]:
    pairs = fetch_index_sourcetypes(cfg, log_fn=log_fn)
    now = dt.datetime.utcnow().isoformat()
    with _conn() as c:
        c.execute("DELETE FROM splunk_index_sourcetypes")
        c.executemany(
            "INSERT INTO splunk_index_sourcetypes (index_name, sourcetype, synced_at) VALUES (?, ?, ?)",
            [(p["index"], p["sourcetype"], now) for p in pairs],
        )
    _set_meta("last_sync_at", now)
    _set_meta("last_sync_count", str(len(pairs)))
    return {"ok": True, "count": len(pairs), "synced_at": now}


def list_splunk_pairs(
    *,
    q: str = "",
    index_filter: str = "",
    limit: int = 2000,
) -> list[dict[str, Any]]:
    sql = "SELECT index_name, sourcetype, synced_at FROM splunk_index_sourcetypes WHERE 1=1"
    params: list[Any] = []
    if index_filter:
        sql += " AND index_name = ?"
        params.append(index_filter)
    if q:
        sql += " AND (index_name LIKE ? OR sourcetype LIKE ?)"
        params.extend([f"%{q}%", f"%{q}%"])
    sql += " ORDER BY index_name, sourcetype LIMIT ?"
    params.append(limit)
    with _conn() as c:
        rows = c.execute(sql, params).fetchall()
    return [dict(r) for r in rows]


def list_indexes() -> list[str]:
    with _conn() as c:
        rows = c.execute(
            "SELECT DISTINCT index_name FROM splunk_index_sourcetypes ORDER BY index_name"
        ).fetchall()
    return [r["index_name"] for r in rows]


def list_mappings() -> list[dict[str, Any]]:
    with _conn() as c:
        rows = c.execute(
            "SELECT * FROM sourcetype_mappings ORDER BY detection_sourcetype"
        ).fetchall()
    return [dict(r) for r in rows]


def get_mapping_map() -> dict[str, dict[str, str]]:
    """detection_sourcetype -> {replay_sourcetype, target_index}."""
    out: dict[str, dict[str, str]] = {}
    for m in list_mappings():
        key = (m.get("detection_sourcetype") or "").strip()
        if key:
            out[key] = {
                "replay_sourcetype": (m.get("replay_sourcetype") or key).strip(),
                "target_index": (m.get("target_index") or "").strip(),
            }
    return out


def upsert_mapping(
    detection_sourcetype: str,
    replay_sourcetype: str,
    target_index: str,
    *,
    notes: str = "",
    auto_matched: bool = False,
) -> dict[str, Any]:
    det = detection_sourcetype.strip()
    if not det:
        raise ValueError("detection_sourcetype is required")
    rep = (replay_sourcetype or det).strip()
    idx = target_index.strip()
    if not idx:
        raise ValueError("target_index is required")
    now = dt.datetime.utcnow().isoformat()
    with _conn() as c:
        c.execute(
            """
            INSERT INTO sourcetype_mappings
                (detection_sourcetype, replay_sourcetype, target_index, auto_matched, notes, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(detection_sourcetype) DO UPDATE SET
                replay_sourcetype=excluded.replay_sourcetype,
                target_index=excluded.target_index,
                auto_matched=excluded.auto_matched,
                notes=excluded.notes,
                updated_at=excluded.updated_at
            """,
            (det, rep, idx, 1 if auto_matched else 0, notes or "", now),
        )
        row = c.execute(
            "SELECT * FROM sourcetype_mappings WHERE detection_sourcetype=?",
            (det,),
        ).fetchone()
    return dict(row) if row else {}


def delete_mapping(mapping_id: int) -> bool:
    with _conn() as c:
        cur = c.execute("DELETE FROM sourcetype_mappings WHERE id=?", (mapping_id,))
    return cur.rowcount > 0


def _normalize_st(s: str) -> str:
    return (s or "").strip().lower()


def auto_match_mappings() -> dict[str, Any]:
    """
    Match detection sourcetypes to Splunk inventory by exact or normalized name.
    """
    with _conn() as c:
        inv = c.execute(
            "SELECT index_name, sourcetype FROM splunk_index_sourcetypes"
        ).fetchall()
    if not inv:
        raise ValueError("Sync Splunk inventory first (Index Map tab).")

    by_st: dict[str, list[tuple[str, str]]] = {}
    for row in inv:
        st = row["sourcetype"]
        by_st.setdefault(_normalize_st(st), []).append((row["index_name"], st))

    created = updated = 0
    for det_st in collect_detection_sourcetypes_from_config():
        norm = _normalize_st(det_st)
        candidates = by_st.get(norm, [])
        if not candidates and ":" in det_st:
            candidates = by_st.get(_normalize_st(det_st.split(":")[-1]), [])
        if not candidates:
            continue
        index_name, replay_st = candidates[0]
        if len(candidates) > 1:
            for idx, st in candidates:
                if st == det_st:
                    index_name, replay_st = idx, st
                    break
        existing = get_mapping_map().get(det_st)
        if existing and existing.get("target_index") == index_name:
            continue
        upsert_mapping(det_st, replay_st, index_name, auto_matched=True, notes="auto-matched")
        if existing:
            updated += 1
        else:
            created += 1
    return {"ok": True, "created": created, "updated": updated}


def collect_detection_sourcetypes_from_config(cfg: Optional[dict] = None) -> list[str]:
    """Unique sourcetypes from local security_content YAML (best-effort)."""
    if cfg is None:
        from app import load_config

        cfg = load_config()
    sc = (cfg.get("security_content_path") or "").strip()
    if not sc:
        return []
    root = Path(sc).expanduser()
    if not root.exists():
        return []
    det_root = root if root.name == "detections" else root / "detections"
    if not det_root.exists():
        det_root = root
    found: set[str] = set()
    for yml in det_root.rglob("*.yml"):
        try:
            doc = yaml.safe_load(yml.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(doc, dict):
            continue
        for t in doc.get("tests") or []:
            if not isinstance(t, dict):
                continue
            for a in t.get("attack_data") or []:
                if isinstance(a, dict) and a.get("sourcetype"):
                    found.add(str(a["sourcetype"]).strip())
    return sorted(found, key=str.lower)


def lookup_pair(detection_sourcetype: str) -> Optional[dict[str, str]]:
    m = get_mapping_map().get((detection_sourcetype or "").strip())
    return m if m and m.get("target_index") else None


def resolve_index_and_sourcetype(
    detection_sourcetype: str,
    default_index: str,
    use_mapping: bool,
) -> tuple[str, str]:
    st = (detection_sourcetype or "").strip()
    if use_mapping:
        from route_planner import suggest_for_detection_sourcetype

        sug = suggest_for_detection_sourcetype(st, default_index=default_index)
        if sug["source"] != "default":
            return sug["suggested_index"], sug["suggested_replay_sourcetype"]
    return default_index, st


def resolve_index_for_item(
    cfg: dict,
    mode: str,
    item: dict,
    default_index: str,
    use_mapping: bool,
    *,
    catalog_detections: Optional[list[dict]] = None,
) -> str:
    """Pick Splunk index for a replay item (CLI uses one index per detection run)."""
    from route_planner import resolve_index_for_item_routed

    idx, _ = resolve_index_for_item_routed(
        cfg, mode, item, default_index, use_mapping, catalog_detections=catalog_detections,
    )
    return idx
