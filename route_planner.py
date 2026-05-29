"""Compare replay sourcetypes with Splunk inventory and suggest target indexes."""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Optional

from index_mapping import get_mapping_map, get_meta, list_splunk_pairs


def _normalize_st(s: str) -> str:
    return (s or "").strip().lower()


def splunk_inventory_index() -> dict[str, list[dict[str, str]]]:
    """Normalized sourcetype -> [{index_name, sourcetype}, ...]."""
    by_norm: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in list_splunk_pairs(limit=50000):
        st = (row.get("sourcetype") or "").strip()
        idx = (row.get("index_name") or "").strip()
        if not st or not idx:
            continue
        by_norm[_normalize_st(st)].append({
            "index_name": idx,
            "sourcetype": st,
        })
    return dict(by_norm)


def _splunk_lookup(det_st: str, inv: dict[str, list[dict[str, str]]]) -> list[dict[str, str]]:
    norm = _normalize_st(det_st)
    hits = list(inv.get(norm, []))
    if hits:
        return hits
    if ":" in det_st:
        tail = _normalize_st(det_st.split(":")[-1])
        hits = list(inv.get(tail, []))
    return hits


def suggest_for_detection_sourcetype(
    detection_sourcetype: str,
    *,
    default_index: str = "test",
    mapping: Optional[dict[str, dict[str, str]]] = None,
    inv: Optional[dict[str, list[dict[str, str]]]] = None,
) -> dict[str, Any]:
    """
    Pick target index for a detection/replay sourcetype.
    Priority: manual mapping > exact Splunk inventory > normalized Splunk > default.
    """
    det_st = (detection_sourcetype or "").strip()
    mapping = mapping or get_mapping_map()
    inv = inv if inv is not None else splunk_inventory_index()

    manual = mapping.get(det_st)
    splunk_hits = _splunk_lookup(det_st, inv)

    splunk_indexes = sorted({h["index_name"] for h in splunk_hits})
    splunk_sourcetypes = sorted({h["sourcetype"] for h in splunk_hits})

    result: dict[str, Any] = {
        "detection_sourcetype": det_st,
        "splunk_matches": splunk_hits,
        "splunk_indexes": splunk_indexes,
        "in_splunk": bool(splunk_hits),
        "manual_mapping": manual,
        "suggested_index": default_index,
        "suggested_replay_sourcetype": det_st,
        "source": "default",
        "status": "unmapped",
        "confidence": "low",
        "needs_review": True,
    }

    if manual and manual.get("target_index"):
        result["suggested_index"] = manual["target_index"]
        result["suggested_replay_sourcetype"] = manual.get("replay_sourcetype") or det_st
        result["source"] = "manual"
        result["confidence"] = "high"
        if splunk_indexes:
            if manual["target_index"] in splunk_indexes and len(splunk_indexes) == 1:
                result["status"] = "mapped"
                result["needs_review"] = False
            elif manual["target_index"] in splunk_indexes:
                result["status"] = "mapped"
                result["needs_review"] = len(splunk_indexes) > 1
            else:
                result["status"] = "conflict"
                result["needs_review"] = True
        else:
            result["status"] = "manual_only"
            result["needs_review"] = False
        return result

    if len(splunk_hits) == 1:
        result["suggested_index"] = splunk_hits[0]["index_name"]
        result["suggested_replay_sourcetype"] = splunk_hits[0]["sourcetype"]
        result["source"] = "splunk_exact" if splunk_hits[0]["sourcetype"] == det_st else "splunk_normalized"
        result["status"] = "splunk_match"
        result["confidence"] = "high"
        result["needs_review"] = False
        return result

    if len(splunk_hits) > 1:
        idx_set = set(splunk_indexes)
        if len(idx_set) == 1:
            result["suggested_index"] = splunk_indexes[0]
            result["suggested_replay_sourcetype"] = splunk_sourcetypes[0]
            result["source"] = "splunk_exact"
            result["status"] = "splunk_ambiguous_st"
            result["confidence"] = "medium"
            result["needs_review"] = True
        else:
            result["suggested_index"] = splunk_indexes[0]
            result["suggested_replay_sourcetype"] = splunk_hits[0]["sourcetype"]
            result["source"] = "splunk_ambiguous"
            result["status"] = "splunk_ambiguous"
            result["confidence"] = "low"
            result["needs_review"] = True
        return result

    return result


def build_routing_matrix(
    catalog: list[dict],
    *,
    default_index: str = "test",
) -> dict[str, Any]:
    """Compare all replay detection sourcetypes against Splunk inventory and mappings."""
    mapping = get_mapping_map()
    inv = splunk_inventory_index()
    inv_synced = bool(get_meta("last_sync_at"))

    replay_sts: set[str] = set()
    for det in catalog:
        for t in det.get("tests") or []:
            if not isinstance(t, dict):
                continue
            for a in t.get("attack_data") or []:
                if isinstance(a, dict) and a.get("sourcetype"):
                    replay_sts.add(str(a["sourcetype"]).strip())

    rows: list[dict[str, Any]] = []
    stats = defaultdict(int)

    for st in sorted(replay_sts, key=str.lower):
        sug = suggest_for_detection_sourcetype(st, default_index=default_index, mapping=mapping, inv=inv)
        det_count = sum(
            1 for det in catalog
            if st in {
                str(a.get("sourcetype", "")).strip()
                for t in (det.get("tests") or [])
                if isinstance(t, dict)
                for a in (t.get("attack_data") or [])
                if isinstance(a, dict)
            }
        )
        rows.append({
            "replay_sourcetype": st,
            "detection_refs": det_count,
            "source": sug["source"],
            "in_splunk": sug["in_splunk"],
            "splunk_indexes": sug["splunk_indexes"],
            "splunk_matches": sug["splunk_matches"],
            "manual_index": (sug["manual_mapping"] or {}).get("target_index", ""),
            "suggested_index": sug["suggested_index"],
            "suggested_replay_sourcetype": sug["suggested_replay_sourcetype"],
            "source": sug["source"],
            "status": sug["status"],
            "confidence": sug["confidence"],
            "needs_review": sug["needs_review"],
        })
        stats[sug["status"]] += 1

    splunk_only: list[dict[str, str]] = []
    replay_norm = {_normalize_st(s) for s in replay_sts}
    for norm, hits in inv.items():
        if norm in replay_norm:
            continue
        for h in hits[:3]:
            splunk_only.append(h)

    return {
        "ok": True,
        "splunk_synced": inv_synced,
        "last_sync_at": get_meta("last_sync_at"),
        "rows": rows,
        "splunk_only_sample": splunk_only[:50],
        "stats": dict(stats),
        "total_replay_sourcetypes": len(rows),
        "total_splunk_sourcetypes": len(inv),
    }


def _sourcetypes_for_item(
    mode: str,
    item: dict,
    catalog_detections: Optional[list[dict]],
) -> list[str]:
    sts: list[str] = []
    if mode == "detections":
        det_id = item.get("detection_id")
        if catalog_detections and det_id:
            det = next((d for d in catalog_detections if d.get("id") == det_id), None)
            if det:
                for st in det.get("sourcetypes") or []:
                    if st and str(st).strip() not in sts:
                        sts.append(str(st).strip())
                for t in det.get("tests") or []:
                    for a in (t.get("attack_data") or []) if isinstance(t, dict) else []:
                        if isinstance(a, dict) and a.get("sourcetype"):
                            s = str(a["sourcetype"]).strip()
                            if s and s not in sts:
                                sts.append(s)
        if not sts and item.get("sourcetype"):
            sts.append(str(item["sourcetype"]).strip())
    elif mode in ("cached", "files"):
        if item.get("sourcetype"):
            sts.append(str(item["sourcetype"]).strip())
    return sts


def preview_replay_routing(
    mode: str,
    items: list[dict],
    *,
    default_index: str = "test",
    use_mapping: bool = True,
    catalog_detections: Optional[list[dict]] = None,
) -> dict[str, Any]:
    """Per-item index suggestions before running a replay."""
    mapping = get_mapping_map() if use_mapping else {}
    inv = splunk_inventory_index() if use_mapping else {}

    previews: list[dict[str, Any]] = []
    summary = defaultdict(int)

    for item in items:
        label = (
            item.get("detection_name") or item.get("name")
            or item.get("path") or item.get("detection_id") or "?"
        )
        sts = _sourcetypes_for_item(mode, item, catalog_detections)
        st_rows: list[dict[str, Any]] = []
        indexes_seen: list[str] = []

        if not use_mapping or not sts:
            resolved = default_index
            previews.append({
                "label": label,
                "item": item,
                "sourcetypes": [],
                "resolved_index": resolved,
                "fallback_index": default_index,
                "source": "fallback",
                "status": "fallback",
                "needs_review": False,
                "message": "No sourcetype or mapping disabled — using fallback index.",
            })
            summary["fallback"] += 1
            continue

        for st in sts:
            sug = suggest_for_detection_sourcetype(
                st, default_index=default_index, mapping=mapping, inv=inv,
            )
            st_rows.append(sug)
            indexes_seen.append(sug["suggested_index"])

        unique_idx = sorted(set(indexes_seen))
        needs_review = any(s["needs_review"] for s in st_rows) or len(unique_idx) > 1
        if len(unique_idx) == 1:
            resolved = unique_idx[0]
            status = "ready"
            if any(s["status"] == "conflict" for s in st_rows):
                status = "conflict"
            elif any(s["needs_review"] for s in st_rows):
                status = "review"
            elif all(s["status"] in ("mapped", "splunk_match", "manual_only") for s in st_rows):
                status = "ready"
            else:
                status = "review"
        else:
            resolved = st_rows[0]["suggested_index"] if st_rows else default_index
            status = "multi_index"

        previews.append({
            "label": label,
            "item": item,
            "sourcetypes": st_rows,
            "resolved_index": resolved,
            "fallback_index": default_index,
            "candidate_indexes": unique_idx,
            "source": st_rows[0]["source"] if len(st_rows) == 1 else "mixed",
            "status": status,
            "needs_review": needs_review,
            "message": _preview_message(status, unique_idx, default_index),
        })
        summary[status] += 1

    return {
        "ok": True,
        "use_mapping": use_mapping,
        "splunk_synced": bool(get_meta("last_sync_at")),
        "items": previews,
        "summary": {
            "total": len(previews),
            "ready": summary.get("ready", 0),
            "review": summary.get("review", 0),
            "conflict": summary.get("conflict", 0),
            "multi_index": summary.get("multi_index", 0),
            "fallback": summary.get("fallback", 0),
            "needs_review": sum(1 for p in previews if p.get("needs_review")),
        },
    }


def _preview_message(status: str, indexes: list[str], fallback: str) -> str:
    if status == "ready":
        return f"Will send to index: {indexes[0]}"
    if status == "multi_index":
        return f"Multiple indexes suggested: {', '.join(indexes)} — review before run"
    if status == "conflict":
        return "Manual mapping differs from Splunk inventory — review before run"
    if status == "review":
        return f"Suggested: {indexes[0] if indexes else fallback} — confirm before run"
    return f"Using fallback index: {fallback}"


def resolve_index_for_item_routed(
    cfg: dict,
    mode: str,
    item: dict,
    default_index: str,
    use_mapping: bool,
    *,
    catalog_detections: Optional[list[dict]] = None,
) -> tuple[str, dict[str, Any]]:
    """Resolved index plus routing detail for logging/UI."""
    preview = preview_replay_routing(
        mode, [item], default_index=default_index,
        use_mapping=use_mapping, catalog_detections=catalog_detections,
    )
    row = preview["items"][0] if preview.get("items") else {}
    return row.get("resolved_index") or default_index, row
