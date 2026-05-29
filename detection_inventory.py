"""Extract sourcetypes from security_content detections and build replay selections."""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Optional

from route_planner import suggest_for_detection_sourcetype
from index_mapping import get_mapping_map


def _sourcetypes_for_detection(det: dict) -> set[str]:
    found: set[str] = set()
    for t in det.get("tests") or []:
        if not isinstance(t, dict):
            continue
        for a in t.get("attack_data") or []:
            if isinstance(a, dict) and a.get("sourcetype"):
                found.add(str(a["sourcetype"]).strip())
    return found


def aggregate_sourcetype_inventory(
    catalog: list[dict],
    *,
    mapping: Optional[dict[str, dict[str, str]]] = None,
) -> dict[str, Any]:
    """
    Group detections by attack_data sourcetype.
    Returns {sourcetypes: [...], total_sourcetypes, total_detections, unmapped_count}.
    """
    mapping = mapping or get_mapping_map()
    by_st: dict[str, list[dict]] = defaultdict(list)
    seen_det: set[str] = set()

    for det in catalog:
        det_id = (det.get("id") or "").strip()
        if not det_id or det_id in seen_det:
            continue
        sts = _sourcetypes_for_detection(det)
        if not sts:
            continue
        seen_det.add(det_id)
        slim = {
            "detection_id": det_id,
            "detection_name": det.get("name") or det_id,
            "file": det.get("file") or "",
        }
        for st in sts:
            by_st[st].append(slim)

    rows: list[dict[str, Any]] = []
    unmapped = 0
    for st in sorted(by_st.keys(), key=str.lower):
        dets = sorted(by_st[st], key=lambda x: (x.get("detection_name") or "").lower())
        sug = suggest_for_detection_sourcetype(st, mapping=mapping)
        if sug["status"] in ("unmapped",) and not sug["in_splunk"]:
            unmapped += 1
        rows.append({
            "sourcetype": st,
            "detection_count": len(dets),
            "detections": dets,
            "mapped_index": sug["suggested_index"],
            "replay_sourcetype": sug["suggested_replay_sourcetype"],
            "is_mapped": sug["source"] != "default",
            "in_splunk": sug["in_splunk"],
            "splunk_indexes": sug["splunk_indexes"],
            "routing_status": sug["status"],
            "routing_source": sug["source"],
            "needs_review": sug["needs_review"],
        })

    return {
        "sourcetypes": rows,
        "total_sourcetypes": len(rows),
        "total_detections": len(seen_det),
        "unmapped_sourcetypes": unmapped,
    }


def replay_items_for_sourcetypes(
    catalog: list[dict],
    sourcetypes: list[str],
) -> list[dict]:
    """Detection replay items for any detection that uses one of the given sourcetypes."""
    want = {s.strip() for s in sourcetypes if (s or "").strip()}
    if not want:
        return []
    items: list[dict] = []
    seen: set[str] = set()
    for det in catalog:
        det_id = (det.get("id") or "").strip()
        if not det_id or det_id in seen:
            continue
        if not (_sourcetypes_for_detection(det) & want):
            continue
        seen.add(det_id)
        items.append({
            "detection_name": det.get("name") or det_id,
            "detection_id": det_id,
        })
    return items

