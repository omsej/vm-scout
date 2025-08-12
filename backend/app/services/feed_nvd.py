# backend/app/services/feed_nvd.py
import os
from datetime import datetime, timedelta
from typing import Tuple, Iterable
import httpx
from sqlalchemy.orm import Session
from sqlalchemy import delete
from ..models import CVE, CVECPE

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_WINDOW_DAYS = 90
FALLBACK_WINDOW_DAYS = 30

def _parse_cvss(v) -> Tuple[float | None, str | None]:
    try:
        m = v["cve"]["metrics"]
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in m and m[key]:
                d = m[key][0]["cvssData"]
                return d.get("baseScore"), d.get("baseSeverity")
    except Exception:
        pass
    return None, None

def _iter_cpes(conf) -> Iterable[Tuple[str, dict]]:
    try:
        for node in conf.get("nodes", []):
            for cm in node.get("cpeMatch", []):
                cpe = cm.get("criteria") or cm.get("cpe23Uri")
                if not cpe:
                    continue
                yield cpe, {
                    "vers_start_incl": cm.get("versionStartIncluding"),
                    "vers_start_excl": cm.get("versionStartExcluding"),
                    "vers_end_incl":   cm.get("versionEndIncluding"),
                    "vers_end_excl":   cm.get("versionEndExcluding"),
                }
    except Exception:
        return

def _split_cpe(cpe23: str):
    # cpe:2.3:a:vendor:product:version:...
    parts = cpe23.split(":")
    vendor = parts[3] if len(parts) > 4 else None
    product = parts[4] if len(parts) > 5 else None
    return vendor, product

def _fetch_window(db: Session, client: httpx.Client, start_dt: datetime, end_dt: datetime) -> int:
    pub_start = start_dt.strftime("%Y-%m-%dT00:00:00.000+00:00")
    pub_end   = end_dt.strftime("%Y-%m-%dT23:59:59.999+00:00")
    print(f"[NVD] window {pub_start} -> {pub_end}")
    params = {"pubStartDate": pub_start, "pubEndDate": pub_end}
    upserted = 0
    start_idx = 0

    while True:
        resp = client.get(NVD_API, params={**params, "startIndex": start_idx})
        resp.raise_for_status()
        data = resp.json()
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            break

        for v in vulns:
            cve_id = v["cve"]["id"]
            descs = v["cve"].get("descriptions", [])
            summary = next((d["value"] for d in descs if d.get("lang") == "en"), None)
            score, sev = _parse_cvss(v)
            pub = v["cve"].get("published")
            pub_dt = None
            if pub:
                try:
                    pub_dt = datetime.fromisoformat(pub.replace("Z", "+00:00"))
                except Exception:
                    pass

            row = db.get(CVE, cve_id)
            if not row:
                row = CVE(id=cve_id)
                db.add(row)
            row.summary = summary
            row.cvss = score
            row.severity = sev
            row.published = pub_dt

            # Replace CPEs for this CVE
            db.flush()
            db.execute(delete(CVECPE).where(CVECPE.cve_id == cve_id))
            conf = v["cve"].get("configurations", {}) or {}
            for cpe23, rng in _iter_cpes(conf):
                vendor, product = _split_cpe(cpe23)
                db.add(CVECPE(
                    cve_id=cve_id,
                    cpe23=cpe23,
                    vendor=vendor,
                    product=product,
                    vers_start_incl=rng["vers_start_incl"],
                    vers_start_excl=rng["vers_start_excl"],
                    vers_end_incl=rng["vers_end_incl"],
                    vers_end_excl=rng["vers_end_excl"],
                ))
            upserted += 1

        db.commit()
        total = data.get("totalResults", 0)
        start_idx += len(vulns)
        if start_idx >= total:
            break

    return upserted

def update_nvd(db: Session, days: int = 30) -> int:
    """
    Chunk the requested range into windows to avoid NVD 404 on large spans.
    """
    # Build client with optional API key (improves quotas)
    print(f"[NVD] update_nvd(days={days}) chunk={DEFAULT_WINDOW_DAYS}")
    headers = {"User-Agent": "vm-scout/0.2"}
    api_key = os.getenv("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key

    now = datetime.utcnow()
    start_dt = now - timedelta(days=days)
    end_dt = now

    window_days = min(DEFAULT_WINDOW_DAYS, max(1, days))
    upsert_total = 0

    with httpx.Client(timeout=60.0, headers=headers) as client:
        cur_start = start_dt
        while cur_start <= end_dt:
            cur_end = min(cur_start + timedelta(days=window_days - 1), end_dt)
            try:
                upsert_total += _fetch_window(db, client, cur_start, cur_end)
            except httpx.HTTPStatusError as e:
                # If window too large yields 404, retry with smaller fallback window
                if e.response is not None and e.response.status_code == 404 and window_days > FALLBACK_WINDOW_DAYS:
                    # Retry in smaller chunks
                    small_start = cur_start
                    while small_start <= cur_end:
                        small_end = min(small_start + timedelta(days=FALLBACK_WINDOW_DAYS - 1), cur_end)
                        upsert_total += _fetch_window(db, client, small_start, small_end)
                        small_start = small_end + timedelta(days=1)
                else:
                    raise
            cur_start = cur_end + timedelta(days=1)

    return upsert_total
