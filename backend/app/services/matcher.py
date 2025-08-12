from __future__ import annotations

import re
from sqlalchemy import select, delete, or_
from sqlalchemy.orm import Session
from packaging import version as pver

from ..models import Asset, Software, CVE, CVECPE, VulnFinding

# Basic aliases for common products
ALIASES = {
    "edge": "microsoft edge",
    "chrome": "google chrome",
    "adobe reader": "acrobat reader",
    "7-zip": "7 zip",
    "visual c++": "visual c",
    "winrar": "winrar",
}

STOPWORDS = {"microsoft", "inc", "corporation", "corp", "the", "llc", "co", "company"}

def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", (s or "").lower()).strip()

def _alias_name(name: str) -> str:
    n = _norm(name)
    for k, v in ALIASES.items():
        if k in n:
            n = n.replace(k, v)
    return n

def _tokens(s: str) -> set[str]:
    return set(t for t in _norm(s).split() if len(t) >= 3 and t not in STOPWORDS)

def _version_in_range(v: str | None, start_incl, start_excl, end_incl, end_excl) -> bool:
    if not v:
        return True
    try:
        V = pver.parse(v)
        if start_incl and V < pver.parse(start_incl): return False
        if start_excl and V <= pver.parse(start_excl): return False
        if end_incl   and V >  pver.parse(end_incl):   return False
        if end_excl   and V >= pver.parse(end_excl):   return False
    except Exception:
        # If we can't parse, don't block on version
        return True
    return True

def _candidate_cpes(db: Session, sw: Software):
    name_tokens = list(_tokens(_alias_name(sw.name)))
    conds = [CVECPE.product.ilike(f"%{t}%") for t in name_tokens]

    # Add vendor hints from publisher tokens
    if sw.publisher:
        pub_tokens = [t for t in _tokens(sw.publisher)]
        conds += [CVECPE.vendor.ilike(f"%{t}%") for t in pub_tokens]

    if not conds:
        return []

    q = select(CVECPE).where(or_(*conds)).limit(10000)
    return db.execute(q).scalars().all()

def _score_match(sw: Software, cpe: CVECPE) -> float:
    st = _tokens(_alias_name(sw.name))
    pt = _tokens(cpe.product or "")
    score = len(st.intersection(pt))
    if sw.publisher and cpe.vendor and cpe.vendor in _norm(sw.publisher):
        score += 1.0
    return score

def match_asset(db: Session, asset_id: int) -> int:
    asset = db.get(Asset, asset_id)
    if not asset:
        return 0

    # Remove previous findings for a fresh snapshot
    db.execute(delete(VulnFinding).where(VulnFinding.asset_id == asset_id))
    db.flush()

    created = 0
    sw_rows = db.execute(select(Software).where(Software.asset_id == asset_id)).scalars().all()
    for sw in sw_rows:
        cpes = _candidate_cpes(db, sw)
        if not cpes:
            continue

        # Top N by simple score
        cpes = sorted(cpes, key=lambda x: _score_match(sw, x), reverse=True)[:75]

        for cpe in cpes:
            if not _version_in_range(sw.version, cpe.vers_start_incl, cpe.vers_start_excl, cpe.vers_end_incl, cpe.vers_end_excl):
                continue
            cve = db.get(CVE, cpe.cve_id)
            if not cve:
                continue
            db.add(VulnFinding(
                asset_id=asset_id,
                software_id=sw.id,
                cve_id=cve.id,
                product=cpe.product,
                detected_version=sw.version,
                severity=cve.severity,
                cvss=cve.cvss,
                kev=cve.kev,
            ))
            created += 1

    db.commit()
    return created

def match_all(db: Session) -> dict[str, int]:
    asset_ids = db.execute(select(Asset.id)).scalars().all()
    total = 0
    for aid in asset_ids:
        total += match_asset(db, aid)
    return {"assets": len(asset_ids), "findings": total}
