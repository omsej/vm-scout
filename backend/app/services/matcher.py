from sqlalchemy.orm import Session
from sqlalchemy import select, delete, or_
from ..models import Asset, Software, CVE, CVECPE, VulnFinding
import re
from packaging import version as pver


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", (s or "").lower()).strip()

def _tokens(s: str) -> set[str]:
    return set(t for t in _norm(s).split() if t and t not in {"microsoft","inc","corporation","corp","the"})

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
        # If version parse fails, conservatively allow match
        return True
    return True

def _candidate_cpes(db: Session, sw: Software):
    tokens = [t for t in _tokens(sw.name) if len(t) >= 3]
    if not tokens:
        return []
    conds = []
    for t in tokens:
        conds.append(CVECPE.product.ilike(f"%{t}%"))
    if sw.publisher:
        pub = _norm(sw.publisher)
        if pub:
            conds.append(CVECPE.vendor.ilike(f"%{pub}%"))
    q = select(CVECPE).where(or_(*conds)).limit(5000)
    return db.execute(q).scalars().all()

def _score_match(sw: Software, cpe: CVECPE) -> float:
    # simple heuristic: token overlap + publisher/vendor hint
    score = 0.0
    if cpe.product:
        st = _tokens(sw.name); pt = _tokens(cpe.product)
        inter = len(st.intersection(pt))
        score += inter
    if sw.publisher and cpe.vendor and cpe.vendor in _norm(sw.publisher):
        score += 1.0
    return score

def match_asset(db: Session, asset_id: int) -> int:
    asset = db.get(Asset, asset_id)
    if not asset:
        return 0

    # wipe previous findings for the asset (MVP)
    db.execute(delete(VulnFinding).where(VulnFinding.asset_id == asset_id))
    db.flush()

    created = 0
    sw_rows = db.execute(select(Software).where(Software.asset_id==asset_id)).scalars().all()
    for sw in sw_rows:
        cpes = _candidate_cpes(db, sw)
        if not cpes:
            continue

        # pick best few candidates by score
        cpes = sorted(cpes, key=lambda x: _score_match(sw, x), reverse=True)[:50]

        for cpe in cpes:
            # version gates
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

def match_all(db: Session):
    assets = db.execute(select(Asset.id)).scalars().all()
    total_findings = 0
    for aid in assets:
        total_findings += match_asset(db, aid)
    return {"assets": len(assets), "findings": total_findings}
