from sqlalchemy import select, delete, or_, and_
from sqlalchemy.orm import Session
import re
from packaging import version as pver
from ..models import Asset, Software, CVE, CVECPE, VulnFinding

ALIASES = {
    "edge": "microsoft edge",
    "chrome": "google chrome",
    "adobe reader": "acrobat reader",
    "7-zip": "7 zip",
}

# NEW: direct vendor/product mapping for common apps
KNOWN = [
    # (needle substring in software name, vendor, product)
    ("7 zip", "7-zip", "7-zip"),
    ("winrar", "rarlab", "winrar"),
    ("vlc media player", "videolan", "vlc_media_player"),
    ("notepad++", "don_ho", "notepad++"),
    ("git", "git-scm", "git"),  # sometimes vendor listed as 'git'
    ("python", "python_software_foundation", "python"),
    ("java", "oracle", "jdk"),
    ("java", "oracle", "jre"),
    ("node.js", "nodejs", "node.js"),
    ("putty", "simon_tatham", "putty"),
    ("winscp", "martin_prikryl", "winscp"),
    ("nvidia", "nvidia", "geforce_experience"),  # heuristic; drivers vary
    ("openvpn", "openvpn", "openvpn"),
    ("winscp", "martin_prikryl", "winscp"),
    ("vmware tools", "vmware", "tools"),
    ("docker desktop", "docker", "docker_desktop"),
    ("google chrome", "google", "chrome"),
    ("microsoft edge", "microsoft", "edge"),
    ("adobe acrobat", "adobe", "acrobat"),
    ("adobe reader", "adobe", "acrobat_reader"),
]

def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", (s or "").lower()).strip()

def _alias_name(name: str) -> str:
    n = _norm(name)
    for k, v in ALIASES.items():
        if k in n:
            n = n.replace(k, v)
    return n

def _tokens(s: str) -> set[str]:
    return {t for t in _norm(s).split() if len(t) >= 3 and t not in {"microsoft","inc","corporation","corp","the"}}

def _version_in_range(v, s_incl, s_excl, e_incl, e_excl) -> bool:
    if not v:
        return True
    try:
        V = pver.parse(v)
        if s_incl and V <  pver.parse(s_incl): return False
        if s_excl and V <= pver.parse(s_excl): return False
        if e_incl and V >  pver.parse(e_incl): return False
        if e_excl and V >= pver.parse(e_excl): return False
    except Exception:
        return True
    return True

def _candidate_cpes(db: Session, sw: Software):
    name = _alias_name(sw.name)
    toks = list(_tokens(name))
    if not toks:
        return []
    conds = [CVECPE.product.ilike(f"%{t}%") for t in toks]
    if sw.publisher:
        pub = _norm(sw.publisher)
        if pub:
            conds.append(CVECPE.vendor.ilike(f"%{pub}%"))
    q = select(CVECPE).where(or_(*conds)).limit(10000)
    return db.execute(q).scalars().all()

def _score_match(sw: Software, cpe: CVECPE) -> float:
    st = _tokens(_alias_name(sw.name))
    pt = _tokens(cpe.product or "")
    score = len(st.intersection(pt))
    if sw.publisher and cpe.vendor and cpe.vendor in _norm(sw.publisher):
        score += 1.0
    return score

def _direct_known_matches(db: Session, sw: Software):
    n = _norm(sw.name)
    for needle, vendor, product in KNOWN:
        if needle in n:
            # Fetch all CVE CPE entries for that vendor/product
            q = select(CVECPE).where(and_(CVECPE.vendor==vendor, CVECPE.product==product)).limit(5000)
            rows = db.execute(q).scalars().all()
            if rows:
                return rows
    return []

def match_asset(db: Session, asset_id: int) -> int:
    asset = db.get(Asset, asset_id)
    if not asset:
        return 0

    db.execute(delete(VulnFinding).where(VulnFinding.asset_id == asset_id))
    db.flush()

    created = 0
    sw_rows = db.execute(select(Software).where(Software.asset_id==asset_id)).scalars().all()
    for sw in sw_rows:
        # 1) Try direct known mapping first
        cpes = _direct_known_matches(db, sw)

        # 2) Fall back to fuzzy product token search
        if not cpes:
            cpes = _candidate_cpes(db, sw)

        if not cpes:
            continue

        # Keep best candidates
        cpes = sorted(cpes, key=lambda x: _score_match(sw, x), reverse=True)[:100]

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

def match_all(db: Session) -> dict:
    ids = db.execute(select(Asset.id)).scalars().all()
    total = 0
    for aid in ids:
        total += match_asset(db, aid)
    return {"assets": len(ids), "findings": total}
