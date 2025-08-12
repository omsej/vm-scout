import httpx
from sqlalchemy.orm import Session
from ..models import CVE
from datetime import datetime

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

def update_kev(db: Session) -> int:
    r = httpx.get(KEV_URL, timeout=60.0)
    r.raise_for_status()
    data = r.json()
    items = data.get("vulnerabilities", [])
    count = 0
    kev_ids = set()
    for it in items:
        cve = it.get("cveID")
        if not cve: 
            continue
        kev_ids.add(cve)
        row = db.get(CVE, cve)
        if row:
            if not row.kev:
                row.kev = True
                count += 1
        else:
            # Create minimal CVE with KEV flag; details can be filled by NVD later
            db.add(CVE(id=cve, summary=None, cvss=None, severity=None, published=None, kev=True))
            count += 1
    db.commit()
    return count
