"""Download DB-IP Lite (country + ASN, IPv4 + IPv6) as MMDB files (ADR-0032).

    python scripts/fetch_geoip.py .geoip          # local dev
    python scripts/fetch_geoip.py /opt/geoip      # image build (Dockerfile)

DB-IP publishes one file per month; early in a month the new one may not be
out yet, so the previous month is tried next. No account is needed.
Licence: CC BY 4.0 — "IP Geolocation by DB-IP" (https://db-ip.com).
"""

from __future__ import annotations

import gzip
import shutil
import sys
import urllib.request
from datetime import date
from pathlib import Path

BASE = "https://download.db-ip.com/free"
KINDS = ("country", "asn")


def _months(today: date) -> list[str]:
    previous = date(today.year - (today.month == 1), (today.month - 2) % 12 + 1, 1)
    return [f"{today:%Y-%m}", f"{previous:%Y-%m}"]


def fetch(target: Path, today: date | None = None) -> None:
    target.mkdir(parents=True, exist_ok=True)
    for kind in KINDS:
        out = target / f"dbip-{kind}-lite.mmdb"
        for month in _months(today or date.today()):
            url = f"{BASE}/dbip-{kind}-lite-{month}.mmdb.gz"
            try:
                # DB-IP answers 403 to urllib's default User-Agent.
                request = urllib.request.Request(url, headers={"User-Agent": "rba-idp-build/1.0"})
                with urllib.request.urlopen(request, timeout=60) as resp, gzip.open(resp) as unzipped:
                    with out.open("wb") as fh:
                        shutil.copyfileobj(unzipped, fh)
            except Exception as exc:  # noqa: BLE001 — try the previous month
                print(f"skip {url}: {exc}", file=sys.stderr)
                continue
            print(f"{out} ← {url} ({out.stat().st_size // 1_000_000} MB)")
            break
        else:
            raise SystemExit(f"could not download DB-IP {kind} for {_months(today or date.today())}")


if __name__ == "__main__":
    fetch(Path(sys.argv[1] if len(sys.argv) > 1 else ".geoip"))
