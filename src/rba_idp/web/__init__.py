"""Hosted login UI (IdP-5). Served by rba-idp; calls the JSON login API."""

from __future__ import annotations

import hashlib
from pathlib import Path

from fastapi.staticfiles import StaticFiles
from starlette.responses import Response

WEB_DIR = Path(__file__).resolve().parent


def static_version(directory: Path = WEB_DIR / "static") -> str:
    """Short hash of every static file: changes whenever any of them does.

    Pages reference ``/static/x.js?v=<this>``, so a deploy gives every asset a
    new URL and no browser can keep running an old script against a new page
    (a phone did exactly that with the two-tap passkey fix).
    """
    digest = hashlib.sha256()
    for path in sorted(p for p in directory.rglob("*") if p.is_file()):
        digest.update(path.relative_to(directory).as_posix().encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()[:12]


class RevalidatingStaticFiles(StaticFiles):
    """Static files the browser must revalidate before reuse.

    ``no-cache`` still caches; it only forbids using a copy without asking.
    An unchanged file answers 304 thanks to the ETag, so the cost is a round
    trip, not a download.
    """

    def file_response(self, *args, **kwargs) -> Response:
        response = super().file_response(*args, **kwargs)
        response.headers["Cache-Control"] = "no-cache"
        return response
