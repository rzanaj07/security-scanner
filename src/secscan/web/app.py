"""FastAPI application: JSON API plus the single-page dashboard."""

# No `from __future__ import annotations` here: FastAPI inspects these annotations at runtime.

import json
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.middleware.trustedhost import TrustedHostMiddleware

from secscan import __version__
from secscan import checks as checks_module
from secscan.checks.ports import PortSpecError
from secscan.models import ScanResult
from secscan.reporting import render_html
from secscan.store import ScanStore
from secscan.target import TargetError
from secscan.web.service import ScanService, compare

STATIC_DIR = Path(__file__).parent / "static"

# The dashboard is a security tool; it should pass its own header checks.
_SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
        "object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    ),
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}
# Exported reports use inline styles; they get a policy that allows those and nothing else.
_REPORT_CSP = "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'"


class ScanRequest(BaseModel):
    target: str = Field(min_length=1, max_length=255)
    checks: list[str] | None = None
    ports: str | None = Field(default=None, max_length=500)
    authorized: bool = False


def create_app(db_path: str | Path, allowed_hosts: list[str] | None = None) -> FastAPI:
    store = ScanStore(db_path)
    store.interrupt_unfinished()
    service = ScanService(store)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        yield
        service.shutdown()

    app = FastAPI(
        title="secscan",
        version=__version__,
        lifespan=lifespan,
        docs_url="/api/docs",
        redoc_url=None,
    )
    app.state.service = service

    if allowed_hosts:
        # Blocks DNS-rebinding: a malicious site cannot reach the API through its own hostname.
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts)

    @app.middleware("http")
    async def security_headers(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        response = await call_next(request)
        if not request.url.path.startswith("/api/docs") and request.url.path != "/openapi.json":
            for name, value in _SECURITY_HEADERS.items():
                response.headers.setdefault(name, value)
        return response

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    def get_scan(scan_id: int) -> dict[str, Any]:
        scan = store.get(scan_id)
        if scan is None:
            raise HTTPException(404, "Scan not found")
        return scan

    def finished_result(scan_id: int) -> ScanResult:
        scan = get_scan(scan_id)
        if scan["status"] != "done":
            raise HTTPException(409, "Scan has not finished")
        return ScanResult.from_dict(scan["result"])

    @app.get("/", include_in_schema=False)
    def index() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html")

    @app.get("/api/checks")
    def list_checks() -> list[dict[str, str]]:
        return [{"name": n, "title": c.title} for n, c in checks_module.CHECKS.items()]

    @app.post("/api/scans", status_code=202)
    def create_scan(req: ScanRequest) -> dict[str, int]:
        if not req.authorized:
            raise HTTPException(
                400, "Confirm that you own the target or have written permission to scan it."
            )
        names = req.checks or list(checks_module.CHECKS)
        unknown = [n for n in names if n not in checks_module.CHECKS]
        if unknown:
            raise HTTPException(422, f"Unknown check(s): {', '.join(unknown)}")
        try:
            scan_id, _ = service.submit(req.target, names, (req.ports or "").strip() or None)
        except (TargetError, PortSpecError) as e:
            raise HTTPException(422, str(e)) from e
        return {"id": scan_id}

    @app.get("/api/scans")
    def list_scans(limit: int = 200) -> list[dict[str, Any]]:
        return store.recent(limit=max(1, min(limit, 1000)))

    @app.get("/api/scans/{scan_id}")
    def scan_detail(scan_id: int) -> dict[str, Any]:
        scan = get_scan(scan_id)
        previous = (
            store.previous_done(scan["target"], scan_id) if scan["status"] == "done" else None
        )
        scan["comparison"] = compare(scan, previous)
        return scan

    @app.delete("/api/scans/{scan_id}", status_code=204)
    def delete_scan(scan_id: int) -> Response:
        scan = get_scan(scan_id)
        if scan["status"] in ("queued", "running"):
            raise HTTPException(409, "Scan is still running")
        store.delete(scan_id)
        return Response(status_code=204)

    @app.get("/api/scans/{scan_id}/report.html")
    def export_html(scan_id: int, download: bool = False) -> HTMLResponse:
        html = render_html(finished_result(scan_id))
        headers = {"Content-Security-Policy": _REPORT_CSP}
        if download:
            headers["Content-Disposition"] = f'attachment; filename="secscan-{scan_id}.html"'
        return HTMLResponse(html, headers=headers)

    @app.get("/api/scans/{scan_id}/report.json")
    def export_json(scan_id: int) -> Response:
        payload = {"tool": "secscan", "version": __version__, **finished_result(scan_id).to_dict()}
        return Response(
            json.dumps(payload, indent=2, default=str),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="secscan-{scan_id}.json"'},
        )

    return app
