"""The HTTP API."""

import logging

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from ..bootstrap import bootstrap
from ..config import get_settings
from .routes import admin, alerts, auth, cases, entities, hunt, intel, logs, ops, overview, rules, traffic

log = logging.getLogger("mysoc")

SECURITY_HEADERS = {
    # API responses are data, never pages: nothing may load or frame them.
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}


def create_app(run_bootstrap: bool = True) -> FastAPI:
    settings = get_settings()
    if run_bootstrap:
        bootstrap()

    app = FastAPI(
        title="mySOC API",
        version="2.0.0",
        # Interactive docs only in development.
        docs_url=None if settings.is_production else "/api/docs",
        redoc_url=None,
        openapi_url=None if settings.is_production else "/api/openapi.json",
    )

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        for k, v in SECURITY_HEADERS.items():
            response.headers.setdefault(k, v)
        if settings.cookie_secure:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    # In Docker the console and API share one origin through the proxy, so
    # CORS only matters for the Vite dev server.
    if not settings.is_production:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=[settings.public_origin],
            allow_credentials=True,
            allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE"],
            allow_headers=["Content-Type", "X-CSRF-Token"],
        )

    for module in (auth, overview, alerts, cases, entities, traffic, hunt, intel, logs, rules, admin, ops):
        app.include_router(module.router)

    @app.get("/api/health", include_in_schema=False)
    def health():
        return {"ok": True}

    return app
