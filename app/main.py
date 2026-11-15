"""
SmritiRakshak — AI Agent Memory Security Firewall
==================================================

Application entrypoint configuring the FastAPI instance, OpenAPI
metadata, route registration, and centralized exception handling.
"""

from __future__ import annotations

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse

from app.api.routes import memory
from app.core.config import APP_DESCRIPTION, APP_NAME, APP_VERSION


def create_app() -> FastAPI:
    """Factory creating and configuring the FastAPI application instance."""
    app = FastAPI(
        title=APP_NAME,
        version=APP_VERSION,
        description=APP_DESCRIPTION,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
    )

    # Register API routes under /api
    app.include_router(memory.router, prefix="/api")

    @app.get("/", include_in_schema=False)
    def root() -> dict[str, str]:
        """Root endpoint returning basic system information and links."""
        return {
            "name": APP_NAME,
            "version": APP_VERSION,
            "docs": "/docs",
            "health": "/api/health",
        }

    # Centralized exception safety handler to prevent unhandled tracebacks
    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "detail": "An internal security error occurred. Details suppressed for security."
            },
        )

    return app


# Application instance for ASGI runners (e.g. uvicorn app.main:app)
app = create_app()
