"""FastAPI application factory."""

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from src.api.v1.routers import auth, scans, research, collaboration
from src.api.middleware import RateLimitMiddleware, add_process_time_header
from src.database import init_db
from src.config import settings


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler.

    Initializes database on startup.
    """
    # Startup
    await init_db()
    yield
    # Shutdown (cleanup if needed)


def create_app() -> FastAPI:
    """Create and configure FastAPI application.

    Returns:
        Configured FastAPI app instance
    """
    app = FastAPI(
        title="Anisakys Enterprise API",
        description="Advanced phishing detection and threat intelligence platform",
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan
    )

    # CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS if hasattr(settings, 'CORS_ORIGINS') else ["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Rate limiting middleware
    app.add_middleware(RateLimitMiddleware)

    # Process time middleware
    app.middleware("http")(add_process_time_header)

    # Include routers
    app.include_router(auth.router, prefix="/api/v1")
    app.include_router(scans.router, prefix="/api/v1")
    # Sprint 4: Advanced Features
    app.include_router(research.router, prefix="/api/v1")
    app.include_router(collaboration.router, prefix="/api/v1")

    # Health check endpoint
    @app.get("/health", tags=["Health"])
    async def health_check():
        """Health check endpoint.

        Returns:
            Health status
        """
        return {"status": "healthy", "service": "anisakys-enterprise"}

    # Root endpoint
    @app.get("/", tags=["Root"])
    async def root():
        """API root endpoint.

        Returns:
            Welcome message with API info
        """
        return {
            "message": "Anisakys Enterprise API",
            "version": "1.0.0",
            "docs": "/docs",
            "health": "/health"
        }

    # Global exception handler
    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        """Handle unexpected exceptions.

        Args:
            request: Request that caused exception
            exc: Exception raised

        Returns:
            JSON error response
        """
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "detail": "Internal server error",
                "type": type(exc).__name__
            }
        )

    return app


# Create app instance for uvicorn
app = create_app()
