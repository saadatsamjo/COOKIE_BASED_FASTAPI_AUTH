# app/main.py

from app.user_settings.routes import router as user_settings_router
from app.authentication.routes import router as auth_router
from fastapi.middleware.cors import CORSMiddleware
from app.database.connection import engine, Base
from contextlib import asynccontextmanager
from app.core.config import settings
from fastapi import FastAPI
import uvicorn


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Handles app startup and shutdown.
    """
    # ✅ Startup logic
    import app.model_registry  # ensures models are registered

    # background tasks are started here if any
    

    # FOR DEVELOPMENT - Uncomment to create tables on startup
    # async with engine.begin() as conn:
    #     await conn.run_sync(Base.metadata.create_all)
    # print("🚀 App startup complete")

    yield  # Application runs here

    # ✅ Shutdown logic
    await engine.dispose()
    # print("👋 App shutdown complete")


# Initialize FastAPI with the lifespan handler
app = FastAPI(lifespan=lifespan)


app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.FRONTEND_URL],  # Your frontend URL
    # allow_origins=[settings.FRONTEND_URL, "http://127.0.0.1:3000"]
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

# Routers
app.include_router(auth_router, prefix="/api/auth", tags=["Authentication"])
app.include_router(user_settings_router, prefix="/api/settings", tags=["User Settings"])





if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
