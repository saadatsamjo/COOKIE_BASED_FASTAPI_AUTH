# app/user_settings/routes.py

from app.authentication.dependencies import get_current_user
from sqlalchemy.ext.asyncio import AsyncSession
from app.user_settings.services.services import (
    # create_settings,
    get_profile,
    get_settings,
    update_settings,
    reset_settings_to_default,
)
from app.user_settings.models import Settings
from app.user_settings.schemas import (
    SettingsRead,
    SettingsCreate,
    SettingsUpdate,
)
from app.users.schemas import UserResponse
from app.database.connection import get_db
from fastapi import APIRouter, Depends
from app.users.models import User

# router = APIRouter(prefix="/settings", tags=["User Settings"])
router = APIRouter()


# # ✅ CREATE SETTINGS
# @router.post("/", response_model=SettingsRead)
# async def create_settings_route(
#     settings_data: SettingsCreate,
#     user: User = Depends(
#         get_current_user
#     ),  # Ideally replaced with actual auth dependency
#     db: AsyncSession = Depends(get_db),
# ):
#     return await create_settings(settings_data, user, db)


# ✅ GET SETTINGS
@router.get("", response_model=SettingsRead)
async def get_settings_route(
    user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)
):
    return await get_settings(user, db)


# ✅ GET PROFILE
@router.get("/profile", response_model=UserResponse)
async def get_profile_route(
    user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)
):
    return await get_profile(user, db)


# ✅ UPDATE SETTINGS
@router.put("", response_model=SettingsRead)
async def update_settings_route(
    settings_data: SettingsUpdate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    return await update_settings(settings_data, user, db)


# ✅ RESET SETTINGS TO DEFAULT
@router.put("/reset", response_model=SettingsRead)
async def reset_settings_to_default_route(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    return await reset_settings_to_default(user, db)
