# app/user_settings/services/services.py

from app.users.services.create_default_settings import create_default_settings
from sqlalchemy.ext.asyncio import AsyncSession
from app.user_settings.models import Settings
from fastapi import HTTPException, status
from app.user_settings.schemas import (
    # SettingsCreate,
    SettingsUpdate,
    SettingsRead,
)
from app.users.models import User
from sqlalchemy import select


# # ============================================================
# # ✅ CREATE SETTINGS (not used because the create_default_settings function is used instead when creating a new user)
# # ============================================================
# async def create_settings(
#     settings_data: SettingsCreate, user: User, db: AsyncSession
# ) -> SettingsRead:
#     stmt = select(Settings).where(Settings.user_id == user.id)
#     result = await db.execute(stmt)
#     existing_settings = result.scalar_one_or_none()

#     if existing_settings:
#         return SettingsRead.model_validate(existing_settings)

#     new_settings = Settings(
#         user_id=user.id,
#         display_name=settings_data.display_name,
#         profile_picture=settings_data.profile_picture,
#         cover_picture=settings_data.cover_picture,
#         bio=settings_data.bio,
#         theme=settings_data.theme or "light",
#         notifications=settings_data.notifications or True,
#         language=settings_data.language or "en",
#     )

#     db.add(new_settings)
#     await db.commit()
#     await db.refresh(new_settings)

#     return SettingsRead.model_validate(new_settings)


# ============================================================
# ✅ GET PROFILE
# ============================================================
async def get_profile(user: User, db: AsyncSession):
    stmt = select(User).where(User.id == user.id)
    result = await db.execute(stmt)
    user_obj = result.scalar_one_or_none()

    if not user_obj:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    return user_obj


# ============================================================
# ✅ GET SETTINGS
# ============================================================
async def get_settings(user: User, db: AsyncSession) -> SettingsRead:
    stmt = select(Settings).where(Settings.user_id == user.id)
    result = await db.execute(stmt)
    settings = result.scalar_one_or_none()

    if not settings:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Settings not found"
        )

    return SettingsRead.model_validate(settings)


# ============================================================
# ✅ UPDATE SETTINGS
# ============================================================
async def update_settings(
    settings_data: SettingsUpdate, user: User, db: AsyncSession
) -> SettingsRead:
    stmt = select(Settings).where(Settings.user_id == user.id)
    result = await db.execute(stmt)
    settings = result.scalar_one_or_none()

    if not settings:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Settings not found"
        )

    for field, value in settings_data.model_dump(exclude_unset=True).items():
        setattr(settings, field, value)

    await db.commit()
    await db.refresh(settings)

    return SettingsRead.model_validate(settings)


# ============================================================
# ✅ RESET ALL SETTINGS TO DEFAULT
# ============================================================
async def reset_settings_to_default(user: User, db: AsyncSession) -> SettingsRead:
    stmt = select(Settings).where(Settings.user_id == user.id)
    result = await db.execute(stmt)
    settings = result.scalar_one_or_none()

    if not settings:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Settings not found"
        )

    # # hardcoding to reset all settings to default values
    # settings.display_name = None
    # settings.profile_picture = None
    # settings.cover_picture = None
    # settings.bio = None
    # settings.theme = "light"
    # settings.notifications = True
    # settings.language = "en"


    # using the create_default_settings function to reset all settings to default values
    await create_default_settings(user, db)

    await db.commit()
    await db.refresh(settings)

    return SettingsRead.model_validate(settings)
