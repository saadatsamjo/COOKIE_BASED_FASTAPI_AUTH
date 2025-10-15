# app/users/services/create_default_settings.py


from app.users.models import User
from app.user_settings.models import Settings
from app.user_settings.schemas import SettingsRead
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select


# ============================================================
# ✅ CREATE DEFAULT SETTINGS
# ============================================================
async def create_default_settings(user: User, db: AsyncSession) -> SettingsRead:
    stmt = select(Settings).where(Settings.user_id == user.id)
    result = await db.execute(stmt)
    existing_settings = result.scalar_one_or_none()

    if existing_settings:
        existing_settings.user_id=user.id
        existing_settings.display_name="default display name"
        existing_settings.profile_picture="default profile picture"
        existing_settings.cover_picture="default cover picture"
        existing_settings.bio="default bio"
        existing_settings.theme="light"
        existing_settings.notifications=True
        existing_settings.language="en"
        return SettingsRead.model_validate(existing_settings)

    new_settings = Settings(
        user_id=user.id,
        display_name="default display name",
        profile_picture="default profile picture",
        cover_picture="default cover picture",
        bio="default bio",
        theme="light",
        notifications=True,
        language="en",
    )

    db.add(new_settings)
    await db.commit()
    await db.refresh(new_settings)

    return SettingsRead.model_validate(new_settings)
