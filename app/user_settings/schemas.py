# app/user_settings/models/schemas.py

from pydantic import BaseModel, ConfigDict
from typing import Optional


# ✅ Base schema shared by other schemas
class SettingsBase(BaseModel):
    display_name: Optional[str] = None
    profile_picture: Optional[str] = None
    cover_picture: Optional[str] = None
    bio: Optional[str] = None
    theme: Optional[str] = None
    notifications: Optional[bool] = None
    language: Optional[str] = None
    user_id: Optional[int] = None
    model_config = ConfigDict(from_attributes=True)


# ✅ Create Schema
class SettingsCreate(SettingsBase):
    model_config = ConfigDict(from_attributes=True)


# ✅ Update Schema
class SettingsUpdate(SettingsBase):
    pass


# ✅ Read Schema (response)
class SettingsRead(SettingsBase):
    settings_id: int
    model_config = ConfigDict(from_attributes=True)