# app/users/schemas.py

from pydantic import BaseModel, EmailStr, Field, ConfigDict, field_validator
from typing import Optional, Literal, List
from datetime import datetime

# Allowed values as constants
ROLES = Literal["admin", "user"]
GENDERS = Literal["male", "female", "unset"]


class UserBase(BaseModel):
    email: EmailStr
    model_config = ConfigDict(from_attributes=True)


# ✅ Request schema for registration
class UserRegister(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=100)
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    is_active: bool = True
    is_verified: bool = False
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    role: ROLES = "user"
    gender: GENDERS = "unset"

    @field_validator("role")
    def validate_role_field(cls, v):
        if v not in ["admin", "user"]:
            raise ValueError(f"Invalid role value: {v}")
        return v

    @field_validator("gender")
    def validate_gender_field(cls, v):
        if v not in ["male", "female", "unset"]:
            raise ValueError(f"Invalid gender value: {v}")
        return v


# ✅ Response schema for user info
class UserResponse(BaseModel):
    id: int
    email: str
    is_active: bool
    is_verified: bool
    created_at: datetime
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    model_config = ConfigDict(from_attributes=True)


class UserInDB(UserRegister):
    id: int
    is_active: bool
    role: ROLES
    gender: GENDERS
    hashed_password: str  # For internal use, not API responses


class UserList(BaseModel):
    users: List[UserResponse]
    total: int


class UserPublic(BaseModel):
    id: int
    role: ROLES
    gender: GENDERS  # Minimal public info (no email for privacy)
