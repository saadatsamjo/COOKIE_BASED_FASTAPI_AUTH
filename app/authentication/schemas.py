# app/authentication/schemas.py
from pydantic import BaseModel, EmailStr, Field
from app.users.schemas import UserResponse
from typing import Optional

# Auth-related input schemas
class UserLogin(BaseModel):
    email: EmailStr
    password: str

class ForgotPassword(BaseModel):
    email: EmailStr

# If reset token is sent via json
# class ResetPassword(BaseModel):
#     token: str
#     new_password: str = Field(..., min_length=8, max_length=100)

# rest token is sent via query param
class ResetPassword(BaseModel): 
    new_password: str = Field(..., min_length=8, max_length=100)

class ChangePassword(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=8, max_length=100)

class VerifyEmail(BaseModel):
    verification_code: str

# Auth-related response schemas (updated for cookie-based auth)
class TokenResponseAfterRegistration(BaseModel):
    """Response after registration - tokens are set in cookies, only user info in body"""
    user: UserResponse
    message: str = "Registration successful"

class AuthMessageResponse(BaseModel):
    message: str

class TokenResponseAfterLogin(BaseModel):
    """Response after login - tokens are set in cookies"""
    message: str = "Login successful"

class TokenResponseAfterRefresh(BaseModel):
    """Response after token refresh - tokens are set in cookies"""
    message: str = "Tokens refreshed successfully"