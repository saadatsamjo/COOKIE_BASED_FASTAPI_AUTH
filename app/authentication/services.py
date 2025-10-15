# app/authentication/services.py

from app.authentication.models import TokenBlacklist, PasswordResetToken
from app.authentication.helpers import formulate_reset_link
from app.helpers.time import utcnow
from app.authentication.utils import (
    send_registration_email_with_verification_code,
    send_reset_password_link_with_token_in_email,
)
from sqlalchemy.ext.asyncio import AsyncSession
from app.authentication.schemas import (
    UserLogin,
)
from app.users.schemas import UserRegister, UserResponse
from fastapi import HTTPException, status
from datetime import datetime, timedelta
from app.authentication.security import (
    generate_password_reset_token,
    generate_verification_code,
    create_refresh_token,
    create_access_token,
    get_password_hash,
    get_token_expiry,
    verify_password,
    decode_token,
)
from typing import Optional, Tuple
from app.users.models import User
from sqlalchemy import select

# Importing create_default_settings
from app.users.services.create_default_settings import create_default_settings


# ============================================================
# ✅ Internal response class for register_user
# ============================================================
class RegistrationResponse:
    """Internal response class that includes tokens for cookie setting"""
    def __init__(self, user: User, access_token: str, refresh_token: str):
        self.user = user
        self.access_token = access_token
        self.refresh_token = refresh_token


# ============================================================
# REGISTER A NEW USER
# ============================================================
async def register_user(
    user_data: UserRegister, db: AsyncSession
) -> RegistrationResponse:
    """Register a new user."""
    # Check if email already exists
    stmt = select(User).where(User.email == user_data.email)
    result = await db.execute(stmt)
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="Email already registered"
        )

    # Create new user
    hashed_password = get_password_hash(user_data.password)
    new_user = User(
        email=user_data.email,
        hashed_password=hashed_password,
        first_name=user_data.first_name,
        last_name=user_data.last_name,
        is_active=True,
        is_verified=False,
    )
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)

    # Auto authenticate and return tokens
    access_token, refresh_token = await login_user(
        UserLogin(email=new_user.email, password=user_data.password), db
    )

    # Create default settings for the new user
    await create_default_settings(new_user, db)
    await db.commit()
    await db.refresh(new_user)

    # Generate verification code and save the code to user
    verification_code = generate_verification_code()
    new_user.verification_code = verification_code
    await db.commit()
    await db.refresh(new_user)

    # Send registration email for verification (commented out for now)
    # send_registration_email_with_verification_code(new_user.email, verification_code)

    # Return internal response with tokens
    return RegistrationResponse(
        user=new_user,
        access_token=access_token,
        refresh_token=refresh_token
    )


# ============================================================
# AUTHENTICATE USER
# ============================================================
async def authenticate_user(
    email: str, password: str, db: AsyncSession
) -> Optional[User]:
    """Authenticate a user by email and password."""
    stmt = select(User).where(User.email == email)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user or not verify_password(password, user.hashed_password):
        return None

    return user


# ============================================================
# LOGIN USER
# ============================================================
async def login_user(user_data: UserLogin, db: AsyncSession) -> Tuple[str, str]:
    """Login user and return access and refresh tokens."""
    user = await authenticate_user(user_data.email, user_data.password, db)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail="User account is inactive"
        )

    # Create tokens
    access_token = create_access_token(data={"sub": user.email})
    refresh_token = create_refresh_token(data={"sub": user.email})

    return access_token, refresh_token


# ============================================================
# REFRESH ACCESS TOKEN
# ============================================================
async def refresh_access_token(
    refresh_token: str, db: AsyncSession
) -> Tuple[str, str]:
    """Generate new access token using refresh token."""
    payload = decode_token(refresh_token)
    if not payload or payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Invalid refresh token"
        )

    email = payload.get("sub")
    if not email:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Invalid token payload"
        )

    # Check if refresh token is blacklisted
    stmt = select(TokenBlacklist).where(TokenBlacklist.token == refresh_token)
    result = await db.execute(stmt)
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has been revoked",
        )

    # Get user
    stmt = select(User).where(User.email == email)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )

    # Create new tokens
    new_access_token = create_access_token(data={"sub": user.email})
    new_refresh_token = create_refresh_token(data={"sub": user.email})

    # Blacklist old refresh token
    blacklist_entry = TokenBlacklist(
        token=refresh_token, 
        user_id=user.id, 
        expires_at=get_token_expiry("refresh")
    )
    db.add(blacklist_entry)
    await db.commit()

    return new_access_token, new_refresh_token


# ============================================================
# LOGOUT USER
# ============================================================
async def logout_user(token: str, user: User, db: AsyncSession) -> None:
    """Logout user by blacklisting the token."""
    blacklist_entry = TokenBlacklist(
        token=token, 
        user_id=user.id, 
        expires_at=get_token_expiry("access")
    )
    db.add(blacklist_entry)
    await db.commit()


# ============================================================
# CREATE PASSWORD RESET LINK WITH THE RESET TOKEN ON IT
# ============================================================
async def create_password_reset_link(
    email: str, db: AsyncSession
) -> tuple[str, str | None]:
    """
    Create a password reset token for a user and send them a reset link.
    Returns (reset_link, reset_token) for logging/testing purposes.
    """
    try:
        # Check if the user exists
        result = await db.execute(select(User).where(User.email == email))
        user = result.scalar_one_or_none()

        # Always respond the same way — don't reveal if user exists
        if not user:
            # Optional: fake delay to prevent timing attacks
            await db.commit()  # maintain parity with user case
            raise HTTPException(
                status_code=status.HTTP_200_OK,
                detail="If the email exists, a password reset link has been sent.",
            )

        # Create a fresh token
        reset_token = generate_password_reset_token()
        reset_entry = PasswordResetToken(
            token=reset_token,
            user_id=user.id,
            expires_at=utcnow() + timedelta(hours=1),
        )
        db.add(reset_entry)
        await db.commit()
        await db.refresh(reset_entry)

        # Generate and send the reset link
        reset_link = formulate_reset_link(reset_token)
        send_reset_password_link_with_token_in_email(email, reset_link)

        return reset_link, reset_token

    except HTTPException:
        # Allow graceful return of the "same message" exception above
        raise
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An unexpected error occurred: {str(e)}",
        )


# ============================================================
# RESET PASSWORD
# ============================================================
async def resetting_password(
    token: str, new_password: str, db: AsyncSession
) -> None:
    """Reset user password using reset token."""
    stmt = select(PasswordResetToken).where(
        PasswordResetToken.token == token,
        PasswordResetToken.used == False,
        PasswordResetToken.expires_at > utcnow(),
    )
    result = await db.execute(stmt)
    reset_token = result.scalar_one_or_none()

    if not reset_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset token",
        )

    stmt = select(User).where(User.id == reset_token.user_id)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, 
            detail="User not found"
        )

    user.hashed_password = get_password_hash(new_password)
    reset_token.used = True
    db.add_all([user, reset_token])
    await db.commit()
    await db.refresh(user)


# ============================================================
# CHANGE/UPDATE PASSWORD
# ============================================================
async def update_password(
    user: User, current_password: str, new_password: str, db: AsyncSession
) -> None:
    """Change user password (requires current password)."""
    if not verify_password(current_password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect",
        )

    user.hashed_password = get_password_hash(new_password)
    await db.commit()


# ============================================================
# VERIFY EMAIL
# ============================================================
async def verify_email_with_code(
    user: User, verification_code: str, db: AsyncSession
) -> None:
    """Verify user email."""
    if verification_code != user.verification_code:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid verification code",
        )

    user.is_verified = True
    await db.commit()