# app/authentication/dependencies.py
from app.authentication.models import TokenBlacklist
from app.authentication.security import decode_token
from fastapi import Depends, HTTPException, status, Request
from sqlalchemy.ext.asyncio import AsyncSession
from app.database.connection import get_db
from app.users.models import User
from sqlalchemy import select
from typing import Optional
from app.core.config import settings

async def get_current_user(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> User:
    """
    Dependency to get the current authenticated user from JWT token in cookies.
    Use this in protected routes.
    """
    # Get token from cookie
    token = request.cookies.get(settings.ACCESS_TOKEN_COOKIE_NAME)
    
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if not token:
        raise credentials_exception

    # Decode token
    payload = decode_token(token)
    if payload is None:
        raise credentials_exception

    # Check token type
    if payload.get("type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Invalid token type"
        )

    # Get user email from token
    email: Optional[str] = payload.get("sub")
    if email is None:
        raise credentials_exception

    # Check if token is blacklisted
    stmt = select(TokenBlacklist).where(TokenBlacklist.token == token)
    result = await db.execute(stmt)
    blacklisted = result.scalar_one_or_none()
    if blacklisted:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Token has been revoked"
        )

    # Get user from database
    stmt = select(User).where(User.email == email)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if user is None:
        raise credentials_exception

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail="User account is inactive"
        )

    return user


async def get_current_active_user(
    current_user: User = Depends(get_current_user),
) -> User:
    """
    Dependency to ensure user is active.
    """
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail="Inactive user"
        )
    return current_user


async def get_current_verified_user(
    current_user: User = Depends(get_current_user),
) -> User:
    """
    Dependency to ensure user is verified (e.g., email verified).
    """
    if not current_user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail="Email not verified"
        )
    return current_user


async def get_refresh_token_user(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> tuple[User, str]:
    """
    Dependency specifically for refresh token validation.
    Returns both the user and the refresh token (for blacklisting).
    """
    # Get token from cookie
    token = request.cookies.get(settings.REFRESH_TOKEN_COOKIE_NAME)
    
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate refresh token",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if not token:
        raise credentials_exception

    # Decode token
    payload = decode_token(token)
    if payload is None:
        raise credentials_exception

    # Check token type
    if payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type, expected refresh token",
        )

    email: Optional[str] = payload.get("sub")
    if email is None:
        raise credentials_exception

    # Check if token is blacklisted
    stmt = select(TokenBlacklist).where(TokenBlacklist.token == token)
    result = await db.execute(stmt)
    blacklisted = result.scalar_one_or_none()
    if blacklisted:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has been revoked",
        )

    # Get user
    stmt = select(User).where(User.email == email)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if user is None:
        raise credentials_exception

    return user, token