# app/authentication/routes.py
from fastapi import APIRouter, Depends, HTTPException, status, Response, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.connection import get_db
from app.users.schemas import UserRegister
from app.authentication.services import (
    register_user,
    login_user,
    refresh_access_token,
    logout_user,
    create_password_reset_link,
    resetting_password,
    update_password,
    verify_email_with_code,
)
from app.authentication.dependencies import (
    get_current_user,
    get_refresh_token_user,
)
from app.authentication.helpers import set_auth_cookies, clear_auth_cookies
from app.users.models import User
from app.authentication.schemas import (
    TokenResponseAfterRegistration,
    TokenResponseAfterLogin,
    TokenResponseAfterRefresh,
    AuthMessageResponse,
    UserLogin,
    ForgotPassword,
    ResetPassword,
    ChangePassword,
    VerifyEmail,
)

router = APIRouter()


@router.post(
    "/register",
    response_model=TokenResponseAfterRegistration,
    status_code=status.HTTP_201_CREATED,
)
async def register(
    user_data: UserRegister, 
    response: Response,
    db: AsyncSession = Depends(get_db)
):
    """
    Register a new user and set authentication cookies.
    """
    user_response = await register_user(user_data, db)
    
    # Set cookies with the tokens
    set_auth_cookies(
        response, 
        user_response.access_token, 
        user_response.refresh_token
    )
    
    # Return response without tokens (they're in cookies now)
    return TokenResponseAfterRegistration(
        user=user_response.user,
        message="Registration successful"
    )


@router.post("/login", response_model=TokenResponseAfterLogin)
async def login(
    user_data: UserLogin, 
    response: Response,
    db: AsyncSession = Depends(get_db)
):
    """
    Login user and set authentication cookies.
    """
    access_token, refresh_token = await login_user(user_data, db)
    
    # Set cookies with the tokens
    set_auth_cookies(response, access_token, refresh_token)
    
    return TokenResponseAfterLogin(message="Login successful")


@router.post("/refresh", response_model=TokenResponseAfterRefresh)
async def refresh_token(
    response: Response,
    user_and_token: tuple = Depends(get_refresh_token_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Get new access and refresh tokens using a valid refresh token from cookies.
    The old refresh token will be blacklisted and a new pair of tokens will be issued.
    """
    user, refresh_token = user_and_token
    
    new_access_token, new_refresh_token = await refresh_access_token(refresh_token, db)
    
    # Set new cookies
    set_auth_cookies(response, new_access_token, new_refresh_token)
    
    return TokenResponseAfterRefresh(message="Tokens refreshed successfully")


@router.post("/logout", response_model=AuthMessageResponse)
async def logout(
    request: Request,
    response: Response,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Logout by blacklisting the current access token and clearing cookies.
    """
    from app.core.config import settings
    
    # Get token from cookie for blacklisting
    token = request.cookies.get(settings.ACCESS_TOKEN_COOKIE_NAME)
    
    if token:
        await logout_user(token, user, db)
    
    # Clear authentication cookies
    clear_auth_cookies(response)
    
    return {"message": "Successfully logged out"}


@router.post("/forgot-password", response_model=dict)
async def forgot_password(
    forgot_data: ForgotPassword, 
    db: AsyncSession = Depends(get_db)
):
    """
    Request a password reset token.
    - **email**: User's email address
    
    If the email exists, a password reset token will be generated.
    In production, this token should be sent via email.
    For development, the token is returned in the response.
    """
    try:
        reset_link, reset_token = await create_password_reset_link(
            forgot_data.email, db
        )
        return {
            "detail": "If the email exists, a password reset link has been sent.",
            "reset_link": reset_link,
            "reset_token": reset_token,
        }
    except HTTPException as e:
        raise e
    except Exception as e:
        # Log the actual error for debugging
        print(f"Error in forgot_password: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing your request.",
        )

#  # if the token is sent via json payload
# @router.post("/reset-password", response_model=AuthMessageResponse)
# async def reset_password(
#     reset_data: ResetPassword, 
#     db: AsyncSession = Depends(get_db)
# ):
#     """
#     Reset password using a valid reset token.
#     - **token**: Password reset token
#     - **new_password**: New password (min 8 characters)
    
#     The token will be marked as used and a new password will be set for the user.
#     """
#     try:
#         await resetting_password(reset_data.token, reset_data.new_password, db)
#         return {"message": "Password reset successfully"}
#     except HTTPException as e:
#         # Re-raise HTTPException (e.g., invalid token)
#         raise e
#     except Exception as e:
#         # Log unexpected errors and return a generic message
#         raise HTTPException(
#             status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
#             detail=f"An error occurred while processing your request, {e}",
#         )

# if the token is sent via query param
@router.post("/reset-password", response_model=AuthMessageResponse)
async def reset_password(
    token: str,
    reset_data: ResetPassword, 
    db: AsyncSession = Depends(get_db)
):
    """
    Reset password using a valid reset token.
    - **token**: Password reset token (query parameter)
    - **new_password**: New password (min 8 characters) in request body
    
    The token will be marked as used and a new password will be set for the user.
    
    Example: POST /reset-password?token=your_token_here
    Body: {"new_password": "newpassword123"}
    """
    try:
        await resetting_password(token, reset_data.new_password, db)
        return {"message": "Password reset successfully"}
    except HTTPException as e:
        # Re-raise HTTPException (e.g., invalid token)
        raise e
    except Exception as e:
        # Log unexpected errors and return a generic message
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred while processing your request, {e}",
        )


@router.post("/change-password", response_model=AuthMessageResponse)
async def change_password(
    change_data: ChangePassword,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Change user password (requires current password).
    - **current_password**: Current password
    - **new_password**: New password (min 8 characters)
    
    The current password will be verified, and if valid, the password will be changed.
    """
    try:
        await update_password(
            user, change_data.current_password, change_data.new_password, db
        )
        return {"message": "Password changed successfully"}
    except HTTPException as e:
        # Re-raise HTTPException (e.g., current password is incorrect)
        raise e
    except Exception as e:
        # Log unexpected errors and return a generic message
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing your request.",
        )


@router.post("/verify-email", response_model=AuthMessageResponse)
async def verify_email(
    verify_data: VerifyEmail,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Verify user email.
    - **verification_code**: Verification code
    
    The verification code will be verified, and if valid, the email will be verified.
    """
    try:
        await verify_email_with_code(user, verify_data.verification_code, db)
        return {"message": "Email verified successfully"}
    except HTTPException as e:
        # Re-raise HTTPException (e.g., invalid verification code)
        raise e
    except Exception as e:
        # Log unexpected errors and return a generic message
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing your request.",
        )