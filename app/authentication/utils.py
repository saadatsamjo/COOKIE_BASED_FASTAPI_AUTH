# app/authentication/utils.py

from app.core.config import settings
from fastapi import HTTPException
import resend
import os


resend.api_key = settings.RESEND_API_KEY

# hard coded name for now
first_name = "First Name"


def send_registration_email_with_verification_code(email, verification_code):
    r = resend.Emails.send(
        {
            "from": "support@medivarse.com",
            "to": email,
            "subject": "Verify your email!",
            "html": f"<p>Hello {first_name}.\
        Welcome to Simbatec.\
        To verify your account, use the code below when prompted to enter your verification code.\
        This code is meant to not be shared to anyone"
            f"<strong> {verification_code} </strong>"
            f"<strong> Simbatec </strong>",
        }
    )


def send_reset_password_link_with_token_in_email(email, reset_link):
    r = resend.Emails.send(
        {
            "from": "support@medivarse.com",
            "to": email,
            "subject": "Reset your password!",
            "html": f"<p> Hello [{first_name}  We are sorry to hear that you have been having trouble logging in on  our Simbatec.\
          To resett your password, click the link below</p>"
            f"<p>{reset_link}</p>"
            "You can only use this link once, not to be shared to anyone"
            f"<strong> Simbatec </strong>",
        }
    )


# def send_verification_email(email, verification_code):
#     r = resend.Emails.send(
#         {
#             "from": "support@medivarse.com",
#             "to": email,
#             "subject": "Verify your email!",
#             "html": f"<p>Hello {first_name}.\
#         Welcome to Simbatec.\
#         To verify your account, use the code below when prompted to enter your verification code.\
#         This code is meant to not be shared to anyone"
#             f"<strong> {verification_code} </strong>"
#             f"<strong> Simbatec </strong>",
#         }
#     )


# def send_invite_email(email, initial_password):
#     r = resend.Emails.send(
#         {
#             "from": "support@medivarse.com",
#             "to": email,
#             "subject": "You are invited to join the team",
#             "html": f"""
#             <p>Hello {first_name},</p>
#             <p>{'inviter_name'} has invited you to join the customer service team at {'company_name'}.</p>
#             <p>Your login details are below:</p>
#             <p>Email: {email}</p>
#             <p>Password: <strong>{initial_password}</strong></p>
#             <p>Welcome to <strong>Simbatec</strong></p>
#         """,
#         }
#     )
