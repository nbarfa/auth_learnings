from flask_jwt_extended import create_access_token
from mail import mail
from flask_mail import Message

def send_verification_email(user):
    verification_token = create_access_token(
        identity=str(user.id),
        additional_claims={"purpose": "email_verification"}
    )

    msg = Message(
        subject="Verify your email",
        recipients=[user.email]
    )
    msg.body = f"""
    Hello {user.username},
    Please verify your email by clicking the link below:
    http://localhost:5000/verify/{verification_token}

    Thank you for registering
    """
    mail.send(msg)

def send_reset_password_email(user):
    reset_token = create_access_token(
        identity=str(user.id),
        additional_claims={"purpose": "password_reset"}
    )

    msg = Message(
        subject="Reset Your Password",
        recipients=[user.email]
    )
    msg.body = f"""
    Hello {user.username},
    You requested a password reset. Please click the link below to reset your password:
    http://localhost:5000/reset-password/{reset_token}
    
    If you did not request this, please ignore this email.
    Thank You for using our service.
    """
    mail.send(msg)
