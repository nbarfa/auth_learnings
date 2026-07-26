from flask_jwt_extended import create_access_token
from mail import mail
from flask_mail import Message

def send_verfication_email(user):
    verification_token = create_access_token(
        identity=user.id,
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
