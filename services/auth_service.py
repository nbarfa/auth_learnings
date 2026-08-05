from database import db
from models import User
from werkzeug.security import generate_password_hash, check_password_hash
from services.email_service import send_verification_email
from flask_jwt_extended import create_access_token, create_refresh_token

def register_user(data):
    existing_user = User.query.filter_by(email=data["email"]).first()
    if existing_user:
        return None
    password_hash = generate_password_hash(data["password"])

    new_user = User(
        username=data["username"],
        email=data["email"],
        password_hash=password_hash
    )

    db.session.add(new_user)
    db.session.commit()

    send_verification_email(new_user)

    return new_user


def login_user(data):
    user = User.query.filter_by(email=data["email"]).first()
    if user is None:
        return {
            "success": False,
            "message": "User not found."
        }

    if not user.is_verified:
        return {
            "success": False,
            "message": "Email not verified."
        }

    if not check_password_hash(user.password_hash, data["password"]):
        return {
            "success": False,
            "message": "Invalid password."
        }

    access_token = create_access_token(identity=str(user.id))
    refresh_token = create_refresh_token(identity=str(user.id))
    return {
        "success": True,
        "message": "Login successful.",
        "access_token": access_token,
        "refresh_token": refresh_token
    }

def get_user_profile(user_id):
    user = User.query.get(user_id)
    if user is None:
        return None
    return user


def verify_user_email(token):
    user = User.email_verification_token(token)
    if not user:
        return {
            "success": False,
            "message": "Invalid or expired token."
        }
    if user.is_verified:
        return {
            "success": False,
            "message": "Email already verified."
        }
    
    user.is_verified = True
    db.session.commit()
    return {
        "success": True,
        "message": "Email verified successfully."
    }

def resend_verfication_email(email):
    user = User.query.filter_by(email=email).first()
    if not user:
        return {
            "success": False,
            "message": "User not found."
        }
    if user.is_verified:
        return {
            "success": False,
            "message": "Email not verified. Please verify your email first."
        }

    send_verification_email(user)

    return {
        "success": True,
        "message": "verification email sent successfully."
    }
