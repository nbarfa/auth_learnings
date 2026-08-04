from database import db
from models import User
from werkzeug.security import generate_password_hash
from services.email_service import send_verification_email

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
        return None

    if not user.is_verified:
        return None

    
        



