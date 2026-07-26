from flask import Blueprint, jsonify, request
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, create_refresh_token, get_jwt, decode_token
from models import User, TokenBlocklist
from database import db 
from werkzeug.security import generate_password_hash, check_password_hash
from decorator import admin_required
from flask_mail import Message
from mail import mail
from services.email_service import send_verfication_email

auth_bp = Blueprint(
    "auth",
    __name__
)

@auth_bp.route("/register", methods=["POST"])
def register():

    data = request.get_json()

    username = data.get("username")
    email = data.get("email")
    password = data.get("password")

    if not username or not email or not password:
        return jsonify(
            {
                "message": "All fields are requried"
            }
        ), 400

    existing_user = User.query.filter_by(
        email=email
    ).first()

    if existing_user:
        return jsonify(
            {
                "message": "email already exist"
            }
        )
    
    hashed_password = generate_password_hash(password)
    user = User(
        username=username,
        email=email,
        password_hash=hashed_password
    )
    db.session.add(user)
    db.session.commit()
    try:
        send_verfication_email(user)
        return jsonify(
            {
                "message": "User registered successfully. Please check your email to verify your account."
            }
        ), 201
    except Exception as e:
        print(e)
        return jsonify(
            {
                "message": "Failed to send verification email. Please resend verifcation email."
            }
        ), 400
    

    

@auth_bp.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    user_id = get_jwt_identity()

    user = User.query.get(user_id)
    if not user:
        return jsonify(
            {
                "message": "user not found"
            }
        ), 404


    access_token = create_access_token(
        identity=user_id
    )
    return jsonify(
        {
            "access_token": access_token
        }
    ), 200

@auth_bp.route("/verify/<verification_token>", methods=["GET"])
def verify_email(verification_token):
    try:
        decoded_token = decode_token(verification_token)
        user_id = decoded_token["sub"]
        user = User.query.get(int(user_id))
        if user is None:
                return jsonify(
                    {
                        "message": "If the account exists and is not yet verified, a verification email has been sent."
                    }
                ), 404
        if user.is_verified:
            return jsonify(
                {
                    "message": "Email already verified"
                }
            ), 200
        user.is_verified = True
        db.session.commit()

        return jsonify(
            {
                "message": "Email verified successfully. You can now log in."
            }
        ), 200
        
    except Exception as e:
        print(e)

        return jsonify(
            {
                "message": "Invalid or expired verification token"
            }
        ), 400

@auth_bp.route("/resend-verfication-email", methods=["POST"])
def resend_verfication_email():
    data = request.get_json()
    email = data.get("email")
    if not email:
        return jsonify(
            {
                "message": "Email is required"
            }
        ), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify(
            {
                "message": "If the account exists and is not yet verified, a verification email has been sent."
            }
        ), 404
    if user.is_verified:
        return jsonify(
            {
                "message": "EMail already verified. You can log in."
            }
        ), 400
    try:
        send_verfication_email(user)
        return jsonify(
            {
                "message": "Verification email resent successfully. Please check your email to verify your account."
            }
        ), 200
    except Exception as e:
        print(e)
        return jsonify(
            {
                "message": "Failed to resend verification email. Please try again."
            }
        ), 400

@auth_bp.route("/forget-password", methods=["POST"])
def forget_password():
    data = request.get_json()
    email = data.get("email")
    if not email:
        return jsonify(
            {
                "message": "Email is required"
            }
        ), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify(
            {
                "message": "If an account with this email exists, a password reset email has been sent."
            }
        ), 404

    


@auth_bp.route("/login", methods=["POST"])
def login():

    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify(
            {
                "message": "Invalid Email or password"
            }
        ), 400
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({
            "message": "Invalid email or password"
        }), 401
        
    if not check_password_hash(user.password_hash, password):
        return jsonify(
            {
                "message": "Invalid email or password"
            }
        ), 401
    if not user.is_verified:
        return jsonify(
            {
                "message": "Please verify your email before logging in."
            }
        ), 403
    
    access_token = create_access_token(
        identity=str(user.id)
    )
    refresh_token = create_refresh_token(
        identity=str(user.id)
    )

    return jsonify(
        {
            "message": "Login Successfull",
            "access_token": access_token,
            "refresh_token": refresh_token
        }
    ), 200

@auth_bp.route("/profile", methods=["GET"])
@jwt_required()
def profile():
    user_id = get_jwt_identity()

    if not user_id:
        return jsonify(
            {
                "message": "Plz login frist"
            }
        ), 401
    
    user = User.query.get(int(user_id))
    if not user:
        return jsonify(
            {
                "message": "User not found"
            }
        ), 404
    return jsonify(
        {
            "message": "Your Profile",
            "id": user.id,
            "username": user.username,
            "email": user.email
        }
    ), 200

@auth_bp.route("/admin", methods=["GET"])
@jwt_required()
@admin_required()
def admin_pannel():
    return jsonify(
        {
            "message": "Welcome Admin"
        }
    ), 200

@auth_bp.route("/delete-user/<int:id>", methods=["DELETE"])
@jwt_required()
@admin_required()
def delete_user(id):
    user = User.query.get(id)
    if not user:
        return jsonify({"message": "USer not found"}), 404
    
    db.session.delete(user)
    db.session.commit()
    return jsonify(
        {
            "message": "User deleted succsssfully"
        }
    ), 200

@auth_bp.route("/logout", methods=["POST"])
@jwt_required()
def logout():
    jwt = get_jwt()
    jti = jwt["jti"]
    token = TokenBlocklist(
        jti=jti
    )
    db.session.add(token)
    db.session.commit()
    return jsonify(
        {
            "message": "Logout Successfully"
        }
    ), 200
