from functools import wraps
from flask import jsonify
from flask_jwt_extended import get_jwt_identity
from models import User

def admin_required():
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            user_id = int(get_jwt_identity())
            user = User.query.get(user_id)
            if not user:
                return jsonify(
                    {
                        "message": "user not found"
                    }
                ), 404
            if user.role != "admin":
                return jsonify(
                    {
                        "message": "Access denied. Admin only"
                    }
                ), 403
            return func(*args, **kwargs)
        return wrapper
    return decorator
