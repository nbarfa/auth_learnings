from flask import Flask
from flask_jwt_extended import JWTManager
from mail import mail
from config import Config
from database import db
from models import TokenBlocklist
from routes.auth import auth_bp

app = Flask(__name__)

app.config.from_object(Config)

# Initialize extensions
db.init_app(app)

mail.init_app(app)

jwt = JWTManager(app)

@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    jti = jwt_payload["jti"]
    token = TokenBlocklist.query.filter_by(jti=jti).first()
    return token is not None

app.register_blueprint(auth_bp)

with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True)