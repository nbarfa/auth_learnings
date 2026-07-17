from flask import Flask
from flask_jwt_extended import JWTManager

from config import Config
from database import db
from models import TokenBlocklist
from routes.auth import auth_bp

app = Flask(__name__)

app.config.from_object(Config)

jwt = JWTManager(app)
@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    jti = jwt_payload["jti"]
    token = TokenBlocklist.query.filter_by(
        jti=jti
    ).first()
    return token is not None

db.init_app(app)

app.register_blueprint(auth_bp)

with app.app_context():
    db.create_all()

if __name__=="__main__":
    app.run(debug=True)

