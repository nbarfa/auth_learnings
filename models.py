from database import db

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(
        db.String(100),
        nullable=True
    )

    email = db.Column(
        db.String(120),
        unique=True,
        nullable=True
    )

    password_hash = db.Column(
        db.String(250),
        nullable=True
    )

    role = db.Column(
        db.String(20),
        default="user",
        nullable=False
    )


class TokenBlocklist(db.Model):
    id = db.Column(
        db.Integer,
        primary_key=True
    )
    jti = db.Column(
        db.String(40),
        nullable=False,
        unique=True
    )
