class Config:
    JWT_SECRET_KEY = "my_jwt_secret_key"
    SECRET_KEY = "my_secret_key"

    SQLALCHEMY_DATABASE_URI = "sqlite:///auth.db"
    SQLALCHEMY_TRACK_MODIFICATION = False

    MAIL_SERVER = "smtp.gmail.com"
    MAIL_PORT = 587
    MAIL_USE_TLS = True

    MAIL_DEFAULT_SENDER = "ppnb973@gmail.com"
    MAIL_USERNAME = "ppnb973@gmail.com"
    MAIL_PASSWORD = "hupiietrwlyyampx"
    