from dotenv import load_dotenv
import os
import logging


class Config:
    load_dotenv()

    SECRET_KEY = os.getenv("SECRET_KEY")
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    LOG_LEVEL = logging.DEBUG
    LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    LOG_FILE = os.getenv("LOG_FILE", "log/app.log")

    AES_KEY_TOTP = os.getenv('AES_KEY_TOTP')
    AES_KEY_RSA = os.getenv('AES_KEY_RSA')
    AES_KEY_NOTE = os.getenv('AES_KEY_NOTE')

    WTF_CSRF_SECRET_KEY = os.getenv("SECRET_KEY")
    WTF_CSRF_ENABLED = True

    SESSION_COOKIE_SECURE = True       
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'

    MAIL_SERVER = os.environ.get('MAIL_SERVER')
    MAIL_PORT = int(os.environ.get('MAIL_PORT') or 25)
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS') is not None
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')

    SECURITY_PASSWORD_SALT = os.getenv("SECURITY_PASSWORD_SALT")
