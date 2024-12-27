from . import db
from bcrypt import hashpw, gensalt, checkpw
from flask_login import UserMixin
import pyotp

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hashed = db.Column(db.String(128), nullable=False)
    totp_secret = db.Column(db.String(16), nullable=True)

    def set_password(self, password):
        self.password_hashed = hashpw(password.encode('utf-8'), gensalt(rounds=10)).decode('utf-8')

    def check_password(self, password):
        return checkpw(password.encode('utf-8'), self.password_hashed.encode('utf-8'))

    def generate_totp_secret(self):
        self.totp_secret = pyotp.random_base32()

    def check_totp(self, code):
        totp = pyotp.TOTP(self.totp_secret)
        return totp.verify(code)