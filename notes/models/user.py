from .. import db
from bcrypt import hashpw, gensalt
from flask_login import UserMixin
import pyotp
from flask import current_app
from Crypto.PublicKey import RSA
from time import time
import jwt
import hmac
from .exceptions import EncryptionError
from .utils import encrypt_data, decrypt_data


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hashed = db.Column(db.String(128), nullable=False)
    totp_secret = db.Column(db.String(128), nullable=True)
    private_key = db.Column(db.Text, nullable=True)
    public_key = db.Column(db.Text, nullable=True)

    def set_password(self, password):
        self.password_hashed = hashpw(password.encode('utf-8'), gensalt(rounds=12)).decode('utf-8')

    def check_password(self, password):
        hashed_password = hashpw(password.encode('utf-8'), self.password_hashed.encode('utf-8'))
        return hmac.compare_digest(hashed_password, self.password_hashed.encode('utf-8'))

    def generate_totp_secret(self):
        try:
            secret = pyotp.random_base32()
            self.totp_secret = encrypt_data(secret.encode('utf-8'), "AES_KEY_TOTP")
        except EncryptionError as e:
            raise EncryptionError("Failed to generate and encrypt TOTP secret.") from e

    def check_totp(self, code):
        totp = pyotp.TOTP(decrypt_data(self.totp_secret, "AES_KEY_TOTP"))
        return totp.verify(code)

    def generate_rsa_keys(self):
        rsa_keys = RSA.generate(2048)
        private_key = rsa_keys.export_key().decode('utf-8')
        public_key = rsa_keys.public_key().export_key().decode('utf-8')
        self.private_key = encrypt_data(private_key.encode('utf-8'), "AES_KEY_RSA")
        self.public_key = public_key

    def get_decrypted_private_key(self):
        if not self.private_key:
            raise Exception("No private key found for decryption.")
        return decrypt_data(self.private_key, "AES_KEY_RSA")

    def get_reset_password_token(self):
        return jwt.encode({'main.password_reset': self.id, 'exp': time() + 600}, current_app.config['SECRET_KEY'], algorithm='HS256')

    @staticmethod
    def verify_reset_password_token(token):
        try:
            id_token = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])['main.password_reset']
        except Exception as e:
            return None
        return db.session.get(User, id_token)
