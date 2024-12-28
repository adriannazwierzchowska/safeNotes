from . import db
from bcrypt import hashpw, gensalt, checkpw
from flask_login import UserMixin
import pyotp
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
from hashlib import sha256

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


class Note(db.Model): # TODO maybe make the encryption parallel?
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(30), nullable=False)
    content = db.Column(db.Text, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    is_encrypted = db.Column(db.Boolean, default=False)
    encrypted_content = db.Column(db.Text, nullable=True)

    decrypted_content = None #temp
    author = db.relationship('User', backref='notes')


    def derive_key(self, user_key):
        return sha256(user_key).digest()

    def encrypt(self, data, user_key):
        key = self.derive_key(user_key)
        iv = get_random_bytes(16)
        aes = AES.new(key, AES.MODE_CBC, iv)
        data_padded = pad(data, AES.block_size)
        encrypted_data = aes.encrypt(data_padded)

        self.is_encrypted = True
        self.encrypted_content = base64.b64encode(iv + encrypted_data).decode('utf-8')


    def decrypt(self, user_key):
        key = self.derive_key(user_key)
        encrypted = base64.b64decode(self.encrypted_content)
        iv = encrypted[:16]
        encrypted_data = encrypted[16:]
        aes = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = aes.decrypt(encrypted_data)
        data_unpadded = unpad(decrypted_data, AES.block_size)

        return data_unpadded