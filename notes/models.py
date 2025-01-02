from . import db
from bcrypt import hashpw, gensalt, checkpw
from flask_login import UserMixin
import pyotp
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
from hashlib import sha256
from flask import current_app
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15

# TODO better error handling
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hashed = db.Column(db.String(128), nullable=False)
    totp_secret = db.Column(db.String(128), nullable=True)
    private_key = db.Column(db.Text, nullable=True)
    public_key = db.Column(db.Text, nullable=True)

    def set_password(self, password):
        self.password_hashed = hashpw(password.encode('utf-8'), gensalt(rounds=10)).decode('utf-8')

    def check_password(self, password):
        return checkpw(password.encode('utf-8'), self.password_hashed.encode('utf-8'))

    def generate_totp_secret(self):
        secret = pyotp.random_base32()
        self.encrypt_totp(secret.encode('utf-8'))

    def check_totp(self, code):
        totp = pyotp.TOTP(self.decrypt_totp())
        return totp.verify(code)

    def encrypt_totp(self, totp_secret):
        key = base64.b64decode(current_app.config.get("AES_KEY"))
        iv = get_random_bytes(16)
        aes = AES.new(key, AES.MODE_CBC, iv)
        data_padded = pad(totp_secret, AES.block_size)
        encrypted_data = aes.encrypt(data_padded)

        self.totp_secret = base64.b64encode(iv + encrypted_data).decode('utf-8')

    def decrypt_totp(self):
        aes_key = base64.b64decode(current_app.config.get("AES_KEY"))
        encrypted = base64.b64decode(self.totp_secret)
        iv = encrypted[:16]
        encrypted_data = encrypted[16:]
        aes = AES.new(aes_key, AES.MODE_CBC, iv)
        decrypted_data = aes.decrypt(encrypted_data)
        data_unpadded = unpad(decrypted_data, AES.block_size)

        return data_unpadded.decode('utf-8')

    def encrypt_key(self, key):
        aes_key = base64.b64decode(current_app.config['AES_KEY'])
        iv = get_random_bytes(16)
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        encrypted_key = cipher.encrypt(pad(key.encode('utf-8'), AES.block_size))

        return base64.b64encode(iv + encrypted_key).decode('utf-8')

    def decrypt_key(self):
        aes_key = base64.b64decode(current_app.config['AES_KEY'])
        encrypted_data = base64.b64decode(self.private_key)
        iv = encrypted_data[:16]
        encrypted_key = encrypted_data[16:]
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        decrypted_key = unpad(cipher.decrypt(encrypted_key), AES.block_size)
        return decrypted_key.decode('utf-8')

    def generate_rsa_keys(self):
        rsa_keys = RSA.generate(2048)
        private_key = rsa_keys.export_key().decode('utf-8')
        public_key = rsa_keys.public_key().export_key().decode('utf-8')
        self.private_key = self.encrypt_key(private_key)
        self.public_key = public_key

class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(30), nullable=False)
    content = db.Column(db.Text, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    is_encrypted = db.Column(db.Boolean, default=False)
    encrypted_content = db.Column(db.Text, nullable=True)
    is_public = db.Column(db.Boolean, default=False)
    signature = db.Column(db.Text, nullable=True)

    decrypted_content = None #temp
    author = db.relationship('User', backref='notes')

    def encrypt(self, data, user_key):
        key = sha256(user_key).digest()
        iv = get_random_bytes(16)
        aes = AES.new(key, AES.MODE_CBC, iv)
        data_padded = pad(data, AES.block_size)
        encrypted_data = aes.encrypt(data_padded)

        self.is_encrypted = True
        self.encrypted_content = base64.b64encode(iv + encrypted_data).decode('utf-8')


    def decrypt(self, user_key):
        key = sha256(user_key).digest()
        encrypted = base64.b64decode(self.encrypted_content)
        iv = encrypted[:16]
        encrypted_data = encrypted[16:]
        aes = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = aes.decrypt(encrypted_data)
        data_unpadded = unpad(decrypted_data, AES.block_size)

        return data_unpadded

    def sign_note(self):
        if not self.author.private_key:
            return
        decrypted_key = self.author.decrypt_key()
        private_key = RSA.import_key(decrypted_key)
        h = SHA256.new(self.content.encode('utf-8'))
        signature_bytes = pkcs1_15.new(private_key).sign(h)
        self.signature = base64.b64encode(signature_bytes).decode('utf-8')

    def verify_signature(self):
        if not self.signature or not self.author.public_key:
            return False

        public_key = RSA.import_key(self.author.public_key.encode('utf-8'))
        h = SHA256.new(self.content.encode('utf-8'))
        sig = base64.b64decode(self.signature)

        try:
            pkcs1_15.new(public_key).verify(h, sig)
            return True
        except (ValueError, TypeError):
            return False

    def get_username(self):
        if not self.signature or not self.author.public_key:
            return "Unknown"

        public_key = RSA.import_key(self.author.public_key.encode('utf-8'))
        h = SHA256.new(self.content.encode('utf-8'))
        sig = base64.b64decode(self.signature)

        try:
            pkcs1_15.new(public_key).verify(h, sig)
            return self.author.username
        except (ValueError, TypeError):
            return "Invalid Signature"


class SharedNotes(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    note_id = db.Column(db.Integer, db.ForeignKey('note.id'), nullable=False)
    signature = db.Column(db.Text, nullable=True)

    user = db.relationship('User', backref='note_access')
    note = db.relationship('Note', backref='note_access')

    def sign_shared_note(self):
        if not self.user.private_key:
            return
        decrypted_key = self.user.decrypt_key()
        private_key = RSA.import_key(decrypted_key)
        h = SHA256.new(self.note.content.encode('utf-8'))
        signature_bytes = pkcs1_15.new(private_key).sign(h)
        self.signature = base64.b64encode(signature_bytes).decode('utf-8')

    def verify_shared_signature(self):
        if not self.signature or not self.user.public_key:
            return False

        public_key = RSA.import_key(self.user.public_key.encode('utf-8'))
        h = SHA256.new(self.note.content.encode('utf-8'))
        sig = base64.b64decode(self.signature)

        try:
            pkcs1_15.new(public_key).verify(h, sig)
            return True
        except (ValueError, TypeError):
            return False

    def get_shared_username(self):
        if not self.signature or not self.user.public_key:
            return "Unknown"

        public_key = RSA.import_key(self.user.public_key.encode('utf-8'))
        h = SHA256.new(self.note.content.encode('utf-8'))
        sig = base64.b64decode(self.signature)

        try:
            pkcs1_15.new(public_key).verify(h, sig)
            return self.user.username
        except (ValueError, TypeError):
            return "Invalid Signature"
