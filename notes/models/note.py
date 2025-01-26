from .. import db
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from hashlib import sha256
from .exceptions import EncryptionError, DecryptionError, SignatureError
from extensions import serializer


class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(30), nullable=False)
    content = db.Column(db.Text, nullable=True)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    is_encrypted = db.Column(db.Boolean, default=False)
    encrypted_content = db.Column(db.Text, nullable=True)
    is_public = db.Column(db.Boolean, default=False)
    signature = db.Column(db.Text, nullable=True)

    decrypted_content = None
    author = db.relationship('User', backref='notes')

    def encrypt(self, data, code):
        if not data or not code:
            raise EncryptionError("No data to encrypt.")
        try:
            key = sha256(code.encode('utf-8')).digest()
            iv = get_random_bytes(12)
            aes = AES.new(key, AES.MODE_GCM, iv)
            encrypted_data, tag = aes.encrypt_and_digest(data.encode('utf-8'))
            self.is_encrypted = True
            self.content = None
            self.encrypted_content = base64.b64encode(iv + tag + encrypted_data).decode('utf-8')
        except Exception as e:
            raise EncryptionError("Encryption failed.") from e

    def decrypt(self, code):
        if not self.encrypted_content or not code:
            raise DecryptionError("No encrypted content.")
        try:
            key = sha256(code.encode('utf-8')).digest()
            encrypted = base64.b64decode(self.encrypted_content)
            iv = encrypted[:12]
            tag = encrypted[12:28]
            encrypted_data = encrypted[28:]
            aes = AES.new(key, AES.MODE_GCM, iv)
            decrypted_data = aes.decrypt_and_verify(encrypted_data, tag)
            return decrypted_data.decode('utf-8')
        except (ValueError, TypeError) as e:
            raise DecryptionError("Decryption for note failed.") from e

    def sign_note(self):
        if not self.author.private_key:
            raise SignatureError("No private key.")
        try:
            decrypted_key = self.author.get_decrypted_private_key()
            private_key = RSA.import_key(decrypted_key)
            data_to_sign = self.encrypted_content if self.is_encrypted else self.content
            if not data_to_sign:
                return
            h = SHA256.new(data_to_sign.encode('utf-8'))
            signature_bytes = pkcs1_15.new(private_key).sign(h)
            self.signature = base64.b64encode(signature_bytes).decode('utf-8')
        except Exception as e:
            raise SignatureError("Signature for note failed.") from e

    def verify_signature(self):
        if not self.signature or not self.author.public_key:
            return False
        try:
            public_key = RSA.import_key(self.author.public_key.encode('utf-8'))
            data_to_verify = self.encrypted_content if self.is_encrypted else self.content
            if not data_to_verify:
                return False
            h = SHA256.new(data_to_verify.encode('utf-8'))
            sig = base64.b64decode(self.signature)

            pkcs1_15.new(public_key).verify(h, sig)
            return True
        except (ValueError, TypeError):
            return False

    def get_username(self):
        if not self.signature or not self.author.public_key:
            return "Unknown"
        try:
            public_key = RSA.import_key(self.author.public_key.encode('utf-8'))
            data = self.encrypted_content if self.is_encrypted else self.content
            if not data:
                return "Unknown"
            h = SHA256.new(data.encode('utf-8'))
            sig = base64.b64decode(self.signature)
            pkcs1_15.new(public_key).verify(h, sig)
            return self.author.username
        except (ValueError, TypeError):
            return "Invalid Signature"

    def get_serialized_id(self):
        return serializer.dumps(self.id)

    @staticmethod
    def get_deserialized_id(serialized_id):
        try:
            return serializer.loads(serialized_id)
        except Exception:
            return None
