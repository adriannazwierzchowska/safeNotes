from .. import db
import base64
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from .exceptions import SignatureError


class SharedNotes(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    note_id = db.Column(db.Integer, db.ForeignKey('note.id'), nullable=False)
    signature = db.Column(db.Text, nullable=True)

    user = db.relationship('User', backref='note_access')
    note = db.relationship('Note', backref='note_access')

    def sign_shared_note(self):
        if not self.user.private_key:
            raise SignatureError("No private key.")
        try:
            decrypted_key = self.user.get_decrypted_private_key()
            private_key = RSA.import_key(decrypted_key)
            data_to_sign = self.note.encrypted_content if self.note.is_encrypted else self.note.content
            if not data_to_sign:
                return
            h = SHA256.new(data_to_sign.encode('utf-8'))
            signature_bytes = pkcs1_15.new(private_key).sign(h)
            self.signature = base64.b64encode(signature_bytes).decode('utf-8')
        except Exception as e:
            raise SignatureError("Signature for note failed.") from e

    def verify_shared_signature(self):
        if not self.signature or not self.user.public_key:
            return False
        try:
            public_key = RSA.import_key(self.user.public_key.encode('utf-8'))
            data_to_verify = self.note.encrypted_content if self.note.is_encrypted else self.note.content
            if not data_to_verify:
                return False
            h = SHA256.new(data_to_verify.encode('utf-8'))
            sig = base64.b64decode(self.signature)
            pkcs1_15.new(public_key).verify(h, sig)
            return True
        except (ValueError, TypeError):
            return False

    def get_shared_username(self):
        if not self.signature or not self.user.public_key:
            return "Unknown"
        try:
            public_key = RSA.import_key(self.user.public_key.encode('utf-8'))
            data = self.encrypted_content if self.is_encrypted else self.content
            if not data:
                return "Unknown"
            h = SHA256.new(data.encode('utf-8'))
            sig = base64.b64decode(self.signature)
            pkcs1_15.new(public_key).verify(h, sig)
            return self.user.username
        except (ValueError, TypeError):
            return "Invalid Signature"

