from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
from flask import current_app
from .exceptions import EncryptionError, DecryptionError


def encrypt_data(data, key_config):
    try:
        key = base64.b64decode(current_app.config.get(key_config))
        iv = get_random_bytes(12)
        aes = AES.new(key, AES.MODE_GCM, iv)
        encrypted_data, tag = aes.encrypt_and_digest(data)
        return base64.b64encode(iv + tag + encrypted_data).decode('utf-8')
    except Exception as e:
        raise EncryptionError("Failed to encrypt data.") from e


def decrypt_data(encrypted, key_config):
    try:
        key = base64.b64decode(current_app.config.get(key_config))
        encrypted = base64.b64decode(encrypted)
        iv = encrypted[:12]
        tag = encrypted[12:28]
        encrypted_data = encrypted[28:]
        aes = AES.new(key, AES.MODE_GCM, iv)
        decrypted_data = aes.decrypt_and_verify(encrypted_data, tag)
        return decrypted_data.decode('utf-8')
    except (ValueError, TypeError) as e:
        raise DecryptionError("Decryption failed.") from e
