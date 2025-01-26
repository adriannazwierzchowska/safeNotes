from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf import CSRFProtect
from flask import request
from itsdangerous import URLSafeSerializer
from flask_login import LoginManager
from flask_mail import Mail

db = SQLAlchemy()
csrf = CSRFProtect()
login_manager = LoginManager()
mail = Mail()
limiter = Limiter(key_func=get_remote_address, storage_uri="memory://")
serializer = URLSafeSerializer("SECRET_KEY")

def username_limit():
    if request.method == "POST":
        username = request.form.get("username")
        if username:
            return f"login:{username.strip().lower()}"
    return f"ip:{request.remote_addr}"



