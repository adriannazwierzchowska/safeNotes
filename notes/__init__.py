from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from extensions import limiter
import logging

db = SQLAlchemy()
login_manager = LoginManager()

def create_app():
    app = Flask(__name__)
    app.config.from_object("config.Config")

    logging.basicConfig(
        level=app.config["LOG_LEVEL"],
        format=app.config["LOG_FORMAT"],
        handlers=[
            logging.FileHandler(app.config["LOG_FILE"]),
            logging.StreamHandler()
        ]
    )
    app.logger = logging.getLogger("flask_app")

    db.init_app(app)
    limiter.init_app(app)

    login_manager.init_app(app)
    login_manager.login_view = "main.login"

    from .routes import app_bp
    app.register_blueprint(app_bp)

    return app

