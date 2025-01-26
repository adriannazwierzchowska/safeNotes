from flask import Flask, flash, redirect, url_for
from extensions import db, login_manager, mail, limiter, csrf
import logging
from werkzeug.middleware.proxy_fix import ProxyFix
from .routes import app_bp, auth_bp, notes_bp


def configure_logging(app):
    logging.basicConfig(
        level=app.config["LOG_LEVEL"],
        format=app.config["LOG_FORMAT"],
        handlers=[logging.FileHandler(app.config["LOG_FILE"]),logging.StreamHandler()]
    )
    app.logger = logging.getLogger("flask_app")


def configure_extensions(app):
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    limiter.init_app(app)
    mail.init_app(app)
    csrf.init_app(app)


def configure_blueprints(app):
    app.register_blueprint(app_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(notes_bp)


def configure_error_handling(app):
    app.config["DEBUG"] = False
    app.config["PROPAGATE_EXCEPTIONS"] = False

    @app.errorhandler(405)
    def method_not_allowed(e):
        flash("Request not allowed.", "danger")
        return redirect(url_for("notes.home"))

    @app.errorhandler(429)
    def rate_limit_error(e):
        flash("Too many requests. Please try again later.", "danger")
        return redirect(url_for("notes.home"))


def create_app():
    app = Flask(__name__, static_folder="static")
    app.config.from_object("config.Config")
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

    configure_logging(app)
    configure_extensions(app)

    with app.app_context():
        limiter.storage.reset()

    configure_blueprints(app)
    configure_error_handling(app)

    return app
