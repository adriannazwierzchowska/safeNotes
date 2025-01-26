from .auth import auth_bp
from .main import app_bp
from .notes import notes_bp

def register_routes(app):
    app.register_blueprint(auth_bp)
    app.register_blueprint(app_bp)
    app.register_blueprint(notes_bp)