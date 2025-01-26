from flask import Blueprint, render_template
from flask_login import login_required, current_user
from ..models import LoginHistory

app_bp = Blueprint("main", __name__)


@app_bp.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")


@app_bp.route("/user/login-history")
@login_required
def login_history():
    logins = LoginHistory.query.filter_by(user_id=current_user.id).all()

    return render_template("login_history.html", logins=logins)

