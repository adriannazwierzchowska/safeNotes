from flask import Blueprint, render_template, session, request, redirect, url_for, flash, abort
from .models import User
from . import db, login_manager
from .forms import RegistrationForm, LoginForm
from flask_login import login_user, login_required, logout_user, current_user
from urllib.parse import urlparse
from extensions import limiter
import time
import pyotp

app_bp = Blueprint("main", __name__)
DELAY = 0.5

import logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

@app_bp.errorhandler(Exception)
def handle_exception(e):
    logger.exception("Unhandled exception: %s", e)
    return "An error occurred", 500

@app_bp.route("/")
def home():
    return render_template("index.html")

@app_bp.route("/login", methods={"POST", "GET"})
@limiter.limit("10 per minute")
def login():
    form = LoginForm()
    if request.method == "POST" and form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        totp = request.form.get("totp")

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password) and user.check_totp(totp):
            login_user(user)

            next = request.args.get('next')
            # logger.debug(f"next: {next}")
            # if not url_has_allowed_host_and_scheme(next, request.host):
            #     return abort(400, description="Invalid redirect URL") # TODO CHANGE

            time.sleep(DELAY)
            if not next or not url_has_allowed_host_and_scheme(next, request.host):
                logger.warning("Invalid or missing `next` parameter. Redirecting to dashboard.")
                return redirect(url_for("main.dashboard"))
            return redirect(next or url_for("main.dashboard"))
        else:
            time.sleep(DELAY)
            flash("Please try again.", "danger")
            return redirect(url_for("main.login"))

    return render_template("login.html", form=form)

@app_bp.route("/register", methods=["POST", "GET"])
@limiter.limit("10 per minute")
def register():
    form = RegistrationForm()
    if request.method == "POST" and form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data

        user = User.query.filter((User.username == username) | (User.email == email)).first()
        if user:
            flash("Please choose a different username or email.", "danger")
            time.sleep(DELAY)
            return render_template("register.html", form=form)  # TODO

        new_user = User(username=username, email=email)
        new_user.set_password(password)
        new_user.generate_totp_secret()
        db.session.add(new_user)
        db.session.commit()

        totp = pyotp.TOTP(new_user.totp_secret)
        qr_code_url = totp.provisioning_uri(name=new_user.email, issuer_name="NotesApp")

        #flash("Registration successful! You can log in now.", "success")
        time.sleep(DELAY)
        return render_template("show_qr.html", qr_code_url=qr_code_url)
    else:
        for field, errors in form.errors.items():
            for error in errors:
                flash(f"{field.capitalize()}: {error}", "danger") # TODO
    return render_template("register.html", form=form)

@app_bp.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", username=current_user.username)

@app_bp.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out successfully.", "info")
    return redirect(url_for("main.home"))


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def url_has_allowed_host_and_scheme(url, host):
    if not url:
        return False

    url = url.strip()
    parsed_url = urlparse(url)
    logger.debug(f"url: {url}")
    # if parsed_url.scheme != "http": #TODO HTTPS FOR PRODUCTION
    #     return False

    if parsed_url.scheme not in ("http", "https", ""):
        return False

    return parsed_url.netloc in ("", host)
    # return parsed_url.netloc == "" or parsed_url.netloc == host
