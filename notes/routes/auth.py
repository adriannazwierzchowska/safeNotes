from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app, session
from ..models import User, LoginHistory, EncryptionError, decrypt_data, DecryptionError
from .. import db, login_manager, mail
from ..forms import RegistrationForm, LoginForm, TOTPAuthForm, PasswordResetRequestForm, PasswordResetForm
from flask_login import login_user, login_required, logout_user
from extensions import limiter, username_limit
import time
import pyotp
from flask_mail import Message
from datetime import datetime
from pytz import timezone
import uuid


auth_bp = Blueprint("auth", __name__)
DELAY = 0.5


@auth_bp.route("/login", methods=["POST", "GET"])
@limiter.limit("5 per minute", key_func=username_limit, methods=['POST'])
def login():
    form = LoginForm()
    random_id = uuid.uuid4().hex
    try:
        if request.method == "POST" and form.validate_on_submit():
            username = form.username.data
            password = form.password.data
            totp = form.totp.data

            if form.hp.data:
                current_app.logger.warning(f"Honeypot triggered from {request.remote_addr}.")
                flash("Please try again.", "danger")
                time.sleep(DELAY)
                return redirect(url_for("auth.login"))

            user = User.query.filter_by(username=username).first()
            if user and user.check_password(password) and user.check_totp(totp):
                login_user(user)

                ip_address = request.remote_addr or "unknown"
                user_agent = request.headers.get('User-Agent') or "unknown"
                current_time = datetime.now(timezone("Europe/Warsaw"))

                history = LoginHistory.query.filter_by(user_id=user.id, ip_address=ip_address, user_agent=user_agent).first()
                if history:
                    history.last_seen = current_time
                else:
                    new = LoginHistory(user_id=user.id, ip_address=ip_address, user_agent=user_agent, first_seen=current_time, last_seen=current_time)
                    db.session.add(new)

                db.session.commit()
                flash("Login successful!", "success")
                return redirect(url_for("main.dashboard"))
            else:
                time.sleep(DELAY)
                current_app.logger.warning(f"Failed: login for user '{username}'.")
                flash("Please try again.", "danger")
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    flash(f"{field}: {error}", "danger")
    except Exception as e:
        current_app.logger.exception(f"Error: during login from {request.remote_addr}.")
        flash("An unexpected error occurred. Please try again.", "danger")
    return render_template("auth/login.html", form=form, random_id=random_id)


@auth_bp.route("/register", methods=["POST", "GET"])
@limiter.limit("5 per minute", key_func=username_limit, methods=['POST'])
def register():
    form = RegistrationForm()
    try:
        if request.method == "POST" and form.validate_on_submit():
            username = form.username.data
            email = form.email.data
            password = form.password.data

            user = User.query.filter((User.username == username) | (User.email == email)).first()
            if user:
                flash("Please choose a different username or email.", "danger")
                time.sleep(DELAY)
                return redirect(url_for("auth.register"))

            new_user = User(username=username, email=email)
            new_user.set_password(password)
            try:
                new_user.generate_totp_secret()
                totp = pyotp.TOTP(decrypt_data(new_user.totp_secret, "AES_KEY_TOTP"))
                qr_code_url = totp.provisioning_uri(name=new_user.email, issuer_name="NotesApp")
            except (EncryptionError, DecryptionError) as e:
                flash("Couldn't generate your TOTP secret. Please try again.", "danger")
                return redirect(url_for("auth.register"))

            session['new_user'] = {
                "username": new_user.username,
                "email": new_user.email,
                "password_hashed": new_user.password_hashed,
                "totp_secret": new_user.totp_secret,
                "qr_code_url": qr_code_url
            }

            return redirect(url_for("auth.register_auth"))
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    flash(f"{field}: {error}", "danger")
    except Exception as e:
        current_app.logger.exception(f"Error: failed registration from {request.remote_addr}.")
        flash("An unexpected error occurred. Please try again.", "danger")
    return render_template("auth/register.html", form=form)


@auth_bp.route("/register-auth", methods=["POST", "GET"])
@limiter.limit("5 per minute", key_func=username_limit, methods=['POST'])
def register_auth():
    form = TOTPAuthForm()
    if "new_user" not in session:
        flash("Please register again.", "danger")
        return redirect(url_for("auth.register"))
    new_user_data = session['new_user']
    qr_code_url = new_user_data.get("qr_code_url")

    if request.method == "POST" and form.validate_on_submit():
        totp_code = form.totp.data
        try:
            new_user = User(username=new_user_data["username"], email=new_user_data["email"], password_hashed=new_user_data["password_hashed"], totp_secret=new_user_data["totp_secret"])
            if not new_user.check_totp(totp_code):
                flash("Invalid TOTP code. Please try again.", "danger")
                return redirect(url_for("auth.register_auth"))

            new_user.generate_rsa_keys()
            db.session.add(new_user)
            db.session.commit()
            session.pop("new_user", None)

            flash("Registration successful! You can now log in.", "success")
            return redirect(url_for("auth.login"))
        except Exception as e:
            current_app.logger.exception(f"Error: during TOTP authentication from {request.remote_addr}.")
            flash("An unexpected error occurred. Please try again.", "danger")
            db.session.rollback()
            return redirect(url_for("auth.register"))

    return render_template("auth/register_auth.html", form=form, qr_code_url=qr_code_url)
@auth_bp.route("/logout")
@login_required
def logout():
    try:
        logout_user()
        flash("Logged out successfully.", "info")
    except Exception as e:
        current_app.logger.exception(f"Error: during logout from {request.remote_addr}.")
        flash("An unexpected error occurred. Please try again.", "danger")
    return redirect(url_for("notes.home"))


@auth_bp.route("/password_reset_request", methods=["POST", "GET"])
@limiter.limit("2 per minute", key_func=username_limit, methods=['POST'])
def password_reset_request():
    form = PasswordResetRequestForm()
    try:
        if request.method == "POST" and form.validate_on_submit():
            username = form.username.data
            email = form.email.data
            totp = form.totp.data

            user = User.query.filter_by(username=username, email=email).first()
            if user and user.check_totp(totp):
                token = user.get_reset_password_token()

                msg = Message(
                    'NotesApp: Password reset',
                    sender=current_app.config['MAIL_USERNAME'],
                    recipients=[user.email],
                )

                msg.html = render_template('password_reset/password_reset_email.html', user=user, token=token)
                msg.body = render_template('password_reset/password_reset_email.txt', user=user, token=token)

                mail.send(msg)

                flash("Email sent. Check your inbox!", "success")
                return redirect(url_for("auth.login"))
            else:
                time.sleep(DELAY)
                current_app.logger.warning(f"Failed: password reset email not sent for {request.remote_addr}.")
                flash("Please try again.", "danger")
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    flash(f"{field}: {error}", "danger")
    except Exception as e:
        current_app.logger.exception(f"Error: during sending a password reset email for {request.remote_addr}.")
        flash("An unexpected error occurred. Please try again.", "danger")
    return render_template("password_reset/password_reset_request.html", form=form)


@auth_bp.route("/password_reset/<token>", methods=["POST", "GET"])
@limiter.limit("2 per minute", key_func=lambda: request.remote_addr, methods=['POST'])
def password_reset(token):
    form = PasswordResetForm()
    try:
        if request.method == "POST" and form.validate_on_submit():
            password = form.password.data
            totp = form.totp.data

            user = User.verify_reset_password_token(token)
            if user and user.check_totp(totp):
                user.set_password(password)
                db.session.commit()

                flash("Password reset. You can log in now!", "success")
                return redirect(url_for("auth.login"))
            else:
                time.sleep(DELAY)
                current_app.logger.warning(f"Failed: password reset from {request.remote_addr}.")
                flash("Please try again.", "danger")
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    flash(f"{field}: {error}", "danger")
    except Exception as e:
        current_app.logger.exception(f"Error: during password reset from {request.remote_addr}.")
        flash("An unexpected error occurred. Please try again.", "danger")
    return render_template("password_reset/password_reset.html", form=form)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))