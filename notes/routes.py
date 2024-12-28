from flask import Blueprint, render_template, session, request, redirect, url_for, flash, abort
from .models import User, Note
from . import db, login_manager
from .forms import RegistrationForm, LoginForm, NoteForm, DecryptNoteForm
from flask_login import login_user, login_required, logout_user, current_user
from urllib.parse import urlparse
from extensions import limiter
import time
import pyotp
import markdown
import bleach

app_bp = Blueprint("main", __name__)
DELAY = 0.5
allowed_tags = ["p", "b", "i", "u", "a", "img", "h1", "h2", "h3", "h4", "h5", "h6"]
allowed_attrs = {"a": ["href"], "img": ["src", "alt"]}

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

@app_bp.route("/notes", methods=["GET"])
@login_required
def notes():
    decrypt_form = DecryptNoteForm()
    user_notes = Note.query.filter_by(author_id=current_user.id).all()

    for note in user_notes:
        if not note.is_encrypted:
            rendered_markdown = markdown.markdown(note.content, extensions=["extra"])
            note.clean_content = bleach.clean(rendered_markdown, tags=allowed_tags, attributes=allowed_attrs)

    return render_template("notes.html", notes=user_notes, decrypt_form=decrypt_form)

@app_bp.route("/add-note", methods=["GET", "POST"])
@login_required
def add_note():
    form = NoteForm()
    if request.method == "POST" and form.validate_on_submit():
        title = form.title.data
        content = form.content.data
        is_encrypted = form.is_encrypted.data
        code = form.code.data

        new_note = Note(title=title, content=content, author_id=current_user.id)

        if is_encrypted:
            new_note.encrypt(content.encode('utf-8'), code.encode('utf-8'))

        #new_note.sign(private_key=current_user.private_key)
        db.session.add(new_note)
        db.session.commit()
        flash("Note saved successfully!", "success")
    user_notes = Note.query.filter_by(author_id=current_user.id).all()
    return render_template("add_note.html", notes=user_notes, form=form)

@app_bp.route("/decrypt-note/<int:note_id>", methods=["POST"])
@login_required
def decrypt_notes(note_id):
    form = DecryptNoteForm()
    if form.validate_on_submit():
        code = form.code.data
        note = Note.query.filter_by(id=note_id, author_id=current_user.id).first()

        if not note:
            flash("Note not found or you do not have permission to view it.", "danger")
            return redirect(url_for("main.dashboard"))
        if not code:
            flash("Please provide a code for decryption.", "danger")
            return redirect(url_for("main.dashboard"))

        try:
            decrypted_content = note.decrypt(code.encode('utf-8'))
            note.decrypted_content = decrypted_content.decode('utf-8')
            flash("Note decrypted!", "success")
            return redirect(url_for("main.view_note", note_id=note.id, decrypted_content=decrypted_content))
        except ValueError:
            flash("Invalid passphrase. Unable to decrypt note.", "danger")
    return redirect(url_for("main.dashboard"))

@app_bp.route("/view-note/<int:note_id>")
@login_required
def view_note(note_id):
    decrypted_content = request.args.get("decrypted_content")
    note = Note.query.filter_by(id=note_id, author_id=current_user.id).first()

    if not note:
        flash("Note not found or you do not have permission to view it.", "danger")
        return redirect(url_for("main.dashboard"))

    if not decrypted_content:
        flash("Failed to retrieve decrypted content.", "danger")
        return redirect(url_for("main.dashboard"))

    rendered_markdown = markdown.markdown(decrypted_content, extensions=["extra"])
    clean_content = bleach.clean(rendered_markdown, tags=allowed_tags, attributes=allowed_attrs)

    return render_template("view_note.html", note=note, decrypted_content=clean_content)


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
