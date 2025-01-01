from flask import Blueprint, render_template, request, redirect, url_for, flash, abort, current_app, session
from .models import User, Note, SharedNotes
from . import db, login_manager
from .forms import RegistrationForm, LoginForm, NoteForm, DecryptNoteForm, TOTPAuthForm
from flask_login import login_user, login_required, logout_user, current_user
from extensions import limiter
import time
import pyotp
import markdown
import bleach

app_bp = Blueprint("main", __name__)
DELAY = 0.5
allowed_tags = ["p", "b", "i", "u", "a", "img", "h1", "h2", "h3", "h4", "h5", "h6", "strong", "em"]
allowed_attrs = {"a": ["href"], "img": ["src", "alt"]}

@app_bp.route("/")
def home():
    decrypt_form = DecryptNoteForm()
    try:
        public_notes = Note.query.filter_by(is_public=True).all()
        if not public_notes:
            flash("There are no public notes.", "info")
        else:
            for note in public_notes:
                if not note.is_encrypted:
                    note.clean_content = sanitize_markdown(note.content)
    except Exception as e:
        current_app.logger.exception(f"Error: during loading public notes from {request.remote_addr} at {time.strftime('%Y-%m-%d %H:%M:%S')}")
        flash("An unexpected error occurred. Please try again.", "danger")
        public_notes = []

    return render_template("index.html", notes=public_notes, decrypt_form=decrypt_form)

@app_bp.route("/login", methods=["POST", "GET"])
@limiter.limit("5 per minute", key_func=lambda: request.remote_addr)
def login():
    form = LoginForm()
    try:
        if request.method == "POST" and form.validate_on_submit():
            username = form.username.data
            password = form.password.data
            totp = form.totp.data

            user = User.query.filter_by(username=username).first()
            if user and user.check_password(password) and user.check_totp(totp):
                login_user(user)
                current_app.logger.info(f"Success: '{username}' logged in successfully from {request.remote_addr} at {time.strftime('%Y-%m-%d %H:%M:%S')}.")
                flash("Login successful!", "success")
                return redirect(url_for("main.dashboard"))
            else:
                time.sleep(DELAY)
                current_app.logger.warning(f"Failed: login from {request.remote_addr} for user '{username}' at {time.strftime('%Y-%m-%d %H:%M:%S')}")
                flash("Please try again.", "danger")
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    flash(f"{error}", "danger")
    except Exception as e:
        current_app.logger.exception(f"Error: during login from {request.remote_addr} at {time.strftime('%Y-%m-%d %H:%M:%S')}")
        flash("An unexpected error occurred. Please try again.", "danger")
    return render_template("login.html", form=form)

@app_bp.route("/register", methods=["POST", "GET"]) #TODO - ADD ANOTHER LAYER OF CHECKING INPUT?
@limiter.limit("5 per minute", key_func=lambda: request.remote_addr)
def register():
    form = RegistrationForm()
    try:
        if request.method == "POST" and form.validate_on_submit():
            username = form.username.data
            email = form.email.data
            password = form.password.data

            user = User.query.filter((User.username == username) | (User.email == email)).first()
            if user:
                current_app.logger.warning(f"Failed: register from {request.remote_addr} for {username}, {email} at {time.strftime('%Y-%m-%d %H:%M:%S')}")
                flash("Please choose a different username or email.", "danger")
                time.sleep(DELAY)
                return redirect(url_for("main.register"))

            new_user = User(username=username, email=email)
            new_user.set_password(password)
            new_user.generate_totp_secret()

            totp = pyotp.TOTP(new_user.decrypt_totp())
            qr_code_url = totp.provisioning_uri(name=new_user.email, issuer_name="NotesApp")

            session['new_user'] = {
                "username": new_user.username,
                "email": new_user.email,
                "password_hashed": new_user.password_hashed,
                "totp_secret": new_user.totp_secret,
                "qr_code_url": qr_code_url
            }

            current_app.logger.info(f"Success: started registration from {request.remote_addr} for user '{username}' at {time.strftime('%Y-%m-%d %H:%M:%S')}")
            return redirect(url_for("main.register_auth"))
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    flash(f"{error}", "danger")
    except Exception as e:
        current_app.logger.exception(f"Error: registration from {request.remote_addr} at {time.strftime('%Y-%m-%d %H:%M:%S')}")
        flash("An unexpected error occurred. Please try again.", "danger")
    return render_template("register.html", form=form)

@app_bp.route("/register-auth", methods=["POST", "GET"])
@limiter.limit("5 per minute", key_func=lambda: request.remote_addr)
def register_auth():
    form = TOTPAuthForm()
    if "new_user" not in session:
        current_app.logger.warning(f"Failed: new user not in session from {request.remote_addr} at {time.strftime('%Y-%m-%d %H:%M:%S')}")
        flash("Please register again.", "danger")
        return redirect(url_for("main.register"))
    new_user_data = session['new_user']
    qr_code_url = new_user_data.get("qr_code_url")

    if request.method == "POST" and form.validate_on_submit():
        totp_code = form.totp.data

        try:
            new_user = User(username=new_user_data["username"], email=new_user_data["email"], password_hashed=new_user_data["password_hashed"], totp_secret=new_user_data["totp_secret"])
            if not new_user.check_totp(totp_code):
                flash("Invalid TOTP code. Please try again.", "danger")
                return redirect(url_for("main.register_auth"))

            db.session.add(new_user)
            db.session.commit()

            session.pop("new_user", None)

            current_app.logger.info(f"Success: new user {new_user_data['username']} registered and TOTP authenticated from {request.remote_addr} at {time.strftime('%Y-%m-%d %H:%M:%S')}")
            flash("Registration successful! You can now log in.", "success")
            return redirect(url_for("main.login"))
        except Exception as e:
            current_app.logger.exception(f"Error: during TOTP authentication from {request.remote_addr} at {time.strftime('%Y-%m-%d %H:%M:%S')}")
            flash("An unexpected error occurred. Please try again.", "danger")
            db.session.rollback()
            return redirect(url_for("main.register"))

    return render_template("register_auth.html", form=form, qr_code_url=qr_code_url)


@app_bp.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")

@app_bp.route("/logout")
@login_required
def logout():
    try:
        username = current_user.username
        logout_user()
        current_app.logger.info(f"Success: user {username} logged out from {request.remote_addr} at {time.strftime('%Y-%m-%d %H:%M:%S')}")
        flash("Logged out successfully.", "info")
    except Exception as e:
        current_app.logger.exception(f"Error: during logout for user '{username}' from {request.remote_addr}.")
        flash("An unexpected error occurred. Please try again.", "danger")
    return redirect(url_for("main.home"))

@app_bp.route("/notes", methods=["GET"])
@login_required
def notes():
    decrypt_form = DecryptNoteForm()
    try:
        user_notes = Note.query.filter_by(author_id=current_user.id).all()
        shared_notes = Note.query.join(SharedNotes).filter(SharedNotes.user_id == current_user.id).all()

        notes = user_notes + shared_notes
        for note in notes:
            if not note.is_encrypted:
                note.clean_content = sanitize_markdown(note.content)
    except Exception as e:
        current_app.logger.exception(f"Error: loading notes for user {current_user.username} from {request.remote_addr} at {time.strftime('%Y-%m-%d %H:%M:%S')}")
        flash("An unexpected error occurred. Please try again.", "danger")
        notes = []
    return render_template("notes.html", notes=notes, decrypt_form=decrypt_form)

@app_bp.route("/add-note", methods=["GET", "POST"])
@login_required
def add_note():
    form = NoteForm()
    try:
        if request.method == "POST" and form.validate_on_submit():
            title = form.title.data
            content = form.content.data
            is_public = form.is_public.data
            is_shared = form.is_shared.data
            shared_users = form.shared_users.data
            is_encrypted = form.is_encrypted.data
            code = form.code.data

            note = Note(title=title, content=content, author_id=current_user.id, is_public=is_public)

            if is_encrypted:
                if not code:
                    flash("Please provide a code to encrypt the note.", "danger")
                    return render_template("add_note.html", form=form)
                note.encrypt(content.encode('utf-8'), code.encode('utf-8'))

            #new_note.sign(private_key=current_user.private_key)
            db.session.add(note)
            db.session.flush()

            if is_shared and shared_users:
                usernames = [username.strip() for username in shared_users.split(',')]
                for username in usernames:
                    user = User.query.filter_by(username=username).first()
                    if user:
                        shared_note = SharedNotes(user_id=user.id, note_id=note.id)
                        db.session.add(shared_note)
                    else:
                        flash(f"Skipping users that do not exist.", "danger")
            db.session.commit()
            current_app.logger.info(f"Success: added a note id:{note.id} for {request.remote_addr} user '{current_user.username}' at {time.strftime('%Y-%m-%d %H:%M:%S')}")
            flash("Note saved successfully!", "success")
    except Exception as e:
        current_app.logger.exception(f"Error while adding a note: {request.remote_addr} for {current_user.username} at {time.strftime('%Y-%m-%d %H:%M:%S')}")
        flash("An unexpected error occurred. Please try again.", "danger")
        db.session.rollback()

    return render_template("add_note.html", form=form)

@app_bp.route("/decrypt-note/<int:note_id>", methods=["POST"])
@login_required
def decrypt_notes(note_id):
    form = DecryptNoteForm()
    try:
        if form.validate_on_submit():
            code = form.code.data
            note = Note.query.filter_by(id=note_id).first()

            if not note:
                current_app.logger.warning(f"Failed: Note {note_id} for decrypting not found for user {current_user.username} from {request.remote_addr} at {time.strftime('%Y-%m-%d %H:%M:%S')}")
                flash("Note not found or you do not have permission to view it.", "danger")
                return redirect(url_for("main.dashboard"))
            if not note.is_public and note.author_id != current_user.id:
                current_app.logger.warning(f"Failed: Unauthorized access attempt for note {note_id} by user {current_user.username} from {request.remote_addr} at {time.strftime('%Y-%m-%d %H:%M:%S')}")
                flash("You do not have permission to view this note.", "danger")
                return redirect(url_for("main.dashboard"))

            try:
                decrypted_content = note.decrypt(code.encode('utf-8'))
                clean_content = sanitize_markdown(decrypted_content)
                current_app.logger.info(f"Success: Note {note_id} decrypted for user {current_user.username} from {request.remote_addr} at {time.strftime('%Y-%m-%d %H:%M:%S')}")
                flash("Note decrypted!", "success")
                return render_template("view_note.html", note=note, clean_content=clean_content)
            except ValueError:
                current_app.logger.warning(f"Failed: Invalid decryption code for note {note_id} by user {current_user.username} from {request.remote_addr} at {time.strftime('%Y-%m-%d %H:%M:%S')}")
                flash("Invalid passphrase. Unable to decrypt note.", "danger")
    except Exception as e:
        current_app.logger.exception(f"Error: during decryption for note {note_id} by user {current_user.username} from {request.remote_addr} at {time.strftime('%Y-%m-%d %H:%M:%S')}")
        flash("An unexpected error occurred. Please try again.", "danger")

    return redirect(url_for("main.dashboard"))

@app_bp.route("/view-note/<int:note_id>")
@login_required
def view_note(note_id):
    decrypted_content = request.args.get("decrypted_content")
    try:
        note = Note.query.filter_by(id=note_id).first()

        if not note:
            current_app.logger.warning(f"Failed: Note {note_id} not found for user {current_user.username} from {request.remote_addr}")
            flash("Note not found or you do not have permission to view it.", "danger")
            return redirect(url_for("main.dashboard"))

        if decrypted_content:
            note.clean_content = sanitize_markdown(decrypted_content.decode("utf-8"))
            current_app.logger.info(f"Success: Displayed decrypted note {note_id} for user {current_user.username} from {request.remote_addr}")
            return render_template("view_note.html", note=note)
        else:
            if not note.is_public and note.author_id != current_user.id:
                current_app.logger.warning(f"Failed: Unauthorized access attempt for note {note_id} by user {current_user.username} from {request.remote_addr}")
                flash("You do not have permission to view this note.", "danger")
                return redirect(url_for("main.dashboard"))
            flash("Failed to retrieve decrypted content.", "danger")
            return redirect(url_for("main.dashboard"))

    except Exception as e:
        current_app.logger.exception(f"Error: during viewing note {note_id} by user {current_user.username} from {request.remote_addr}")
        flash("An unexpected error occurred. Please try again.", "danger")
    return redirect(url_for("main.dashboard"))


@app_bp.route("/public-notes", methods=["GET"])
@login_required
def public_notes():
    decrypt_form = DecryptNoteForm()
    try:
        public_notes = Note.query.filter_by(is_public=True).all()
        for note in public_notes:
            if not note.is_encrypted:
                note.clean_content = sanitize_markdown(note.content)

        current_app.logger.info(f"Success: Loaded public notes from {request.remote_addr} at {time.strftime('%Y-%m-%d %H:%M:%S')}")
    except Exception as e:
        current_app.logger.exception(f"Error: during loading public notes from {request.remote_addr} at {time.strftime('%Y-%m-%d %H:%M:%S')}")
        flash("An unexpected error occurred. Please try again.", "danger")
        public_notes = []
    return render_template("notes.html", notes=public_notes, decrypt_form=decrypt_form)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def sanitize_markdown(content):
    try:
        rendered_markdown = markdown.markdown(content, extensions=["extra"])
        clean_content = bleach.clean(rendered_markdown, tags=allowed_tags, attributes=allowed_attrs)
        return clean_content
    except Exception as e:
        return "Error sanitizing markdown"
