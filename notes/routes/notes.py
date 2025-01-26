from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app
from ..models import User, Note, SharedNotes, DecryptionError, EncryptionError, SignatureError
from .. import db, login_manager
from ..forms import NoteForm, DecryptNoteForm
from flask_login import login_required, current_user
import time
import markdown
import bleach

notes_bp = Blueprint("notes", __name__)
DELAY = 0.5

allowed_tags = [
    "p", "b", "i", "u", "a", "img", "h1", "h2", "h3", "h4", "h5", "h6", "strong", "em", "blockquote", "ul", "ol", "li", "code", "pre", "hr",
    "table", "thead", "tbody", "tr", "th", "td", "sup", "sub", "del", "mark", "span"
]
allowed_attrs = {"a": ["href", "title"], "img": ["src", "alt", "title"], "th": ["colspan", "rowspan"], "td": ["colspan", "rowspan"], "span": ["class"]}


@notes_bp.route("/")
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
        public_notes = []
        current_app.logger.exception(f"Error: during loading public notes from {request.remote_addr} at {time.strftime('%Y-%m-%d %H:%M:%S')}")
        flash("An unexpected error occurred. Please try again.", "danger")

    return render_template("index.html", notes=public_notes, decrypt_form=decrypt_form)


@notes_bp.route("/notes", methods=["GET"])
@login_required
def notes():
    decrypt_form = DecryptNoteForm()
    try:
        user_notes = Note.query.filter_by(author_id=current_user.id).all()
        shared_notes = Note.query.join(SharedNotes).filter(SharedNotes.user_id == current_user.id).all()

        notes = user_notes + shared_notes
        for note in notes:
            if not note.is_encrypted:
                if not note.verify_signature():
                    current_app.logger.warning(f"Failed: Signature for note {note.id} failed for user {current_user.username} from {request.remote_addr}")
                    flash(f"Signature verification for note titled '{note.title}' failed.", "danger")
                    return redirect(url_for("main.dashboard"))
                try:
                    note.clean_content = sanitize_markdown(note.content)
                except (ValueError, TypeError):
                    current_app.logger.warning(f"Failed: Invalid signature for note {note.id} by user {current_user.username} from {request.remote_addr}")
                    flash("You do not have permission to view this note.", "danger")
                    return redirect(url_for("main.dashboard"))
    except Exception as e:
        current_app.logger.exception(f"Error: loading notes for user {current_user.username} from {request.remote_addr}.")
        flash("An unexpected error occurred. Please try again.", "danger")
        notes = []
    return render_template("notes/notes.html", notes=notes, decrypt_form=decrypt_form)


@notes_bp.route("/add-note", methods=["GET", "POST"])
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
                    return render_template("notes/add_note.html", form=form)
                try:
                    note.encrypt(content, code)
                except EncryptionError as e:
                    current_app.logger.exception(f"Error: while encrypting note for user '{current_user.username}'.")
                    flash("Encryption failed. Please try again.", "danger")
                    return render_template("notes/add_note.html", form=form)

            db.session.add(note)
            db.session.flush()
            try:
                note.sign_note()
            except SignatureError as e:
                current_app.logger.exception(f"Failed: signing note for user '{current_user.username}'.")
                flash("Please try again.", "danger")
                db.session.rollback()
                return render_template("notes/add_note.html", form=form)

            if is_shared and shared_users:
                usernames = [username.strip() for username in shared_users.split(',')]
                for username in usernames:
                    user = User.query.filter_by(username=username).first()
                    if user:
                        shared_note = SharedNotes(user_id=user.id, note_id=note.id)
                        db.session.add(shared_note)
                        db.session.flush()
                        try:
                            shared_note.sign_shared_note()
                        except SignatureError as e:
                            current_app.logger.exception(f"Failed: signing note for user '{current_user.username}'.")
                            flash("Please try again.", "danger")
                            db.session.rollback()
                            return render_template("notes/add_note.html", form=form)
                    else:
                        flash(f"Skipping users that do not exist.", "danger")
            db.session.commit()
            flash("Note saved successfully!", "success")
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    flash(f"{field}: {error}", "danger")
    except Exception as e:
        current_app.logger.exception(f"Error while adding a note for {current_user.username}.")
        flash("An unexpected error occurred. Please try again.", "danger")
        db.session.rollback()

    return render_template("notes/add_note.html", form=form)


@notes_bp.route("/decrypt-note/<note_id>", methods=["POST"])
@login_required
def decrypt_notes(note_id):
    form = DecryptNoteForm()
    try:
        note_id = Note.get_deserialized_id(note_id)
        if not note_id:
            current_app.logger.warning(f"Failed: Invalid note_id {note_id} provided.")
            flash("Please try again.", "danger")
            return redirect(url_for("main.dashboard"))

        if form.validate_on_submit():
            code = form.code.data
            note = Note.query.filter_by(id=note_id).first()

            if not note:
                current_app.logger.warning(f"Failed: Note {note.id} for decrypting not found for user {current_user.username}.")
                flash("Note not found or you do not have permission to view it.", "danger")
                return redirect(url_for("main.dashboard"))
            if not note.is_public and note.author_id != current_user.id:
                shared_note = SharedNotes.query.filter_by(note_id=note.id, user_id=current_user.id).first()
                if not shared_note or not shared_note.verify_shared_signature():
                    current_app.logger.warning(f"Failed: Unauthorized access or invalid shared signature for note {note.id} by user {current_user.username}.")
                    flash("You do not have permission to view or decrypt this note.", "danger")
                    return redirect(url_for("main.dashboard"))
            if not note.verify_signature():
                current_app.logger.warning(f"Failed: Signature for {note.id} failed for user {current_user.username}.")
                flash("Signature verification failed.", "danger")
                return redirect(url_for("main.dashboard"))

            try:
                decrypted_content = note.decrypt(code)
                if decrypted_content:
                    if not note.is_encrypted or note.encrypted_content:
                        note.clean_content = sanitize_markdown(decrypted_content)
                        flash("Note decrypted!", "success")
                        return render_template("notes/view_note.html", note=note)
                    else:
                        flash("Decryption failed.", "danger")
                        return redirect(url_for("main.dashboard"))
            except DecryptionError as e:
                current_app.logger.warning(f"Failed: Invalid decryption code for note {note.id} by user {current_user.username} from {request.remote_addr}.")
                flash("Unable to decrypt note. Please try again", "danger")
                return redirect(url_for("main.dashboard"))
    except Exception as e:
        current_app.logger.exception(f"Error: during decryption from {request.remote_addr}.")
        flash("An unexpected error occurred. Please try again.", "danger")
    return redirect(url_for("main.dashboard"))


@notes_bp.route("/public-notes", methods=["GET"])
@login_required
def public_notes():
    decrypt_form = DecryptNoteForm()
    try:
        public_notes = Note.query.filter_by(is_public=True).all()
        for note in public_notes:
            if not note.is_encrypted:
                note.clean_content = sanitize_markdown(note.content)

    except Exception as e:
        current_app.logger.exception(f"Error: during loading public notes from {request.remote_addr}.")
        flash("An unexpected error occurred. Please try again.", "danger")
        public_notes = []
    return render_template("notes/notes.html", notes=public_notes, decrypt_form=decrypt_form)


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
