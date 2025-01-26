from wtforms import StringField, PasswordField, SubmitField, ValidationError, BooleanField, TextAreaField, HiddenField
from wtforms.validators import DataRequired, Email, EqualTo, Length, Regexp
from flask_wtf import FlaskForm
import math


USERNAME_REGEX = r'^[a-zA-Z0-9_]+$'
PASSWORD_REGEX = r'^[a-zA-Z0-9!@#$%^&*_+/?]+$'
NOTE_CONTENT_REGEX = r'^[a-zA-Z0-9#*.,?\s\n!\[\]\(\):/_\-\'"`’~>^<|{}+=@\[\]\\\\]*$'
TOTP_REGEX = r'^[0-9]+$'


def calculate_entropy(password):
    unique_chars = set(password)
    pool_size = len(unique_chars)
    return len(password) * math.log2(pool_size) if pool_size > 0 else 0


def password_strength_check(form, field, condition=True):
    if condition:
        password = field.data
        entropy = calculate_entropy(password)
        if entropy < 35:
            raise ValidationError("Password or code is too weak.")


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=20), Regexp(USERNAME_REGEX)])
    email = StringField('Email', validators=[DataRequired(), Email(), Length(min=3, max=120)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8, max=40), Regexp(PASSWORD_REGEX), password_strength_check])
    confirm = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password'), Length(min=8, max=30), Regexp(PASSWORD_REGEX)])
    submit = SubmitField('Register')


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=20), Regexp(USERNAME_REGEX)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8, max=40), Regexp(PASSWORD_REGEX)])
    totp = StringField('TOTP Code', validators=[DataRequired(), Length(min=6, max=6), Regexp(TOTP_REGEX)])
    hp = StringField('Hp')
    submit = SubmitField('Login')

    def validate_honeypot(self, field):
        if field.data:
            raise ValidationError("Honeypot triggered.")


class NoteForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(max=30), Regexp(USERNAME_REGEX)])
    content = TextAreaField('Write your note here.', validators=[DataRequired(), Length(max=1500), Regexp(NOTE_CONTENT_REGEX)])
    is_public = BooleanField('Do you want the note to be public?')
    is_shared = BooleanField('Do you want the note to be shared with chosen users?')
    shared_users = StringField('Usernames to share the note with (comma-separated)', validators=[Length(max=100), Regexp(r'^[a-zA-Z0-9_,]*$')])
    is_encrypted = BooleanField('Do you want to encrypt the note?')
    code = PasswordField('Code')
    submit = SubmitField('Add note')

    def validate_code(self, field):
        if self.is_encrypted.data:
            if not field.data:
                raise ValidationError("Please provide a code for encryption.")
            if len(field.data) < 8 or len(field.data) > 40:
                raise ValidationError("Code must be between 8 and 40 characters long.")
            if not Regexp(PASSWORD_REGEX).__call__(None, field):
                raise ValidationError("Code must only contain alphanumeric characters or underscores.")
            try:
                password_strength_check(None, field)
            except ValidationError as e:
                raise ValidationError(str(e))

    def validate_shared_users(self, field):
        if self.is_shared.data:
            if not field.data:
                raise ValidationError("Please provide usernames to share the note with.")
            usernames = [username.strip() for username in field.data.split(',')]
            if any(len(username) > 20 for username in usernames):
                raise ValidationError("Usernames must be less than 20 characters.")


class DecryptNoteForm(FlaskForm):
    code = PasswordField('Code', validators=[DataRequired(), Length(min=8, max=40), Regexp(PASSWORD_REGEX)])
    submit = SubmitField('Decrypt')


class TOTPAuthForm(FlaskForm):
    totp = StringField('TOTP Code', validators=[DataRequired(), Length(min=6, max=6), Regexp(TOTP_REGEX)])
    submit = SubmitField('Verify account')


class PasswordResetRequestForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=20), Regexp(USERNAME_REGEX)])
    email = StringField('Email', validators=[DataRequired(), Email(), Length(min=3, max=120)])
    totp = StringField('TOTP Code', validators=[DataRequired(), Length(min=6, max=6), Regexp(TOTP_REGEX)])
    submit = SubmitField('Send email with your new password')


class PasswordResetForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8, max=40), Regexp(PASSWORD_REGEX), password_strength_check])
    confirm = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password'), Length(min=8, max=30), Regexp(PASSWORD_REGEX)])
    totp = StringField('TOTP Code', validators=[DataRequired(), Length(min=6, max=6), Regexp(TOTP_REGEX)])
    submit = SubmitField('Reset your password')
