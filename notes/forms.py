from wtforms import StringField, PasswordField, SubmitField, ValidationError, BooleanField
from wtforms.validators import DataRequired, Email, EqualTo, Length, Regexp
from flask_wtf import FlaskForm
import math

def calculate_entropy(password):
    unique_chars = set(password)
    pool_size = len(unique_chars)

    if pool_size == 0:
        return 0

    return len(password) * math.log2(pool_size)
def password_strength_check(form, field):
    password = field.data
    entropy = calculate_entropy(password)
    if entropy < 40:
        raise ValidationError(f"Password is too weak.")

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=20), Regexp(r'^[a-zA-Z0-9_]+$')])
    email = StringField('Email', validators=[DataRequired(), Email(), Length(min=3, max=120)]) # TODO - ADD REGEX
    password = PasswordField('Password', validators=[DataRequired(), Length(min=3, max=20), Regexp(r'^[a-zA-Z0-9_]+$'), password_strength_check])
    confirm = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password'), Length(min=8, max=30), Regexp(r'^[a-zA-Z0-9_]+$')])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    totp = StringField('TOTP Code', validators=[DataRequired(), Length(min=6, max=6)])
    submit = SubmitField('Login')


class NoteForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(max=30), Regexp(r'^[a-zA-Z0-9_]+$')])
    content = StringField('Write your note here.', validators=[DataRequired()])
    is_encrypted = BooleanField('Do you want to encrypt the note?')
    code = StringField('Code')
    submit = SubmitField('Add note')

    def validate_code(self, field):
        if self.is_encrypted.data and (not field.data or len(field.data) < 3 or len(field.data) > 20):
            raise ValidationError("Incorrect code size.")

class DecryptNoteForm(FlaskForm):
    code = StringField('Code', validators=[DataRequired(), Length(min=3, max=20), password_strength_check])
    submit = SubmitField('Decrypt')




