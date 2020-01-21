from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, IntegerField, BooleanField
from wtforms.validators import DataRequired

class SubjectForm(FlaskForm):
    """
    Form for admin to add or edit a subject
    """
    subject_name = StringField('subject_name', validators=[DataRequired()])
    submit = SubmitField('Submit')

class StudentForm(FlaskForm):
    """
    Form for admin to add or edit a subject
    """
    student_name = StringField('student_name', validators=[DataRequired()])
    student_surname = StringField('student_surname', validators=[DataRequired()])
    student_course = IntegerField('student_course', validators=[DataRequired()])
    student_studybook = IntegerField('student_studybook', validators=[DataRequired()])
    submit = SubmitField('Submit')

class LabForm(FlaskForm):
    """
    Form for admin to add or edit a subject
    """
    lab_number = IntegerField('lab_number', validators=[DataRequired()])
    subject_id = IntegerField('subject_id', validators=[DataRequired()])
    submit = SubmitField('Submit')

class LabResultForm(FlaskForm):
    """
    Form for admin to add or edit a subject
    """
    lab_id = IntegerField('lab_id', validators=[DataRequired()])
    student_id = IntegerField('student_id', validators=[DataRequired()])
    is_passed = BooleanField('is_passed')
    submit = SubmitField('Submit')

class SkillForm(FlaskForm):
    """
    Form for admin to add or edit a subject
    """
    subject_id = IntegerField('subject_id', validators=[DataRequired()])
    skill_grade = StringField('skill_grade', validators=[DataRequired()])
    submit = SubmitField('Submit')

class StudentSkillForm(FlaskForm):
    """
    Form for admin to add or edit a subject
    """
    student_id = StringField('student_id', validators=[DataRequired()])
    skill_id = StringField('skill_id', validators=[DataRequired()])
    submit = SubmitField('Submit')

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')

from app import db
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    email = db.Column(db.String(120), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    def __repr__(self):
        return '<User {}>'.format(self.username)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

from app import login

@login.user_loader
def load_user(id):
    return User.query.get(int(id))

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import ValidationError, DataRequired, Email, EqualTo
from app.models import User

# ...

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    password2 = PasswordField(
        'Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('Please use a different username.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('Please use a different email address.')
