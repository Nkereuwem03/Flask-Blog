from flask_wtf import FlaskForm
from flask_login import current_user
from wtforms import StringField, PasswordField, SubmitField, BooleanField, SelectField, TextAreaField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError, Regexp, AnyOf
from flask_wtf.file import FileField, FileAllowed, FileRequired, FileSize, FileStorage
from Blog.models import Users, Role
from Blog.extensions import bcrypt
import pycountry

# countries = [(value to be shown on form, label to be stored in database)]
countries = [(country.name, country.name) for country in pycountry.countries]

class SignUpForm(FlaskForm):

    username = StringField("Username", validators=[DataRequired(message="Please input your username"),
                                                   Length(min=5, max=15,
                                                          message="Username must be between 5 and 10 characters"),
                                                   Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0, 'Usernames must have only letters, numbers, dots or ''underscores')])
    email = StringField("Email", validators=[DataRequired(message="Please input your email"), Email(message="Please enter a valid email")])
    password = PasswordField("Password", validators=[DataRequired()])
    confirm_password = PasswordField("Confirm Password", validators=[EqualTo("password",
                                                                             message="Password do not match"),
                                                                     DataRequired()])
    location = SelectField('Location', choices=countries, validators=[DataRequired(message='Please entry a location'),
                                                                    AnyOf([choice[0] for choice in countries], message='Invalid choice. Please select a valid option.')])
    profile_picture = FileField("Profile Image", validators=[FileAllowed(['jpg', 'png'], "Images only!")])
    submit = SubmitField("Sign Up")

    def validate_username(self, username):
        self.username = username
        user = Users.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError(message="Username already exist!")

    def validate_email(self, email):
        self.email = email
        user = Users.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError(message="Email already exist!")

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    remember = BooleanField("Remember Me")
    submit = SubmitField("Log in")

class UpdateProfileForm(FlaskForm):
    username = StringField("Username")
    email = StringField("Email")
    profile_picture = FileField("Profile Image", validators=[FileAllowed(['jpg', 'png'], "Images only!")])
    submit = SubmitField("Update Profile")

    def validate_username(self, username):
        self.username = username
        if current_user.username != username.data:
            user = Users.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError("Username already exist!")

    def validate_email(self, email):
        self.email = email
        if current_user.email != email.data:
            user = Users.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError("Email already exist!")

class ChangePasswordForm(FlaskForm):
    current_password = PasswordField("Current password", validators=[DataRequired()])
    new_password = PasswordField("New password", validators=[DataRequired()])
    confirm_new_password = PasswordField("Confirm new password", validators=[EqualTo("new_password",
                                                                             message="Password do not match"),
                                                                     DataRequired()])
    submit = SubmitField("Change Password")

    def validate_current_password(self, current_password):
        self.current_password = current_password
        if not bcrypt.check_password_hash(current_user.password, current_password.data):
            raise ValidationError(message="Current password is not correct")

class RequestPasswordResetForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email(message="Please enter a valid email")])
    submit = SubmitField("Request password reset")


class ResetPasswordForm(FlaskForm):
    new_password = PasswordField("New password", validators=[DataRequired()])
    confirm_password = PasswordField("Confirm Password", validators=[EqualTo("new_password",
                                                                             message="Password do not match"),
                                                                     DataRequired()])
    submit = SubmitField("Reset Password")
    
class EditProfileAdminForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(1, 64), 
                                                   Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0, 
                                                          'Usernames must have only letters, numbers, dots or underscores')])
    email = StringField('Email', validators=[DataRequired(), Length(1, 64), Email()])
    confirmed = BooleanField('Confirmed')
    role = SelectField('Role', coerce=int)
    name = StringField('Real name', validators=[Length(0, 64)])
    location = SelectField('Location', choices=countries, validators=[DataRequired(message='Please entry a location'),
                                                                    AnyOf([choice[0] for choice in countries], message='Invalid choice. Please select a valid option.')])
    about_me = TextAreaField('About me')
    profile_picture = FileField("Profile Image", validators=[FileAllowed(['jpg', 'png'], "Images only!")])
    submit = SubmitField('Submit')
    
    def __init__(self, user, *args, **kwargs):
        super(EditProfileAdminForm, self).__init__(*args, **kwargs)
        self.role.choices = [(role.id, role.name)
                             for role in Role.query.order_by(Role.name).all()]
        self.user = user
 
    def validate_email(self, field):
        if field.data != self.user.email and \
            Users.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.')
    
    
    def validate_username(self, field):
        if field.data != self.user.username and Users.query.filter_by(username=field.data).first():
            raise ValidationError('Username already in use.')
