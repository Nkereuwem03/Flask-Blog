from flask import (Blueprint, render_template, redirect, url_for, 
                   flash, request, current_app, abort)
from flask_login import current_user, login_user, login_required, logout_user
from Blog.auth.forms import (SignUpForm, LoginForm, 
                             UpdateProfileForm, ChangePasswordForm, 
                             RequestPasswordResetForm, ResetPasswordForm,
                             EditProfileAdminForm)
from Blog.extensions import bcrypt, db
from Blog.models import Users, Post, Role
from Blog.auth.utils import (save_image, send_email, 
                             generate_password_reset_token, confirm_password_reset_token, 
                             admin_required, permission_required)
import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from urllib.parse import urlsplit

auth = Blueprint('auth', __name__, url_prefix='/auth')

year = datetime.date.today().year

@auth.before_app_request
def before_request():
    if current_user.is_authenticated:
        current_user.ping()
        if not current_user.confirmed \
                and request.endpoint \
                and request.blueprint != 'auth' \
                and request.endpoint != 'static':
            return redirect(url_for('auth.unconfirmed_account'))

@auth.route("/sign-up", methods=["GET", "POST"])
def sign_up():
    if current_user.is_authenticated:
        return redirect(url_for("views.index"))
    form = SignUpForm()
    if form.validate_on_submit():
        hash_password = bcrypt.generate_password_hash(form.password.data).decode("utf-8")
        user = Users(username=form.username.data, 
                     email=form.email.data, 
                     password=hash_password,
                     location=form.location.data)
        gravatar_hash = user.generate_gravatar_hash()
        user.gravatar_hash = gravatar_hash
        if form.profile_picture.data:
            picture_name = save_image(form.profile_picture.data)
            user.profile_picture = picture_name
        db.session.add(user)
        db.session.commit()
        
        # token = user.generate_account_verification_token()
        # send_email(user.email, 'Confirm Your Account', 'mail/confirm_account', user=user, token=token)
        
        # if current_app.config['FLASKY_ADMIN']:
        #     send_email(current_app.config['FLASKY_ADMIN'], 'New User', 'mail/to_admin')
        
        flash(f'A confirmation email has been sent to you by {form.email.data}!', 'success')
        return redirect(url_for('main.home'))
    return render_template('auth/signup.html', form=form, year=year)

@auth.route("/confirm-account/<token>", methods=["GET", "POST"])
@login_required
def confirm_account(token):
    if current_user.confirmed:
        return redirect(url_for('main.home'))
    if current_user.account_verification_token_confirmed(token):   
        db.session.commit()     
        flash('You have confirmed your account. Thanks!', "success")
        # send_email()
    else:
        flash('The confirmation link is invalid or has expired.')
    return redirect(url_for('main.home'))

@auth.route('/unconfirmed-account')
def unconfirmed_account():
    if current_user.is_anonymous or current_user.confirmed:
        return redirect(url_for('main.home'))
    return render_template('auth/unconfirmed_account.html', year=year)

@auth.route('/confirm-account')
@login_required
def resend_account_confirmation():
    # token = current_user.generate_account_verification_token()
    # send_email(current_user.email, 'Confirm Your Account',
    #            'mail/confirm_account', user=current_user, token=token)
    flash(f'A new confirmation email has been sent to you by {current_user.email}.')
    return redirect(url_for('main.home'))

@auth.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main.home"))
    form = LoginForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(email=form.email.data).first()
        if user is None or not bcrypt.check_password_hash(user.password, form.password.data):
            flash("Login unsuccessful. Please check email and password", "danger")
            return redirect(url_for("auth.login"))
        login_user(user, remember=form.remember.data)
        flash("Logged in successfully!", "success")
        next_page = request.form.get('next')
        # if next_page is None or next_page.startswith('/'):
        if not next_page or urlsplit(next_page).netloc != '':
            next_page = url_for('main.home')
        return redirect(next_page)
    return render_template("auth/login.html", form=form, year=year)

@auth.route('/user/<username>', methods=['GET', 'POST'])
def profile(username):
    page = request.args.get("page", default=1, type=int)
    user = Users.query.filter_by(username = username).first_or_404()
    if user is None:
        abort(404)
    user_posts = Post.query.filter_by(author = user).order_by(Post.date.desc()).paginate(page=page, error_out=False, per_page=current_app.config['FLASKY_POSTS_PER_PAGE']) 
    # date_str = user.last_seen
    # date_format = '%Y-%m-%d %H:%M:%S.%f'
    # date_obj = datetime.datetime.strptime(date_str, date_format)
    # time = date_obj    
    return render_template('auth/profile.html', user=user, 
                           time=user.last_seen, posts=user_posts, year=year)

@auth.route('/profile/edit-profile', methods=['GET', 'POST'])
@login_required
def edit():
    form = UpdateProfileForm()
    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.email = form.email.data
        gravatar_hash = current_user.generate_gravatar_hash()
        current_user.gravatar_hash = gravatar_hash
        if form.profile_picture.data:
            picture_name = save_image(form.profile_picture.data)
            current_user.profile_picture = picture_name
        db.session.commit()
        flash("Account updated", "success")
        return redirect(url_for("auth.profile", username=current_user.username))
    form.username.data = current_user.username
    form.email.data = current_user.email
    return render_template('auth/edit_profile.html', form=form, year=year)

@auth.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("main.home"))

@auth.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        new_password = bcrypt.generate_password_hash(form.new_password.data).decode("utf-8")
        current_user.password = new_password
        db.session.commit()
        flash("Your password has been changed.", "success")
        return redirect(url_for("auth.profile", username=current_user.username))        
    return render_template('auth/change_password.html', form=form, year=year)

@auth.route('/request-password-reset', methods=['GET', 'POST'])
def request_password_reset():
    form = RequestPasswordResetForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(email=form.email.data).first()
        if user:
            pass
            # token = generate_password_reset_token(user.id, user.email, user.password)
            # send_email(form.email.data, 'Password Reset', 'mail/password_reset', user=user, token=token)
        flash("A message has been sent to your email with instructions on how to reset your password.", "info")
        return redirect(url_for('main.home'))
    return render_template('auth/request_password_reset.html', form=form, year=year)

@auth.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    form = ResetPasswordForm()
    if form.validate_on_submit():
        token_email = confirm_password_reset_token(token['email'])
        token_password = confirm_password_reset_token(token['password'])
        user = Users.query.filter_by(email=token_email).first_or_404()
        if user:
            if user.email == token_email and user.password == token_password:
                user.password = bcrypt.generate_password_hash(form.password.data)
                db.session.commit()
                flash('You have successfully reset your password', 'success')
                # send_mail()
                return redirect(url_for('auth.login'))
        flash('The confirmation link is invalid or expired', 'danger')
        return redirect(url_for('auth.profile'))
    return render_template('auth/reset_password.html', form=form, year=year)
        
@auth.route('/admin/edit-profile/<int:id>', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_edit_profile(id):
    user = Users.query.get_or_404(id)
    form = EditProfileAdminForm(user=user)
    if form.validate_on_submit():
        user.username = form.username.data
        user.email = form.email.data
        user.confirmed = form.confirmed.data
        user.role = Role.query.get(form.role.data)
        user.location = form.location.data
        user.about_me = form.about_me.data
        db.session.add(user)
        db.session.commit()
        flash('The profile has been updated.', 'success')
        return redirect(url_for('.profile', username=user.username))
    form.username.data = user.username
    form.email.data = user.email
    form.confirmed.data = user.confirmed
    form.role.data = user.role_id
    form.location.data = user.location
    form.about_me.data = user.about_me
    return render_template('auth/admin_edit_profile.html', form=form, user=user)

            