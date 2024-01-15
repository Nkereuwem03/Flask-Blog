from flask import (Blueprint, render_template, request, flash, current_app,
                   redirect, url_for, make_response)
import datetime
from flask_mail import Message
from dotenv import load_dotenv
import os
from Blog.extensions import db, mail
from Blog.models import Post, Permission, Comments
from flask_login import current_user, login_required
from Blog.auth.utils import permission_required

load_dotenv('.env')

main = Blueprint('main', __name__, url_prefix='/')

year = datetime.date.today().year

@main.route('/all')
@login_required
def show_all():
    resp = make_response(redirect(url_for('main.home')))
    resp.set_cookie('show_followed', '', max_age=30*24*60*60) # 30 days
    return resp

@main.route('/followed')
@login_required
def show_followed():
    resp = make_response(redirect(url_for('main.home')))
    resp.set_cookie('show_followed', '1', max_age=30*24*60*60) # 30 days
    return resp

@main.route("/")
def home():
    show_followed = False
    if current_user.is_authenticated:
        show_followed = bool(request.cookies.get('show_followed', ''))
    if show_followed:
        query = current_user.followed_posts
    else:
        query = Post.query
    page = request.args.get("page", default=1, type=int)
    all_posts = query.order_by(Post.date.desc()).paginate(page=page, error_out=False, per_page=current_app.config['FLASKY_POSTS_PER_PAGE'],)
    return render_template('main/index.html', posts=all_posts,
                           show_followed=show_followed, year=year)
        
@main.route("/about")
def about():
    return render_template("main/about.html", year=year)

@main.route("/contact", methods=['GET', 'POST'])
def contact():
    if request.method == "POST":
        name = request.form.get('name')
        email = request.form.get('email')
        phone = request.form.get('phone')
        message = request.form.get('message')
        
        msg = Message(f'Mesage from your webssite. phone {phone}', sender=email, recipients=[{os.environ.get('MAIL_USERNAME')}])
        msg.body = message
        mail.send(msg.body)
        
        flash("Message sent successfully", "success")
        return render_template("main/contact.html", 'success', year=year)
        
    return render_template("main/contact.html", year=year)

@main.route("/moderate", methods=['GET', 'POST'])
@login_required
@permission_required(Permission.MODERATE)
def moderate():
    page = request.args.get('page', default=1, type=int)
    pagination = Comments.query.order_by(Comments.time.desc()).paginate(page=page, per_page=20, error_out=False)
    return render_template("main/moderate.html", comments=pagination, year=year)

@main.route("/moderate/enable/<int:comment_id>", methods=['GET', 'POST'])
@login_required
@permission_required(Permission.MODERATE)
def moderate_enable(comment_id):
    comment = Comments.query.filter_by(id=comment_id).first()
    comment.disabled = False
    db.session.commit()
    return redirect(url_for('main.moderate', page=request.args.get('page', 1, type=int)))

@main.route("/moderate/disable/<int:comment_id>", methods=['GET', 'POST'])
@login_required
@permission_required(Permission.MODERATE)
def moderate_disable(comment_id):
    comment = Comments.query.filter_by(id=comment_id).first()
    comment.disabled = True
    db.session.commit()
    return redirect(url_for('main.moderate', page=request.args.get('page', 1, type=int)))