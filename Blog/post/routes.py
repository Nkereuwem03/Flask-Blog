from flask import Blueprint, render_template, request, flash, redirect, url_for, abort, current_app
import datetime
from Blog.post.forms import CreatePostForm
from flask_login import login_required, current_user
from Blog.models import Post, Comments
from Blog.extensions import db
from Blog.post.forms import CommentForm

year = datetime.date.today().year

post = Blueprint("post", __name__, url_prefix="/post")

@post.route("/create_post", methods=['GET', 'POST'])
@login_required
def create():
    form = CreatePostForm()
    if form.validate_on_submit():
        post = Post(title=form.title.data, 
                    subtitle=form.subtitle.data, 
                    body=form.body.data,
                    img_url = form.img_url.data,
                    # author=current_user._get_current_object(),
                    author=current_user)
        db.session.add(post)
        db.session.commit()
        flash("Your post has been created", "success")
        return redirect(url_for("main.home"))
    return render_template('post/create_post.html', form=form, year=year)

@post.route('/<int:post_id>', methods=["GET", "POST"])
def post_by_id(post_id):
    form = CommentForm()
    per_page = current_app.config['FLASKY_COMMENTS_PER_PAGE']
    
    post = Post.query.filter_by(id=post_id).first_or_404()
    total_comments = len(post.comment)

    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login or register to comment", 'info')
            return redirect(url_for("auth.login"))
        comment = Comments(body=form.body.data,
                           comment_user=current_user,
                           post=post)
        db.session.add(comment)
        db.session.commit()
        form.body.data = None
        return redirect(url_for('post.post_by_id', post_id=post.id, page=-1))
    
    page = request.args.get('page', default=1, type=int)
    if page == -1:
        page = (total_comments - 1) // per_page + 1
    pagination = Comments.query.order_by(Comments.time.asc()).paginate(page=page, per_page=per_page, error_out=False)
    form.body.data = None
    return render_template("post/post.html", post=post, form=form, post_comments=pagination, year=year)

@post.route('/edit-post/<int:post_id>', methods=["GET", "POST"])
@login_required
def edit_post(post_id):
    post = Post.query.filter_by(id=post_id).first_or_404()
    # post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)
    form = CreatePostForm()
    if form.validate_on_submit():
        post.title = form.title.data
        post.subtitle = form.subtitle.data
        post.body = form.body.data
        post.img_url = form.img_url.data
        post.author = current_user
        db.session.commit()
        flash("Your post has been updated", "success")
        return redirect(url_for("post.post_by_id", post_id=post.id))
    if request.method == "GET":
        form.title.data = post.title
        form.subtitle.data = post.subtitle
        form.body.data = post.body
        form.img_url.data = post.img_url
    return render_template('post/edit_post.html', post=post, form=form, year=year)

@post.route('/delete-post/<int:post_id>', methods=["GET", "POST"])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)
    if post:
        db.session.delete(post)
        db.session.commit()
        return redirect(url_for("main.home"))