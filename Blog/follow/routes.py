from flask import Blueprint, flash, redirect, url_for, request, render_template
from flask_login import login_required, current_user
from Blog.extensions import db
from Blog.models import Users, Permission
from Blog.auth.utils import permission_required
import datetime

follow = Blueprint("follow", __name__, url_prefix="/user")

year = datetime.date.today().year

@follow.route("/follow/<username>")
@login_required
@permission_required(Permission.FOLLOW)
def follows(username):
    user = Users.query.filter_by(username=username).first()
    if user is None:
        flash('Invalid user.')
        return redirect(url_for('main.home'))
    if current_user.is_following(user):
        flash('You are already following this user.')
        return redirect(url_for('auth.profile', username=username))
    current_user.follow(user)
    db.session.commit()
    flash(f'You are now following {username}')
    return redirect(url_for('auth.profile', username=username))

    
@follow.route("/unfollow/<username>")
@login_required
@permission_required(Permission.FOLLOW)
def unfollow(username):
    user = Users.query.filter_by(username=username).first()
    if user is None:
        flash('Invalid user.')
        return redirect(url_for('main.home'))
    current_user.unfollow(user)
    db.session.commit()
    flash(f'You unfollowed {username}')
    return redirect(url_for('auth.profile', username=username))
    
@follow.route("/followers/<username>")
def followers(username):
    user = Users.query.filter_by(username=username).first()
    if user is None:
        flash('Invalid user.')
        return redirect(url_for('.index'))
    page = request.args.get('page', default=1, type=int)
    pagination = user.followers.paginate(page=page, per_page=20, error_out=False)
    follows = [{'user': item.follower, 'timestamp': item.timestamp} for item in pagination.items]
    return render_template('follow/followers.html', user=user, title="Followers of", 
                           endpoint='.followers', pagination=pagination, follows=follows, year=year)
    
@follow.route("/following/<username>")
def following(username):
    user = Users.query.filter_by(username=username).first()
    if user is None:
        flash('Invalid user.')
        return redirect(url_for('.index'))
    page = request.args.get('page', default=1, type=int)
    pagination = user.followed.paginate(page=page, per_page=20, error_out=False)
    follows = [{'user': item.followed, 'timestamp': item.timestamp} for item in pagination.items]
    return render_template('follow/following.html', user=user, title="Followings", 
                           endpoint='.followers', pagination=pagination, follows=follows, year=year)

    