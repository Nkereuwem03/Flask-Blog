from datetime import datetime, date, timezone, timedelta
from flask_login import UserMixin, AnonymousUserMixin
from Blog.extensions import login_manager, db, bcrypt
import hashlib
import jwt
from flask import current_app, request, url_for
from sqlalchemy import event

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(user_id)

class Follow(db.Model): 
    __tablename__ = 'follows'
    follower_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    followed_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
class Users(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(), nullable=False, unique=True)
    email = db.Column(db.String(), nullable=False, unique=True)
    confirmed = db.Column(db.Boolean, default=False)
    password = db.Column(db.String(), nullable=False)
    profile_picture = db.Column(db.String(100), default="default.jpg")
    about_me = db.Column(db.Text())
    location = db.Column(db.String())
    member_since = db.Column(db.DateTime(), default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    gravatar_hash = db.Column(db.String(32))
         
    post = db.relationship("Post", backref="author", lazy=True)
    comment = db.relationship('Comments', backref="comment_user", lazy=True)
    followed = db.relationship('Follow', foreign_keys=[Follow.follower_id], 
                                backref=db.backref('follower', lazy='joined'), lazy='dynamic', 
                                cascade='all, delete-orphan')
    followers = db.relationship('Follow', foreign_keys=[Follow.followed_id], 
                                backref=db.backref('followed', lazy='joined'), lazy='dynamic', 
                                cascade='all, delete-orphan')
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))

    def __repr__(self):
        return f'<User {self.username}>'
    
    def __init__(self, **kwargs):
        super(Users, self).__init__(**kwargs)
        if self.role is None:
            if self.email == current_app.config['FLASKY_ADMIN']:
                self.role = Role.query.filter_by(name='Administrator').first()
            if self.role is None:
                self.role = Role.query.filter_by(default=True).first()
        if self.email is not None and self.gravatar_hash is None:
            self.gravatar_hash = self.generate_gravatar_hash()
        self.follow(self)
        
    # def __init__(self, username, password):
    #     self.username = username
    #     self.password = bcrypt.generate_password_hash(password).decode('utf-8')
    
    @staticmethod
    def add_self_follows():
        for user in Users.query.all():
            if not user.is_following(user):
                user.follow(user)
                db.session.add(user)
                db.session.commit()

    def avatar(self, size):
        digest = hashlib.md5(self.email.lower().encode('utf-8')).hexdigest()
        return f'https://www.gravatar.com/avatar/{digest}?d=identicon&s={size}'
    
    def follow(self, user):
        if not self.is_following(user):
            f = Follow(follower=self, followed=user)
            db.session.add(f)
            
    def unfollow(self, user):
        f = self.followed.filter_by(followed_id=user.id).first()
        if f:
            db.session.delete(f)
        
    def is_following(self, user):
        if user.id is None:
            return False
        return self.followed.filter_by(followed_id=user.id).first() is not None
    
    def is_followed_by(self, user):
        if user.id is None:
            return False
        return self.followers.filter_by(follower_id=user.id).first() is not None
    
    def generate_account_verification_token(self, expiration=3600):
        reset_token = jwt.encode(
            {
                "confirm": self.email,
                "exp": datetime.now(tz=timezone.utc) + timedelta(seconds=expiration)
            },
            current_app.config['SECRET_KEY'],
            algorithm="HS256"
        )
        return reset_token

    def account_verification_token_confirmed(self, token):
        try:
            data = jwt.decode(
                token,
                current_app.config['SECRET_KEY'],
                leeway=timedelta(seconds=10),
                algorithms=['HS256']
            )
        except:
            return False
        if data.get('confirm') != self.email:
            return False
        self.confirmed = True
        db.session.add(self)
        return True

    def can(self, perm):
        return self.role is not None and self.role.has_permission(perm)
 
    def is_administrator(self):
        return self.can(Permission.ADMIN)
    
    def ping(self):
        self.last_seen = datetime.utcnow()
        db.session.add(self)
        db.session.commit()
     
    def generate_gravatar_hash(self):
        # email = self.email.lower().encode('utf-8')
        # hash_value = hashlib.md5(email).hexdigest()
        # gravatar_hash = hash_value
        # return gravatar_hash
        return hashlib.md5(self.email.lower().encode('utf-8')).hexdigest()
         
    def gravatar(self, size=100, default='identicon', rating='g'):
        if request.is_secure:
            url = 'https://secure.gravatar.com/avatar'
        else:
            url = 'http://www.gravatar.com/avatar'
        hash = self.gravatar_hash or self.generate_gravatar_hash()
        return '{url}/{hash}?s={size}&d={default}&r={rating}'.format(url=url, hash=hash, size=size, default=default, rating=rating)
    
    @property
    def followed_posts(self):
        return Post.query.join(Follow, Follow.followed_id == Post.user_id).filter(Follow.follower_id == self.id)

def check_email_change(target, value, oldvalue, initiator):
    if value != oldvalue:
        target.gravatar_hash = target.generate_gravatar_hash
        print(f"Target: {target}")
        print(f"New Value: {value}")
        print(f"Old Value: {oldvalue}")
        print(f"Initiator: {initiator}")
        
event.listen(Users.email, 'set', check_email_change)
    
class AnonymousUser(AnonymousUserMixin):
    def can(self, permissions):
        return False
 
    def is_administrator(self):
        return False

login_manager.anonymous_user = AnonymousUser

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(), nullable=False)
    subtitle = db.Column(db.String(), nullable=False)
    date = db.Column(db.DateTime, index=True, nullable=False, default=date.today().strftime("%B %d, %Y"))
    # time = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    comment = db.relationship("Comments", backref="post", lazy=True, cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Post: ({self.title})>"
    
    def to_json(self):
        json_post = {
            'url': url_for('api.get_post', id=self.id),
            'title': self.title,
            'sub_title': self.sub_title,
            'date_created': self.date,
            'body': self.body,
            'img_url':self.img_url,
            'author_url': url_for('api.get_user', id=self.user_id),
            'comments_url': url_for('api.get_post_comments', id=self.id),
            'comment_count': self.comments.count()
        }
        return json_post

class Comments(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text, nullable=False)
    time = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    disabled = db.Column(db.Boolean)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey("post.id"), nullable=False)

    def __repr__(self):
        return f"<Comments: ({self.body})>"
    
class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    default = db.Column(db.Boolean, default=False, index=True)
    permissions = db.Column(db.Integer)
    users = db.relationship('Users', backref='role', lazy='dynamic')
    
    def __init__(self, **kwargs):
        super(Role, self).__init__(**kwargs)
        if self.permissions is None:
            self.permissions = 0
            
    def has_permission(self, perm):
        return self.permissions & perm == perm
    def add_permission(self, perm):
        if not self.has_permission(perm):
            self.permissions += perm
    def remove_permission(self, perm):
        if self.has_permission(perm):
            self.permissions -= perm
    def reset_permissions(self):
        self.permissions = 0
    
    @staticmethod
    def insert_roles():
        roles = {
            'User': [Permission.FOLLOW, Permission.COMMENT, Permission.WRITE],
            'Moderator': [Permission.FOLLOW, Permission.COMMENT, Permission.WRITE, Permission.MODERATE],
            'Administrator': [Permission.FOLLOW, Permission.COMMENT, Permission.WRITE, Permission.MODERATE, Permission.ADMIN],
            }
        default_role = 'User'
        for r in roles:
            role = Role.query.filter_by(name=r).first()
            if role is None:
                role = Role(name=r)
            role.reset_permissions()
            for perm in roles[r]:
                role.add_permission(perm)
            role.default = (role.name == default_role)
            db.session.add(role)
        db.session.commit()
    
class Permission:
    FOLLOW = 1
    COMMENT = 2
    WRITE = 4
    MODERATE = 8
    ADMIN = 16
    
    