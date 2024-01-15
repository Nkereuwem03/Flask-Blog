from random import randint
from sqlalchemy.exc import IntegrityError
from faker import Faker
from Blog.extensions import db, bcrypt
from Blog.models import Users, Post
import hashlib

def gravatar_hash(email):
    return hashlib.md5(email.lower().encode('utf-8')).hexdigest()

def users(count=100):
    fake = Faker()
    i = 0
    while i < count:
        u = Users(
            email=fake.email(),
            username=fake.user_name(),
            password=bcrypt.generate_password_hash('a').decode("utf-8"),
            profile_picture='default.jpg',
            confirmed=True,
            location=fake.city(),
            about_me=fake.text(),
            member_since=fake.past_date()
            )
        # gravatar_hash = u.generate_gravatar_hash()
        # u.gravatar_hash = gravatar_hash
        gravatar_hash=hashlib.md5(u.email.lower().encode('utf-8')).hexdigest()
        u.gravatar_hash=gravatar_hash
        db.session.add(u)
        try:
            db.session.commit()
            i += 1
        except IntegrityError:
            db.session.rollback()
        
def posts(count=100):
    fake = Faker()
    user_count = Users.query.count()
    for i in range(count):
        u = Users.query.offset(randint(0, user_count - 1)).first()
        p = Post(
            title=fake.text(),
            subtitle=fake.text(),
            img_url='https://www.image.com',
            body=fake.text(),
            date=fake.past_date(),
            author=u
            )
        db.session.add(p)
    db.session.commit()
