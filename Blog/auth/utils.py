from werkzeug.utils import secure_filename
from flask import current_app, render_template
import os
from flask_mail import Message
from Blog.extensions import mail
from threading import Thread
from itsdangerous import URLSafeTimedSerializer
import jwt
from datetime import datetime, timezone, timedelta
from functools import wraps
from flask import abort
from flask_login import current_user
from Blog.models import Permission

def save_image(profile_picture):
    picture_name = secure_filename(profile_picture.filename)
    picture_path = os.path.join(current_app.root_path, "static/images", picture_name)
    profile_picture.save(picture_path)
    return picture_name

# def send_async_email(app, msg):
#     with app.app_context():
#         mail.send(msg)

# def send_email(to, subject, template, **kwargs):
#     msg = Message(current_app.config['FLASKY_MAIL_SUBJECT_PREFIX'] + subject, 
#                   sender=current_app.config['FLASKY_MAIL_SENDER'], recipients=[to])
#     msg.body = render_template(template + '.txt', **kwargs)
#     msg.html = render_template(template + '.html', **kwargs)
#     thr = Thread(target=send_async_email, args=[current_app, msg])
#     thr.start()
#     return thr

def send_email(to, subject, template, **kwargs):
    msg = Message(current_app.config['FLASKY_MAIL_SUBJECT_PREFIX'] + subject,
    sender=current_app.config['FLASKY_MAIL_SENDER'], recipients=[to])
    msg.body = render_template(template + '.txt', **kwargs)
    msg.html = render_template(template + '.html', **kwargs)
    mail.send(msg)

def generate_password_reset_token(id, email, password):
    serializer = URLSafeTimedSerializer(secret_key='secretkey')
    token = serializer.dumps({'id': id, 'email': email, 'password': password}, salt='salt')
    return token
    
def confirm_password_reset_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(secret_key='secretkey')
    try:
        payload = serializer.loads(
            token,
            salt='salt',
            max_age=expiration
        )
    except:
        return False
    return payload

# def generate_password_reset_token(id, email, password, expiration=3600):
#     reset_token = jwt.encode(
#         {
#             "payload": {
#                 "id": id,
#                 "email": email,
#                 'password': password
#                 },
#             "exp": datetime.now(tz=timezone.utc) + timedelta(seconds=expiration)
#         },
#         "secret_key",
#         algorithm="HS256"
#     )
#     return reset_token

# def confirm_password_reset_token(token):
#     try:
#         data = jwt.decode(
#             token,
#             'secret_key',
#             leeway=timedelta(seconds=10),
#             algorithms=['HS256']
#         )
#     except:
#         return False
#     return data

def permission_required(permission):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.can(permission):
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def admin_required(f):
    return permission_required(Permission.ADMIN)(f)