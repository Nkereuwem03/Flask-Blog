from flask import Flask
from Blog.config import config
from Blog.extensions import (db, bcrypt, login_manager, 
                             mail, ckeditor, moment, bootstrap, 
                             migrate, pagedown)

def create_app():
    app = Flask(__name__)
    app.config.from_object(config['development'])
    db.init_app(app)
    bcrypt.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    login_manager.login_message_category = "info"
    mail.init_app(app)
    migrate.init_app(app, db)
    ckeditor.init_app(app)
    moment.init_app(app)
    bootstrap.init_app(app)
    pagedown.init_app(app)
      
    from Blog.post.routes import post
    from Blog.auth.routes import auth
    from Blog.main.routes import main
    from Blog.follow.routes import follow
    from Blog.errors.handlers import errors
    app.register_blueprint(auth)
    app.register_blueprint(post)
    app.register_blueprint(main)
    app.register_blueprint(follow)
    app.register_blueprint(errors)
    
    return app


