from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_bcrypt import Bcrypt
from flask_mail import Mail
from flask_migrate import Migrate
from flask_ckeditor import CKEditor
from flask_moment import Moment
from flask_bootstrap import Bootstrap
from flask_pagedown import PageDown

db = SQLAlchemy()
login_manager = LoginManager()
bcrypt = Bcrypt()
mail = Mail()
migrate = Migrate()
ckeditor = CKEditor()
moment = Moment()
bootstrap = Bootstrap()
pagedown = PageDown()