import secrets
import os
from dotenv import load_dotenv

load_dotenv('.env')

SECRET = secrets.token_hex(16)

SQLALCHEMY_DATABASE_URI = f"postgresql://{os.environ.get('DB_USER')}:{os.environ.get('DB_PASSWORD')}@{os.environ.get('DB_HOST')}:{os.environ.get('DB_PORT')}/{os.environ.get('DB_NAME')}"
    
class Config():
    SECRET_KEY = SECRET
    SECURITY_PASSWORD_SALT = "password_salt"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ECHO = False
    DEVELOPMENT = True                                                                                                  
    # CKEDITOR_SERVE_LOCAL = True
    MAIL_SERVER = 'smtp.googlemail.com'
    MAIL_PORT = 587
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    MAIL_USE_TLS = True
    # MAIL_USE_SSL = True
    # FLASKY_ADMIN = 'nkereuwem.udoudo1@gmail.com'
    FLASKY_ADMIN = os.environ.get('MAIL_USERNAME')
    FLASKY_MAIL_SUBJECT_PREFIX = 'Nkereuwem_BLOG -'
    FLASKY_MAIL_SENDER = 'Flasky Admin <flasky@example.com>'
    FLASKY_POSTS_PER_PAGE = 4
    FLASKY_COMMENTS_PER_PAGE = 20
    
    @staticmethod
    def init_app(app):
        pass
    
class Production():
    DEVELOPMENT = False
    DEBUG = False
                
class DevelopmentConfig(Config):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = SQLALCHEMY_DATABASE_URI

class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = SQLALCHEMY_DATABASE_URI

class ProductionConfig(Config):
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or SQLALCHEMY_DATABASE_URI
 
config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
