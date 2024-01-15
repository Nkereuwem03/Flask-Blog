from Blog import create_app
from Blog.extensions import db
from Blog.models import Users, Post, Follow, Comments
# from flask_migrate import Migrate

app = create_app()
# migrate = Migrate(app, db)

if __name__ == "__main__":
    app.run()
