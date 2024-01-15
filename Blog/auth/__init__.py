from Blog.auth.routes import auth
from Blog.models import Permission

@auth.app_context_processor
def inject_permissions():
    return dict(Permission=Permission)
