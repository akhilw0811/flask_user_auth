from functools import wraps
from flask import abort
from flask_login import current_user

def superadmin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.user_type != 'superadmin':
            abort(403)
        return f(*args, **kwargs)
    return decorated_function
