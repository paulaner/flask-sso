from flask import Flask, flash, Response, redirect, render_template, session, url_for, request, abort
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
from tabledef import *
from itsdangerous import URLSafeTimedSerializer
import hashlib
from functools import wraps
from wtforms import Form, BooleanField, StringField, PasswordField, validators
from flask_principal import Principal, Identity, identity_changed, identity_loaded, AnonymousIdentity, Permission, Need, RoleNeed, ItemNeed
from werkzeug.contrib.cache import MemcachedCache

cache = MemcachedCache(['127.0.0.1:11211'])

app = Flask(__name__)

# load the extension
principals = Principal(app)

# Create a permission with a single Need, in this case a RoleNeed.
admin_permission = Permission(RoleNeed('admin'))

# Create a permission with a single Need, in this case a RoleNeed.
user_permission = Permission(RoleNeed('user'))

login_manager = LoginManager(app)
login_manager.init_app(app)
login_manager.session_protection = "strong"
login_manager.login_view = "login"


# APPLICATION # 


'''
DECORATORS
'''
@principals.identity_loader
def read_identity_from_flask_login():
    if current_user.is_authenticated:
        return Identity(current_user.role)
    return AnonymousIdentity()

@identity_loaded.connect_via(app)
def on_identity_loaded(sender, identity):
    if not isinstance(identity, AnonymousIdentity):
        identity.provides.add(RoleNeed(identity.id))

def requires_roles(*roles):
    def wrapper(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if get_current_user_role() not in roles:
                clean_up()
                return unauthorized()
            return f(*args, **kwargs)
        return wrapped
    return wrapper

def get_current_user_role():
    return current_user.role

def authorized_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' in session and session['logged_in'] and 'token' in session and session['token'] is not None:
            value = hashlib.md5(str(str(request.headers.get('User-Agent')) + request.remote_addr).encode('utf-8')).hexdigest()
            user = User.verify_auth_token(session['token'])           
            if user is not None and value == cache.get(session['token']):
                return f(*args, **kwargs)
            else:
                clean_up()
                abort(401)
        else:
            clean_up()
            return redirect(url_for('login'))
    return decorated_function


'''
HELPER METHODS/CLASSES
'''
def clean_up():
    if cache.get('token') is not None:
        cache.delete(session['token'])
    session['logged_in'] = False
    session.pop('token', None)
    session.pop('admin', None)
    session.clear()
    logout_user()

class RegistrationForm(Form):
    username = StringField('username', [validators.Length(min=4, max=25)])
    email = StringField('email', [validators.Length(min=6, max=35)])
    password = PasswordField('password', [
        validators.DataRequired(),
        validators.EqualTo('confirm_password', message='Passwords Must Match')
    ])
    confirm_password = PasswordField('confirm_password')


'''
ERROR HANDLERS
'''
@app.errorhandler(401)
def page_not_found(e):
    return render_template('fail.html')

@app.errorhandler(403)
def access_denied(e):
    return render_template('permission_denied.html', user = current_user)

@login_manager.unauthorized_handler
def unauthorized():
    return render_template('unauthorized.html')


'''
USER MANAGEMENT
'''
@app.route('/register', methods=['POST', 'GET'])
def register():
    form = RegistrationForm(request.form)
    if request.method == 'POST' and form.validate():
        
        existing_user = User.get_by_username(form.username.data)
        
        if existing_user is not None:
            return render_template('user_duplicate.html')

        username = form.username.data
        password = form.password.data
        email = form.email.data
        
        user = User(username,password,email,False,"user")
        engine = create_engine('sqlite:///tutorial.db', echo=True)
        Session = sessionmaker(bind=engine)
        sess = Session()

        sess.add(user)
        sess.commit()
        return render_template('register_success.html')
    return render_template('new_user.html', form=form)

@app.route('/new_user', methods=['POST', 'GET'])
def new_user():
    return render_template('new_user.html', form=None)

@app.route('/delete/<username>', methods=['POST', 'GET'])
@authorized_required
@login_required
def delete(username):
    user = User.delete(username)
    return list_users()

@app.route('/list_users', methods=['POST', 'GET'])
@login_required
@admin_permission.require(http_exception=403)
@authorized_required
def list_users():
    users = User.all()
    return render_template('list_users.html', users = users)


'''
LOGIN/LOGOUT METHODS/ROUTES
'''
@app.route("/logout")
@login_required
def logout():
    clean_up()
    return render_template('logout.html')

@login_manager.user_loader
def load_user(user_id):
    result = User.get(user_id)
    return result

@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        POST_USERNAME = str(request.form['username'])
        POST_PASSWORD = str(request.form['password'])

        result = User.get_by_username(POST_USERNAME)
        if result is None:
            clean_up()
            flash('User Name Not Found')
            abort(401)

        match = result.check_password(POST_PASSWORD)

        if match:
            login_user(result,remember=True)
            session['logged_in'] = True
            session['admin'] = result.admin
            session['token'] = result.generate_auth_token();

            value = hashlib.md5(str(str(request.headers.get('User-Agent')) + request.remote_addr).encode('utf-8')).hexdigest()
            cache.set(session['token'], value, timeout=5 * 60)
            return redirect(url_for('success'))
        else:
            clean_up()
            abort(401)
    else:
        if 'token' in session and session['token'] is not None:
            value = hashlib.md5(str(str(request.headers.get('User-Agent')) + request.remote_addr).encode('utf-8')).hexdigest()
            user = User.verify_auth_token(session['token'])
            
            if user is not None and value == cache.get(session['token']):
                return redirect(url_for('success'))
            else:
                clean_up()
                return render_template('login.html')
        
        clean_up()
        return render_template('login.html')


'''
ROUTES
'''
@app.route('/index')
@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/success', methods=['POST', 'GET'])
@login_required
@authorized_required
def success():
    return render_template('success.html', user = current_user)

@app.route('/content/<id>', methods=['POST', 'GET'])
@login_required
@admin_permission.require(http_exception=403)
@authorized_required
def show_content(id):
    if str(current_user.id) == str(id):
        return render_template('content.html', user = current_user)
    clean_up()
    abort(401)


if __name__ == "__main__":
    app.secret_key = "KEYYYYY"
    app.REMEMBER_COOKIE_DURATION = 5
    app.run(debug=True, host='0.0.0.0', port=4000)