from flask import render_template, url_for, flash, redirect, request, jsonify, abort
from app import app, mysql, bcrypt
from app.forms import RegistrationForm, LoginForm, RequestResetForm, ResetPasswordForm, ChangePasswordForm, AddUserForm
from app.models import User
from flask_login import login_user, current_user, logout_user, login_required
import hashlib
from app.decorators import superadmin_required

@app.route("/")
@app.route("/home")
def home():
    return render_template('home.html')

@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        User.create(form.username.data, form.email.data, form.password.data)
        flash('Your account has been created! You can now log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.get_by_email(form.email.data)
        if user and User.verify_password(user.password, form.password.data):
            login_user(user, remember=True)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route("/reset_password", methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RequestResetForm()
    if form.validate_on_submit():
        flash('An email has been sent with instructions to reset your password.', 'info')
        return redirect(url_for('login'))
    return render_template('reset_request.html', title='Reset Password', form=form)

@app.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    user = User.verify_reset_token(token)
    if user is None:
        flash('That is an invalid or expired token', 'warning')
        return redirect(url_for('reset_request'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = hashlib.md5(form.password.data.encode()).hexdigest()
        user.password = hashed_password
        mysql.connection.commit()
        flash('Your password has been updated! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('reset_password.html', title='Reset Password', form=form)

@app.route("/account", methods=['GET', 'POST'])
@login_required
def account():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if User.verify_password(current_user.password, form.old_password.data):
            hashed_password = hashlib.md5(form.new_password.data.encode()).hexdigest()
            current_user.password = hashed_password
            mysql.connection.commit()
            flash('Your password has been changed!', 'success')
            return redirect(url_for('account'))
        else:
            flash('Old password is incorrect', 'danger')
    return render_template('account.html', title='Account', form=form)

@app.route("/add_user", methods=['GET', 'POST'])
@superadmin_required
def add_user():
    form = AddUserForm()
    if form.validate_on_submit():
        hashed_password = hashlib.md5(form.password.data.encode()).hexdigest()
        User.create(
            username=form.username.data.strip(),
            email=form.email.data.strip(),
            password=hashed_password,
            user_type=form.user_type.data
        )
        flash('User has been created!', 'success')
        return redirect(url_for('list_users'))
    return render_template('add_user.html', title='Add User', form=form)

@app.route("/list_users")
@superadmin_required
def list_users():
    return render_template('list_users.html')

@app.route("/api/users")
@superadmin_required
def api_users():
    users = User.query.filter_by(is_delete='N').all()
    user_data = [{
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'phone': user.phone,
        'user_type': user.user_type,
        'is_enable': user.is_enable
    } for user in users]
    return jsonify(user_data)

@app.route("/toggle_user/<int:user_id>", methods=['POST'])
@superadmin_required
def toggle_user(user_id):
    user = User.query.get(user_id)
    if user.is_enable == 'Y':
        user.is_enable = 'N'
    else:
        user.is_enable = 'Y'
    mysql.session.commit()
    return jsonify(success=True)

@app.route("/delete_user/<int:user_id>", methods=['POST'])
@superadmin_required
def delete_user(user_id):
    user = User.query.get(user_id)
    user.is_delete = 'Y'
    mysql.session.commit()
    return jsonify(success=True)
