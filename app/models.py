import hashlib
from flask_login import UserMixin
from app import mysql, login_manager, bcrypt

class User(UserMixin):
    def __init__(self, id, username, email, password, user_type='user', is_enable='Y', is_delete='N'):
        self.id = id
        self.username = username
        self.email = email
        self.password = password
        self.user_type = user_type
        self.is_enable = is_enable
        self.is_delete = is_delete

    @staticmethod
    def create(username, email, password, user_type='user'):
        username = username.strip()
        hashed_password = hashlib.md5(password.encode()).hexdigest()
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO users (username, email, password, user_type) VALUES (%s, %s, %s, %s)", (username, email, hashed_password, user_type))
        mysql.connection.commit()
        cur.close()

    @staticmethod
    def get_by_id(user_id):
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        user_data = cur.fetchone()
        cur.close()
        if user_data:
            return User(user_data['id'], user_data['username'], user_data['email'], user_data['password'], user_data['user_type'], user_data['is_enable'], user_data['is_delete'])
        return None

    @staticmethod
    def get_by_email(email):
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        user_data = cur.fetchone()
        cur.close()
        if user_data:
            return User(user_data['id'], user_data['username'], user_data['email'], user_data['password'], user_data['user_type'], user_data['is_enable'], user_data['is_delete'])
        return None


    @staticmethod
    def create(username, email, password):
        username = username.strip()
        hashed_password = hashlib.md5(password.encode()).hexdigest()
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO users (username, email, password) VALUES (%s, %s, %s)", (username, email, hashed_password))
        mysql.connection.commit()
        cur.close()

    def verify_password(stored_password, provided_password):
        return stored_password == hashlib.md5(provided_password.encode()).hexdigest()


@login_manager.user_loader
def load_user(user_id):
    return User.get_by_id(user_id)
