import os

class Config:
    SECRET_KEY = 'secret'
    MYSQL_HOST = 'localhost'
    MYSQL_USER = 'flaskuser'
    MYSQL_PASSWORD = 'password123'
    MYSQL_DB = 'flask_auth_db'
    MYSQL_CURSORCLASS = 'DictCursor'
