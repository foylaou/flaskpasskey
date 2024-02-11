from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()


# 設定使用者模型

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(225), nullable=False)
    passkey = db.Column(db.String(225), nullable=False)
    def set_password(self, password):
        """創建密碼哈希"""
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        """驗證密碼"""
        return check_password_hash(self.password_hash, password)