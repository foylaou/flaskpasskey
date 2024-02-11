# 導入必要的套件
import codecs
import wtforms
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, current_user, login_required, LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm, CSRFProtect
from passlib.hash import pbkdf2_sha256
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms.validators import InputRequired

# 設定應用程式
app = Flask(__name__)
app.config['SECRET_KEY'] = '1416519848949'  # 確保設置了秘密鑰匙

# 初始化 Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
csrf = CSRFProtect(app)


# 定義用戶加載函數
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# 設定應用程式


# 設定資料庫
app.config["SQLALCHEMY_DATABASE_URI"] = "mysql+pymysql://av2288444:@t0955787053S@<host>/<dbname>"

db = SQLAlchemy(app)


# 設定使用者模型
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    passkey = db.Column(db.String(120), nullable=False)


# 設定登入表單
class LoginForm(FlaskForm):
    username = wtforms.StringField("使用者名稱", validators=[InputRequired()])
    password = wtforms.PasswordField("密碼", validators=[InputRequired()])


# 設定註冊表單
class RegisterForm(FlaskForm):
    username = wtforms.StringField("使用者名稱", validators=[InputRequired()])
    email = wtforms.EmailField("電子郵件", validators=[InputRequired()])
    password = wtforms.PasswordField("密碼", validators=[InputRequired()])


# 設定登入路由
@app.route("/")
def index():
    """
    首頁路由
    如果使用者已登入，則導向首頁
    否則導向登入頁面
    """
    if current_user.is_authenticated:
        return render_template("index.html")
    else:
        return redirect(url_for("login"))


# 設定登入路由
@app.route("/login", methods=["GET", "POST"])
def login():
    """
    登入路由

    如果使用者已登入，則導向首頁
    否則顯示登入表單
    """
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    form = LoginForm()
    if form.validate_on_submit():
        """
        驗證表單資料
        如果驗證成功，則登入使用者並導向首頁
        否則顯示錯誤訊息
        """
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for("index"))

        flash("登入失敗")
    return render_template("login.html", form=form)


# 設定註冊路由
@app.route("/register", methods=["GET", "POST"])
def register():
    """
    註冊路由

    如果使用者已登入，則導向首頁
    否則顯示註冊表單
    """
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    form = RegisterForm()
    if form.validate_on_submit():
        """
        驗證表單資料
        如果驗證成功，則註冊使用者並導向登入頁面
        否則顯示錯誤訊息
        """
        user = User(username=form.username.data, email=form.email.data,
                    password=generate_password_hash(form.password.data), passkey=generate_passkey())
        db.session.add(user)
        db.session.commit()
        flash("註冊成功")
        return redirect(url_for("login"))

    return render_template("register.html", form=form)


# 生成 Passkey
def generate_passkey():
    """
    生成 Passkey

    使用 pbkdf2_sha256 函數生成 Passkey
    """
    return pbkdf2_sha256.hash("12345")


# 驗證 Passkey
def verify_passkey(passkey, user):
    """
    驗證 Passkey

    使用 pbkdf2_sha256 函數驗證 Passkey
    """
    return pbkdf2_sha256.verify(passkey, user.passkey)


# 設定 Passkey 路由
@app.route("/passkey", methods=["GET", "POST"])
def passkey():
    """
    Passkey 路由

    如果使用者已登入，則顯示 Passkey 輸入頁面
    否則導向登入頁面
    """
    if current_user.is_authenticated:
        if request.method == "GET":
            return render_template("passkey.html")
        else:
            passkey = request.form["passkey"]
            if verify_passkey(passkey, current_user):
                flash("Passkey 驗證成功")
                return redirect(url_for("index"))
            else:
                flash("Passkey 驗證失敗")
                return render_template("passkey.html")
    else:
        return redirect(url_for("login"))


# 啟動應用程式
if __name__ == "__main__":
    app.run(debug=True)
