import os
import tempfile
import wtforms
from flask import Flask, render_template, redirect, url_for, flash, request, session,send_file
from flask_login import login_user, current_user, LoginManager, logout_user
from flask_migrate import Migrate
from flask_wtf import FlaskForm, CSRFProtect
from flask_wtf.csrf import generate_csrf
from flask_wtf.file import FileRequired, FileField
from passlib.hash import pbkdf2_sha256
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from wtforms.validators import InputRequired
from model.connectedb import db, User  # 引入 db 實例
from model.textfix import *
from model.form import *

# 設定應用程式
app = Flask(__name__)
app.config['SECRET_KEY'] = '1416519848949'  # 確保設置了秘密鑰匙
UPLOAD_FOLDER = tempfile.mkdtemp()
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
# 初始化 Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
csrf = CSRFProtect(app)
# 設定資料庫
app.config["SQLALCHEMY_DATABASE_URI"] = "mysql+pymysql://av2288444:!t0955787053S@foynas.synology.me:3369/web"
db.init_app(app)
migrate = Migrate(app, db)
with app.app_context():
    db.create_all()


# 定義用戶加載函數
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

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
@app.route("/", methods=["GET"])
def index():
    """
    首頁路由
    如果使用者已登入，則導向首頁
    否則導向登入頁面
    """
    csrf_token = generate_csrf()
    if current_user.is_authenticated:
        return render_template('index.html', csrf_token=csrf_token)
    else:
        return redirect(url_for("login"))


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/upload', methods=['POST'])
def upload():
    flash('test')
    # 获取上传的文件
    uploaded_file = request.files['file']
    if uploaded_file is not None:
        filename = secure_filename(uploaded_file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        uploaded_file.save(file_path)  # 保存文件

        # 调用处理文件的函数
        processed_text = process_text(file_path)
        processed_text2 = process_text2(file_path)

        # 渲染结果页面并传递处理后的文本
        return render_template('result.html', text=processed_text, text2=processed_text2)
    else:
        flash('No file uploaded.')


# 設定登入路由
@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            session.permanent = True
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

@app.route('/download')
def download():
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], 'btunlock.mobileconfig')

    # 將處理後的文本保存到新的檔
    with open(file_path, 'w', encoding='utf-8') as file:
        file.write(request.args.get('text', ''))

    # 提供下載連結
    return send_file(file_path, as_attachment=True)


# 處理方式2：在網頁上顯示處理結果
@app.route('/download2')
def download2():
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], 'unlock.mobileconfig')

    # 將處理後的文本保存到新的檔
    with open(file_path, 'w', encoding='utf-8') as file:
        file.write(request.args.get('text', ''))

    # 提供下載連結
    return send_file(file_path, as_attachment=True)

@app.route('/email')
def email():
    # 在此處添加發送電子郵件的代碼
    # 可以使用Python的smtplib庫來發送電子郵件
    return "處理結果已發送到您的電子郵件。"

# 啟動應用程式
if __name__ == "__main__":
    app.run(debug=True)
