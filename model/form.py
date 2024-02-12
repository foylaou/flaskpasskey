import wtforms
from flask_wtf import FlaskForm
from wtforms.validators import InputRequired


# 設定登入表單
class LoginForm(FlaskForm):
    username = wtforms.StringField("使用者名稱", validators=[InputRequired()])
    password = wtforms.PasswordField("密碼", validators=[InputRequired()])


# 設定註冊表單
class RegisterForm(FlaskForm):
    username = wtforms.StringField("使用者名稱", validators=[InputRequired()])
    email = wtforms.EmailField("電子郵件", validators=[InputRequired()])
    password = wtforms.PasswordField("密碼", validators=[InputRequired()])