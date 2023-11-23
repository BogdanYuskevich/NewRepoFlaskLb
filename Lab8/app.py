import re
from flask import Flask, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_migrate import Migrate
from flask_wtf import FlaskForm
from werkzeug.security import check_password_hash, generate_password_hash
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Email


app = Flask(__name__)
app.config['SECRET_KEY'] = 'Hello'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'  # SQLite database file
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'



class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)



class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Register')

    def validate_email(self, email):
        email_pattern = re.compile(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$')
        if not email_pattern.match(email.data):
            return False
        return True

    def validate_username(self, username):
        username_pattern = re.compile(r'^[a-z0-9.]+$')
        if not username_pattern.match(username.data):
            return False
        return True


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')


@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('account'))
    else:
        return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        existing_user = User.query.filter_by(username=form.username.data).first()
        if existing_user:
            flash('User with this username already exists. Please choose a different username.', 'danger')
        else:
            existing_email = User.query.filter_by(email=form.email.data).first()
            if existing_email:
                flash('User with this email already exists. Please use a different email address.', 'danger')
            else:
                if not form.validate_username(form.username):
                    flash('Username can only contain lowercase letters, numbers, and dots.', 'danger')
                else:
                    if not form.validate_email(form.email):
                        flash('Please enter a valid email address.', 'danger')
                    else:
                        hashed_password = generate_password_hash(form.password.data)
                        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
                        db.session.add(new_user)
                        db.session.commit()
                        flash('Registration successful. You can now log in.', 'success')
                        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            return redirect(url_for('index'))
        else:
            flash('Login unsuccessful. Please check email and password.', 'danger')
    return render_template('login.html', title='Login', form=form)


@app.route('/account')
@login_required
def account():
    return render_template('account.html', title='Account')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))



@login_manager.user_loader
def user_loader(user_id):
    return User.query.get(int(user_id))


if __name__ == '__main__':
    app.run(debug=True)
