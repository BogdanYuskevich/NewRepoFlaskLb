from datetime import datetime
from email_validator import validate_email
from flask import Flask, render_template, flash, redirect, url_for
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from forms import RegistrationForm, LoginForm

app = Flask(__name__)
app.config.from_object('config')
db = SQLAlchemy(app)
migrate = Migrate(app, db)


# models
class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    photo_path = db.Column(db.String(255))
    registration_time = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"User(id={self.id}, username={self.username}, email={self.email}, photo_path={self.photo_path})"

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)


@app.route('/')
def home():
    return render_template('base.html')


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
                    if form.password.data != form.confirm_password.data:
                        flash('Password and confirmation do not match.', 'danger')
                    else:
                        if not form.validate_email(form.email):
                            flash('Please enter a valid email address.', 'danger')
                        else:
                            new_user = User(username=form.username.data, email=form.email.data, password_hash=generate_password_hash(form.password.data), registration_time=datetime.utcnow())
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
        if user and user.verify_password(form.password.data):
            flash('Login successful.', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid email or password. Please try again.', 'danger')
    return render_template('login.html', form=form)


@app.route('/users')
def user_list():
    users = User.query.all()
    return render_template('users.html', users=users)


if __name__ == '__main__':
    app.run(debug=True)
