from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, TextAreaField
from wtforms.validators import DataRequired

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'ASFDSADFSAGDFSG'
db = SQLAlchemy(app)


class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.Text, nullable=False)
    comment = db.Column(db.Text, nullable=False)


class FeedbackForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    comment = TextAreaField('Feedback', validators=[DataRequired()])


@app.route('/', methods=['GET', 'POST'])
def index():
    form = FeedbackForm()
    if form.validate_on_submit():
        name = form.name.data
        comment = form.comment.data

        feedback = Feedback(name=name, comment=comment)
        db.session.add(feedback)
        db.session.commit()

        return redirect(url_for('index'))

    feedbacks = Feedback.query.all()
    return render_template('feedback_form.html', form=form, feedbacks=feedbacks)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
