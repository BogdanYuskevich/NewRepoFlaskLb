from flask import Flask, render_template, request
import platform
import datetime

app = Flask(__name__)


def get_os_info():
    return str(platform.system() + " " + platform.release() + " " + platform.version())


def get_current_time():
    now = datetime.datetime.now()
    return now.strftime("%Y-%m-%d %H:%M:%S")


@app.route('/')
def home():
    page_title = "Main page"
    os_info = get_os_info()
    user_agent = request.headers.get('User-Agent')
    current_time = get_current_time()
    return render_template('page1.html', title=page_title, os_info=os_info, user_agent=user_agent,
                           current_time=current_time)


@app.route('/page1')
def page1():
    page_title = "Main page"
    os_info = get_os_info()
    user_agent = request.headers.get('User-Agent')
    current_time = get_current_time()
    return render_template('page1.html', title=page_title, os_info=os_info, user_agent=user_agent,
                           current_time=current_time)


@app.route('/page2')
def page2():
    page_title = "About me"
    os_info = get_os_info()
    user_agent = request.headers.get('User-Agent')
    current_time = get_current_time()
    return render_template('page2.html', title=page_title, os_info=os_info, user_agent=user_agent,
                           current_time=current_time)


@app.route('/page3')
def page3():
    page_title = "Contacts"
    os_info = get_os_info()
    user_agent = request.headers.get('User-Agent')
    current_time = get_current_time()
    return render_template('page3.html', title=page_title, os_info=os_info, user_agent=user_agent,
                           current_time=current_time)


my_skills = ["Java", "Spring", "Hibernate"]


@app.route('/skills')
@app.route('/skills/<int:id>')
def display_skills(id=None):
    if id is None:
        return render_template('page2.html', skills=my_skills, total=len(my_skills))
    elif 0 <= id < len(my_skills):
        return render_template('page2.html', skills=[my_skills[id]])
    else:
        return "Skill not found"


if __name__ == '__main__':
    app.run()
