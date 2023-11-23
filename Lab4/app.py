import datetime
import os

from flask import Flask, render_template, request, redirect, url_for, session
import json

app = Flask(__name__)
app.secret_key = 'aboba'


def load_users():
    file_path = os.path.join(app.root_path, 'static','clients.json')
    with open(file_path, 'r') as f:
        return json.load(f)


users = load_users()
user_cookies = {}


@app.route('/')
def index():
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    users = load_users()
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username in users and users[username]['password'] == password:
            session['username'] = username
            return redirect(url_for('info'))
        else:
            return render_template('login.html')

    return render_template('login.html')


@app.route('/info')
def info():
    users = load_users()
    username = session.get('username', None)
    if username:
        user_info = users.get(username, None)
        if user_info:
            cookies = get_user_cookies()
            return render_template('info.html', user_info=user_info, cookies=cookies)
    return redirect(url_for('login'))


@app.route('/logout', methods=['POST'])
def logout():
    session.pop('username', None)
    session.pop('message', None)
    user_cookies.clear()
    return redirect(url_for('login'))


@app.route('/add_cookie', methods=['POST'])
def add_cookie():
    username = session.get('username', None)
    if username:
        key = request.form['cookie_key']
        value = request.form['cookie_value']
        expiry = int(request.form['cookie_expiry'])
        user_cookies[key] = {"value": value, "expiry": expiry, "creation_time": str(datetime.datetime.now())}
    return redirect(url_for('info'))


@app.route('/delete_cookie', methods=['POST'])
def delete_cookie():
    username = session.get('username', None)
    if username:
        key = request.form['delete_cookie_key']
        if key in user_cookies:
            user_cookies.pop(key)
    return redirect(url_for('info'))


@app.route('/delete_all_cookies', methods=['POST'])
def delete_all_cookies():
    username = session.get('username', None)
    if username:
        user_cookies.clear()
    return redirect(url_for('info'))


def get_user_cookies():
    cookies_list = []
    for key, cookie in user_cookies.items():
        expiry_time = datetime.datetime.strptime(cookie['creation_time'], '%Y-%m-%d %H:%M:%S.%f') + datetime.timedelta(seconds=cookie['expiry'])
        cookies_list.append({
            'key': key,
            'value': cookie['value'],
            'expiry': expiry_time,
            'creation_time': cookie['creation_time']
        })
    return cookies_list


@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    username = session.get('username', None)
    if username:
        if request.method == 'POST':
            new_password = request.form.get('new_password')
            if new_password:
                change_user_password(username, new_password)
    return redirect(url_for('info'))


def change_user_password(username, new_password):
    with open('static/clients.json', 'r+') as f:
        users = json.load(f)
        if username in users:
            users[username]['password'] = new_password
            f.seek(0)
            json.dump(users, f, indent=4)
            f.truncate()


if __name__ == '__main__':
    app.run(debug=True)