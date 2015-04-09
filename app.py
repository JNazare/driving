from flask import Flask, jsonify, abort, make_response, request, url_for, render_template, redirect, session
import requests
from passlib.hash import sha256_crypt
from functools import wraps
import os
import json

askiiBaseUrl = "http://localhost:5000/askii/api/v1.0"
key = "qb4SpwwMbvDut4DK5SGT3GU5eYGQAzAa0FC0Wu56Mo0"
headers = {"Content-Type": "application/json"}

app = Flask(__name__)
app.secret_key = 'bacon'

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user", None) is None:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
@login_required
def index():
    return render_template('index.html', user=session["user"])

@app.route('/login', methods=['GET'])
def login():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def do_login():
    username = request.form.get("username", None).lower()
    password = request.form.get("password", None)
    askiiUser = requests.get(askiiBaseUrl+"/users/username/"+username+"?key="+key, headers=headers)
    if askiiUser == None:
        abort(404)
    askiiUser = askiiUser.json()["user"]
    hashed_password = askiiUser.get("password", None)
    if not hashed_password:
        abort(404)
    if sha256_crypt.verify(password, hashed_password) == False:
        abort(404)
    if askiiUser.get("_id", None):
        askiiUser["_id"]=unicode(askiiUser["_id"])
    session["user"]=askiiUser
    return redirect(url_for('index', next=request.url))

@app.route('/signup', methods=['POST'])
def do_signup():
    username = request.form.get("username", None).lower()
    password = request.form.get("password", None)
    hashed_password = sha256_crypt.encrypt(password)
    data = json.dumps({"username": username, "password": str(hashed_password)})
    askiiUser = requests.post(askiiBaseUrl+"/users?key="+key, headers=headers, data=data)
    if askiiUser == None:
        abort(404)
    session["user"]=askiiUser.json()["user"]
    return redirect(url_for('index', next=request.url))

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 4000))
    app.run(host='0.0.0.0', port=port, debug=True)
