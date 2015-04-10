from flask import Flask, jsonify, abort, make_response, request, url_for, render_template, redirect, session
import requests
from passlib.hash import sha256_crypt
from functools import wraps
import os
import json
from random import shuffle

askiiBaseUrl = "http://askii.media.mit.edu/askii/api/v1.0"
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

def progress():
    if session["count"]>100:
        return 100
    else:
        return session["count"]


@app.route('/')
@login_required
def index():
    session["count"]=0
    session["seen_questions"] = []
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
    askiiUser["_id"]=askiiUser["uri"].split("/")[-1]
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
    askiiUser["_id"]=askiiUser["uri"].split("/")[-1]
    session["user"]=askiiUser.json()["user"]
    return redirect(url_for('index', next=request.url))

@app.route('/logout', methods=['GET'])
def logout():
    session.clear()
    return redirect(url_for('login', next=request.url))

@app.route('/question/<count>', methods=['GET'])
def get_question(count):
    count = int(count)
    session_count = session.get("count", 0)
    if count < session_count and count >= 0:
        print count, session_count
        question = requests.get(askiiBaseUrl+"/questions/"+session["seen_questions"][session_count]+"?key="+key).json()
    else:
        session["count"]=count
        data = json.dumps({"count": str(count)})
        question = requests.post(askiiBaseUrl+"/next/"+session["user"]["_id"]+"?key="+key, headers=headers, data=data)
        question = question.json()
        session["seen_questions"].append(question["uri"].split("/")[-1])
    print question
    random_choices = []
    for possibility in question["possiblities"]:
        random_choices.append((possibility, 0))
    random_choices.append((question["answer"],1))
    shuffle(random_choices)
    progress_int = progress()
    return render_template('question.html', question=question, choices=random_choices, count=count, progress=progress_int, user=session["user"])

@app.route('/answer', methods=['POST'])
def answer_question():
    num_answer = request.form.get("answer", "0")
    question_id = request.form.get("question_id", "")
    user_id = session["user"]["_id"]
    data = json.dumps({"answer": num_answer})
    answer = requests.post(askiiBaseUrl+"/users/"+user_id+"/"+question_id+"?key="+key, headers=headers, data=data)
    count_str = str(session["count"]+1)
    next_url = url_for('get_question', count=count_str, _external=True)
    return jsonify({"next_url" : next_url})

@app.route('/stats', methods=['GET'])
def get_stats():
    user_id = session["user"]["_id"]
    user = requests.get(askiiBaseUrl+"/users/"+user_id+"?key="+key, headers=headers)
    answered_questions = user.json()["user"]["questions"]
    easy_questions = {}
    medium_questions = {}
    hard_questions = {}
    very_hard_questions = {}
    for question_key in answered_questions:
        question_val = answered_questions[question_key]
        if question_val["difficulty"] <= 1:
            easy_questions[question_key] = requests.get(askiiBaseUrl+"/questions/"+question_key+"?key="+key, headers=headers).json()["question"]
        elif question_val["difficulty"] <= 3:
            medium_questions[question_key] = requests.get(askiiBaseUrl+"/questions/"+question_key+"?key="+key, headers=headers).json()["question"]
        elif question_val["difficulty"] <= 5:
            hard_questions[question_key] = requests.get(askiiBaseUrl+"/questions/"+question_key+"?key="+key, headers=headers).json()["question"]
        elif question_val["difficulty"] <= 7:
            very_hard_questions[question_key] = requests.get(askiiBaseUrl+"/questions/"+question_key+"?key="+key, headers=headers).json()["question"]
    all_ratings = [{"easy": easy_questions}, {"medium": medium_questions}, {"hard": hard_questions}, {"very hard": very_hard_questions}]
    return render_template('stats.html', user=user, ratings=all_ratings)

@app.route('/review/<question_id>', methods=['GET'])
def review_question(question_id):
    question = requests.get(askiiBaseUrl+"/questions/"+question_id+"?key="+key, headers=headers).json()
    return render_template('review.html', user=session["user"], question=question["question"])


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 4000))
    app.run(host='0.0.0.0', port=port, debug=True)

