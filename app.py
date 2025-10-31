import os
from urllib.parse import urlparse, urlunparse
from flask import Flask, request, render_template_string, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import matplotlib.pyplot as plt
import io
import base64
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')  # Set SECRET_KEY in Render env vars for production

# Configure PostgreSQL database
database_url = os.environ.get('DATABASE_URL')
if database_url:
    if database_url.startswith('postgres://'):
        database_url = database_url.replace('postgres://', 'postgresql://', 1)
    parsed_url = urlparse(database_url)
    new_scheme = 'postgresql+psycopg'
    modified_url = urlunparse((new_scheme, parsed_url.netloc, parsed_url.path, parsed_url.params, parsed_url.query, parsed_url.fragment))
    app.config['SQLALCHEMY_DATABASE_URI'] = modified_url
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://localhost:5432/polls_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Other models (unchanged)
class Poll(db.Model):
    id = db.Column(db.String(8), primary_key=True)
    question = db.Column(db.String(200), nullable=False)
    expiration_datetime = db.Column(db.DateTime, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Link polls to users
    options = db.relationship('Option', backref='poll', lazy=True)

class Option(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(100), nullable=False)
    poll_id = db.Column(db.String(8), db.ForeignKey('poll.id'), nullable=False)
    votes = db.relationship('Vote', backref='option', lazy=True)

class Vote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    poll_id = db.Column(db.String(8), db.ForeignKey('poll.id'), nullable=False)
    option_id = db.Column(db.Integer, db.ForeignKey('option.id'), nullable=False)
    voter_ip = db.Column(db.String(45), nullable=False)

# Updated templates with login-aware navbar
def get_navbar(is_logged_in=False):
    if is_logged_in:
        return '''
    <nav class="bg-blue-600 text-white p-4">
      <div class="container mx-auto flex justify-between items-center">
        <h1 class="text-xl font-bold">Simple Polls</h1>
        <div class="space-x-4">
          <a href="/" class="hover:underline">Home</a>
          <a href="/create" class="hover:underline">Create Poll</a>
          <a href="/logout" class="hover:underline">Logout ({{ current_user.username }})</a>
        </div>
      </div>
    </nav>
    '''
    else:
        return '''
    <nav class="bg-blue-600 text-white p-4">
      <div class="container mx-auto flex justify-between items-center">
        <h1 class="text-xl font-bold">Simple Polls</h1>
        <div class="space-x-4">
          <a href="/" class="hover:underline">Home</a>
          <a href="/login" class="hover:underline">Login</a>
          <a href="/signup" class="hover:underline">Signup</a>
        </div>
      </div>
    </nav>
    '''

HOME_TEMPLATE = '''
<!doctype html>
<html>
<head>
  <title>Simple Polls</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-100 min-h-screen flex flex-col">
  {{ navbar }}
  <div class="container mx-auto p-4 flex-grow">
    <h2 class="text-2xl font-semibold mb-4 text-center">Active Polls</h2>
    {% with messages = get_flashed_messages() %}
      {% if messages %}
        <div class="mb-4 p-4 bg-yellow-100 border border-yellow-400 text-yellow-700 rounded">
          {{ messages[0] }}
        </div>
      {% endif %}
    {% endwith %}
    {% if polls %}
      <div class="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
        {% for poll in polls %}
          <div class="bg-white p-4 rounded-lg shadow-md">
            <h3 class="text-lg font-medium mb-2">{{ poll.question }}</h3>
            <p class="text-sm text-gray-500">Expires: {% if poll.expiration_datetime %}{{ poll.expiration_datetime }} {% else %}Never{% endif %}</p>
            <div class="space-y-2">
              <a href="/poll/{{ poll.id }}" class="block text-blue-600 hover:underline">Vote</a>
              <a href="/results/{{ poll.id }}" class="block text-blue-600 hover:underline">View Results</a>
              {% if current_user.is_authenticated %}
              <a href="/delete/{{ poll.id }}" class="block text-red-600 hover:underline" onclick="return confirm('Are you sure you want to delete this poll?');">Delete</a>
              {% endif %}
            </div>
          </div>
        {% endfor %}
      </div>
    {% else %}
      <p class="text-center text-gray-600">No polls available. {% if not current_user.is_authenticated %}<a href="/create" class="text-blue-600 hover:underline">Create one! (Login first)</a>{% else %}<a href="/create" class="text-blue-600 hover:underline">Create one!</a>{% endif %}</p>
    {% endif %}
  </div>
</body>
</html>
'''

CREATE_TEMPLATE = '''
<!doctype html>
<html>
<head>
  <title>Create Poll</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-100 min-h-screen flex flex-col">
  {{ navbar }}
  <div class="container mx-auto p-4 flex-grow flex items-center justify-center">
    <div class="bg-white p-6 rounded-lg shadow-md w-full max-w-md">
      <h2 class="text-2xl font-semibold mb-4 text-center">Create a Poll</h2>
      {% with messages = get_flashed_messages() %}
        {% if messages %}
          <div class="mb-4 p-4 bg-red-100 border border-red-400 text-red-700 rounded">
            {{ messages[0] }}
          </div>
        {% endif %}
      {% endwith %}
      <form method="post" class="space-y-4">
        <div>
          <label class="block text-sm font-medium text-gray-700">Question</label>
          <input name="question" required class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring focus:ring-blue-500 focus:ring-opacity-50" placeholder="Enter your question">
        </div>
        <div>
          <label class="block text-sm font-medium text-gray-700">Options (minimum 2)</label>
          <input name="options" required class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring focus:ring-blue-500 focus:ring-opacity-50" placeholder="Option 1">
          <input name="options" required class="mt-2 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring focus:ring-blue-500 focus:ring-opacity-50" placeholder="Option 2">
          <input name="options" class="mt-2 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring focus:ring-blue-500 focus:ring-opacity-50" placeholder="Option 3 (optional)">
          <input name="options" class="mt-2 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring focus:ring-blue-500 focus:ring-opacity-50" placeholder="Option 4 (optional)">
        </div>
        <div>
          <label class="block text-sm font-medium text-gray-700">Expiration (days from now, optional)</label>
          <input name="expiration_days" type="number" min="0" class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring focus:ring-blue-500 focus:ring-opacity-50" placeholder="e.g., 7 for 7 days">
        </div>
        <button type="submit" class="w-full bg-blue-600 text-white py-2 rounded-md hover:bg-blue-700 transition">Create Poll</button>
      </form>
    </div>
  </div>
</body>
</html>
'''

SIGNUP_TEMPLATE = '''
<!doctype html>
<html>
<head>
  <title>Signup</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-100 min-h-screen flex flex-col">
  {{ navbar }}
  <div class="container mx-auto p-4 flex-grow flex items-center justify-center">
    <div class="bg-white p-6 rounded-lg shadow-md w-full max-w-md">
      <h2 class="text-2xl font-semibold mb-4 text-center">Signup</h2>
      {% with messages = get_flashed_messages() %}
        {% if messages %}
          <div class="mb-4 p-4 bg-red-100 border border-red-400 text-red-700 rounded">
            {{ messages[0] }}
          </div>
        {% endif %}
      {% endwith %}
      <form method="post" class="space-y-4">
        <div>
          <label class="block text-sm font-medium text-gray-700">Username</label>
          <input name="username" required class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring focus:ring-blue-500 focus:ring-opacity-50">
        </div>
        <div>
          <label class="block text-sm font-medium text-gray-700">Email</label>
          <input name="email" type="email" required class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring focus:ring-blue-500 focus:ring-opacity-50">
        </div>
        <div>
          <label class="block text-sm font-medium text-gray-700">Password</label>
          <input name="password" type="password" required class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring focus:ring-blue-500 focus:ring-opacity-50">
        </div>
        <button type="submit" class="w-full bg-blue-600 text-white py-2 rounded-md hover:bg-blue-700 transition">Signup</button>
      </form>
      <p class="mt-4 text-center"><a href="/login" class="text-blue-600 hover:underline">Already have an account? Login</a></p>
    </div>
  </div>
</body>
</html>
'''

LOGIN_TEMPLATE = '''
<!doctype html>
<html>
<head>
  <title>Login</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-100 min-h-screen flex flex-col">
  {{ navbar }}
  <div class="container mx-auto p-4 flex-grow flex items-center justify-center">
    <div class="bg-white p-6 rounded-lg shadow-md w-full max-w-md">
      <h2 class="text-2xl font-semibold mb-4 text-center">Login</h2>
      {% with messages = get_flashed_messages() %}
        {% if messages %}
          <div class="mb-4 p-4 bg-red-100 border border-red-400 text-red-700 rounded">
            {{ messages[0] }}
          </div>
        {% endif %}
      {% endwith %}
      <form method="post" class="space-y-4">
        <div>
          <label class="block text-sm font-medium text-gray-700">Email</label>
          <input name="email" type="email" required class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring focus:ring-blue-500 focus:ring-opacity-50">
        </div>
        <div>
          <label class="block text-sm font-medium text-gray-700">Password</label>
          <input name="password" type="password" required class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring focus:ring-blue-500 focus:ring-opacity-50">
        </div>
        <button type="submit" class="w-full bg-blue-600 text-white py-2 rounded-md hover:bg-blue-700 transition">Login</button>
      </form>
      <p class="mt-4 text-center"><a href="/signup" class="text-blue-600 hover:underline">Don't have an account? Signup</a></p>
    </div>
  </div>
</body>
</html>
'''

VOTE_TEMPLATE = '''
<!doctype html>
<html>
<head>
  <title>Vote - {{ question }}</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-100 min-h-screen flex flex-col">
  {{ navbar }}
  <div class="container mx-auto p-4 flex-grow flex items-center justify-center">
    <div class="bg-white p-6 rounded-lg shadow-md w-full max-w-md">
      <h2 class="text-2xl font-semibold mb-4">{{ question }}</h2>
      {% if error %}
        <p class="text-red-500 mb-4">{{ error }}</p>
      {% endif %}
      <form method="post" class="space-y-4">
        {% for opt in options %}
          <div class="flex items-center">
            <input type="radio" name="vote" value="{{ opt.id }}" required class="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300">
            <label class="ml-2 text-gray-700">{{ opt.text }}</label>
          </div>
        {% endfor %}
        <button type="submit" class="w-full bg-blue-600 text-white py-2 rounded-md hover:bg-blue-700 transition">Vote</button>
      </form>
      <a href="/results/{{ poll_id }}" class="block mt-4 text-blue-600 hover:underline text-center">View Results</a>
    </div>
  </div>
</body>
</html>
'''

RESULTS_TEMPLATE = '''
<!doctype html>
<html>
<head>
  <title>Results - {{ question }}</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-100 min-h-screen flex flex-col">
  {{ navbar }}
  <div class="container mx-auto p-4 flex-grow flex items-center justify-center">
    <div class="bg-white p-6 rounded-lg shadow-md w-full max-w-lg">
      <h2 class="text-2xl font-semibold mb-4">{{ question }}</h2>
      <p class="text-gray-600 mb-4">Total votes: {{ total_votes }}</p>
      <img src="data:image/png;base64,{{ chart }}" alt="Results Chart" class="w-full rounded-md">
      <div class="mt-4">
        {% for opt in options %}
          <p class="text-gray-700">{{ opt.text }}: {{ opt.votes|length }} vote{% if opt.votes|length != 1 %}s{% endif %}</p>
        {% endfor %}
      </div>
      <a href="/poll/{{ poll_id }}" class="block mt-4 text-blue-600 hover:underline text-center">Back to Voting</a>
    </div>
  </div>
</body>
</html>
'''

# Initialize database
with app.app_context():
    db.create_all()

@app.route('/', methods=['GET'])
def home():
    polls = Poll.query.filter((Poll.expiration_datetime.is_(None)) | (Poll.expiration_datetime > datetime.utcnow())).all()
    navbar = get_navbar(current_user.is_authenticated)
    return render_template_string(HOME_TEMPLATE, polls=polls, navbar=navbar)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    navbar = get_navbar(False)
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
            flash('Username or email already exists!')
            return render_template_string(SIGNUP_TEMPLATE, navbar=navbar)
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash('Account created! Please log in.')
        return redirect(url_for('login'))
    return render_template_string(SIGNUP_TEMPLATE, navbar=navbar)

@app.route('/login', methods=['GET', 'POST'])
def login():
    navbar = get_navbar(False)
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            flash('Logged in successfully!')
            return redirect(url_for('home'))
        flash('Invalid email or password!')
    return render_template_string(LOGIN_TEMPLATE, navbar=navbar)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully!')
    return redirect(url_for('home'))

@app.route('/create', methods=['GET', 'POST'])
@login_required
def create_poll():
    navbar = get_navbar(True)
    if request.method == 'POST':
        question = request.form['question']
        options = [opt for opt in request.form.getlist('options') if opt.strip()]
        if len(options) < 2:
            flash('Need at least 2 options!')
            return render_template_string(CREATE_TEMPLATE, navbar=navbar)
        expiration_days = request.form.get('expiration_days')
        expiration = None
        if expiration_days and int(expiration_days) > 0:
            expiration = datetime.utcnow() + timedelta(days=int(expiration_days))
        poll_id = str(uuid.uuid4())[:8]
        poll = Poll(id=poll_id, question=question, expiration_datetime=expiration, user_id=current_user.id)
        db.session.add(poll)
        for opt_text in options:
            option = Option(text=opt_text, poll_id=poll_id)
            db.session.add(option)
        db.session.commit()
        flash('Poll created successfully!')
        return redirect(url_for('vote', poll_id=poll_id))
    return render_template_string(CREATE_TEMPLATE, navbar=navbar)

@app.route('/delete/<poll_id>', methods=['GET'])
@login_required
def delete(poll_id):
    poll = Poll.query.get_or_404(poll_id)
    if poll.user_id != current_user.id:
        flash('You can only delete your own polls!')
        return redirect(url_for('home'))
    db.session.delete(poll)
    db.session.commit()
    flash('Poll deleted!')
    return redirect(url_for('home'))

@app.route('/poll/<poll_id>', methods=['GET', 'POST'])
def vote(poll_id):
    poll = Poll.query.get_or_404(poll_id)
    if poll.expiration_datetime and poll.expiration_datetime < datetime.utcnow():
        flash('This poll has expired!')
        return redirect(url_for('home'))
    options = poll.options
    navbar = get_navbar(current_user.is_authenticated)
    client_ip = request.remote_addr
    if Vote.query.filter_by(poll_id=poll_id, voter_ip=client_ip).first():
        return render_template_string(VOTE_TEMPLATE, question=poll.question, options=options, poll_id=poll_id, error="You already voted!", navbar=navbar)
    if request.method == 'POST':
        option_id = request.form['vote']
        option = Option.query.get_or_404(option_id)
        if option.poll_id == poll_id:
            vote = Vote(poll_id=poll_id, option_id=option_id, voter_ip=client_ip)
            db.session.add(vote)
            db.session.commit()
        return redirect(url_for('results', poll_id=poll_id))
    return render_template_string(VOTE_TEMPLATE, question=poll.question, options=options, poll_id=poll_id, navbar=navbar)

@app.route('/results/<poll_id>')
def results(poll_id):
    poll = Poll.query.get_or_404(poll_id)
    if poll.expiration_datetime and poll.expiration_datetime < datetime.utcnow():
        flash('This poll has expired!')
        return redirect(url_for('home'))
    options = poll.options
    navbar = get_navbar(current_user.is_authenticated)
    total_votes = sum(len(opt.votes) for opt in options)
    plt.figure(figsize=(6, 4))
    plt.bar([opt.text for opt in options], [len(opt.votes) for opt in options], color='#2563eb')
    plt.title(poll.question, fontsize=12, pad=10)
    plt.ylabel('Votes', fontsize=10)
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    img = io.BytesIO()
    plt.savefig(img, format='png')
    img.seek(0)
    chart_url = base64.b64encode(img.getvalue()).decode()
    plt.close()
    return render_template_string(RESULTS_TEMPLATE, question=poll.question, total_votes=total_votes, chart=chart_url, options=options, poll_id=poll_id, navbar=navbar)

if __name__ == '__main__':
    app.run(debug=True)