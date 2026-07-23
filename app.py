import os
from urllib.parse import urlparse, urlunparse
from flask import Flask, request, render_template_string, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
import uuid
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import io
import base64
from datetime import datetime, timedelta

app = Flask(__name__)

# Trust exactly one reverse-proxy hop (Render sits in front of the app) so
# request.remote_addr reflects the real visitor IP instead of the proxy's
# internal IP. Without this, every visitor looks identical to Flask, which
# is what caused the "only one vote per poll, ever" bug.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')

# Database: SQLite locally, PostgreSQL on Render
database_url = os.environ.get('DATABASE_URL')
if database_url:
    if database_url.startswith('postgres://'):
        database_url = database_url.replace('postgres://', 'postgresql://', 1)
    parsed_url = urlparse(database_url)
    modified_url = urlunparse(('postgresql+psycopg', parsed_url.netloc, parsed_url.path,
                               parsed_url.params, parsed_url.query, parsed_url.fragment))
    app.config['SQLALCHEMY_DATABASE_URI'] = modified_url
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///polls.db'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Poll(db.Model):
    id = db.Column(db.String(8), primary_key=True)
    question = db.Column(db.String(200), nullable=False)
    expiration_datetime = db.Column(db.DateTime, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    options = db.relationship('Option', backref='poll', lazy=True, cascade='all, delete-orphan')

class Option(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(100), nullable=False)
    poll_id = db.Column(db.String(8), db.ForeignKey('poll.id'), nullable=False)
    votes = db.relationship('Vote', backref='option', lazy=True, cascade='all, delete-orphan')

class Vote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    poll_id = db.Column(db.String(8), db.ForeignKey('poll.id'), nullable=False)
    option_id = db.Column(db.Integer, db.ForeignKey('option.id'), nullable=False)
    voter_ip = db.Column(db.String(45), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ---------------------------------------------------------------------------
# Shared UI building blocks
# ---------------------------------------------------------------------------

STYLES = '''
<style>
  @import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;600;700&family=Inter:wght@400;500;600;700&display=swap');

  :root {
    --ink: #14142B;
    --paper: #FAF9F4;
    --card: #FFFFFF;
    --line: #E6E2D6;
    --teal: #0E9C8E;
    --teal-dark: #0B7C71;
    --gold: #F2B705;
    --danger: #D8503F;
    --success: #2E9E5B;
    --muted: #6B6A78;
  }

  * { box-sizing: border-box; }

  body {
    font-family: 'Inter', sans-serif;
    background-color: var(--paper);
    background-image: radial-gradient(circle at 1px 1px, #00000009 1px, transparent 0);
    background-size: 24px 24px;
    color: var(--ink);
  }

  h1, h2, h3, .display {
    font-family: 'Space Grotesk', sans-serif;
    letter-spacing: -0.01em;
  }

  .site-nav {
    background: var(--ink);
    border-bottom: 3px solid var(--teal);
  }
  .site-nav a { color: #E9E8F5; opacity: 0.85; transition: opacity .15s ease; }
  .site-nav a:hover { opacity: 1; text-decoration: none; }
  .site-nav a.active { opacity: 1; color: var(--gold); }
  .brand-mark {
    display: inline-flex; align-items: center; gap: 8px;
  }
  .brand-dot {
    width: 10px; height: 10px; border-radius: 999px; background: var(--gold);
    box-shadow: 0 0 0 3px rgba(242,183,5,0.25);
  }

  .btn-primary {
    background: var(--teal);
    color: white;
    font-weight: 600;
    transition: transform .12s ease, background .15s ease;
  }
  .btn-primary:hover { background: var(--teal-dark); transform: translateY(-1px); }
  .btn-primary:active { transform: translateY(0); }

  .field {
    border: 1.5px solid var(--line);
    background: var(--card);
    transition: border-color .15s ease, box-shadow .15s ease;
  }
  .field:focus {
    outline: none;
    border-color: var(--teal);
    box-shadow: 0 0 0 3px rgba(14,156,142,0.15);
  }

  /* Ballot-ticket card with perforated edge */
  .ticket {
    position: relative;
    background: var(--card);
    border: 1.5px solid var(--line);
    border-radius: 16px;
    transition: transform .15s ease, box-shadow .15s ease;
  }
  .ticket:hover { transform: translateY(-3px); box-shadow: 0 10px 24px rgba(20,20,43,0.08); }
  .ticket::before {
    content: "";
    position: absolute;
    left: 0; right: 0; top: 42px;
    border-top: 2px dashed var(--line);
  }
  .ticket::after {
    content: "";
    position: absolute;
    left: -8px; top: 32px;
    width: 16px; height: 16px;
    background: var(--paper);
    border-radius: 999px;
    border: 1.5px solid var(--line);
    box-shadow: 592px 0 0 -1.5px var(--line);
  }

  .badge { font-size: 0.7rem; font-weight: 700; letter-spacing: 0.04em; text-transform: uppercase; padding: 3px 10px; border-radius: 999px; }
  .badge-live { background: rgba(46,158,91,0.12); color: var(--success); }
  .badge-none { background: rgba(107,106,120,0.12); color: var(--muted); }

  .flash {
    border-left: 4px solid;
    border-radius: 8px;
  }
  .flash-success { background: rgba(46,158,91,0.08); border-color: var(--success); color: #1F6B3C; }
  .flash-error { background: rgba(216,80,63,0.08); border-color: var(--danger); color: #A6392C; }
  .flash-info { background: rgba(14,156,142,0.08); border-color: var(--teal); color: var(--teal-dark); }

  /* Ballot option row for voting */
  .ballot-row {
    display: flex;
    align-items: center;
    gap: 12px;
    border: 1.5px solid var(--line);
    border-radius: 12px;
    padding: 14px 16px;
    cursor: pointer;
    transition: border-color .15s ease, background .15s ease;
    background: var(--card);
  }
  .ballot-row:hover { border-color: var(--teal); }
  .ballot-box {
    width: 20px; height: 20px;
    border: 2px solid var(--muted);
    border-radius: 4px;
    flex-shrink: 0;
    display: flex; align-items: center; justify-content: center;
    transition: border-color .15s ease, background .15s ease;
  }
  .ballot-row input { position: absolute; opacity: 0; width: 0; height: 0; }
  .ballot-row input:checked ~ .ballot-box {
    background: var(--teal);
    border-color: var(--teal);
  }
  .ballot-row input:checked ~ .ballot-box::after {
    content: "✓"; color: white; font-size: 13px; font-weight: 700;
  }
  .ballot-row:has(input:checked) {
    border-color: var(--teal);
    background: rgba(14,156,142,0.06);
  }

  .bar-track { background: var(--line); border-radius: 999px; overflow: hidden; height: 10px; }
  .bar-fill { background: var(--teal); height: 100%; border-radius: 999px; transition: width .4s ease; }

  .site-footer { border-top: 1px solid var(--line); color: var(--muted); }

  .empty-illustration { opacity: 0.9; }
</style>
'''

def nav_html(active):
    def cls(name):
        return 'active' if active == name else ''
    if current_user.is_authenticated:
        auth_links = f'''
          <a href="/create" class="{cls('create')} hover:underline">Create Poll</a>
          <a href="/logout" class="hover:underline">Logout ({current_user.username})</a>
        '''
    else:
        auth_links = f'''
          <a href="/login" class="{cls('login')} hover:underline">Login</a>
          <a href="/signup" class="{cls('signup')} hover:underline">Signup</a>
        '''
    return f'''
  <nav class="site-nav text-white p-4">
    <div class="container mx-auto flex justify-between items-center">
      <a href="/" class="brand-mark">
        <span class="brand-dot"></span>
        <h1 class="text-xl font-bold m-0">Simple Polls</h1>
      </a>
      <div class="space-x-4 text-sm font-medium">
        <a href="/" class="{cls('home')} hover:underline">Home</a>
        {auth_links}
      </div>
    </div>
  </nav>
'''

FOOTER = '''
  <footer class="site-footer mt-auto py-6 text-center text-sm">
    <p>Simple Polls &mdash; quick questions, honest answers.</p>
    <p class="mt-1">Built by <span class="font-semibold" style="color: var(--teal-dark);">Rohith</span>.</p>
  </footer>
'''

def flashes_html():
    from flask import get_flashed_messages
    blocks = []
    for category, message in get_flashed_messages(with_categories=True):
        cls = {'success': 'flash-success', 'error': 'flash-error'}.get(category, 'flash-info')
        blocks.append(f'<div class="flash {cls} mb-4 p-4">{message}</div>')
    return ''.join(blocks)

def page_shell(active, title, body):
    return f'''
<!doctype html>
<html>
<head>
  <title>{title} - Simple Polls</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <script src="https://cdn.tailwindcss.com"></script>
  {STYLES}
</head>
<body class="min-h-screen flex flex-col">
  {nav_html(active)}
  <div class="container mx-auto p-4 flex-grow">
    {body}
  </div>
  {FOOTER}
</body>
</html>
'''

# ---------------------------------------------------------------------------
# Page templates (Jinja strings, assembled at request time via page_shell)
# ---------------------------------------------------------------------------

HOME_BODY = '''
<div class="max-w-5xl mx-auto">
  <div class="mb-6 text-center">
    <h2 class="text-3xl font-bold mb-1">Active Polls</h2>
    <p class="text-sm" style="color: var(--muted);">Cast a vote or start a poll of your own.</p>
  </div>
  {{ flashes|safe }}
  {% if polls %}
    <div class="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
      {% for poll in polls %}
        <div class="ticket p-5 pt-6">
          <div class="flex items-start justify-between gap-2 mb-3">
            <h3 class="text-lg font-semibold leading-snug">{{ poll.question }}</h3>
            {% if poll.expiration_datetime %}
              <span class="badge badge-live whitespace-nowrap">Expires soon</span>
            {% else %}
              <span class="badge badge-none whitespace-nowrap">No expiry</span>
            {% endif %}
          </div>
          <p class="text-xs mb-4" style="color: var(--muted);">
            {% if poll.expiration_datetime %}Closes {{ poll.expiration_datetime.strftime('%b %d, %Y %H:%M') }} UTC{% else %}Open indefinitely{% endif %}
            &middot; {{ poll.options|length }} option{{ 's' if poll.options|length != 1 else '' }}
          </p>
          <div class="space-y-2 pt-2" style="border-top: none;">
            <a href="/poll/{{ poll.id }}" class="btn-primary block text-center py-2 rounded-md">Vote now</a>
            <a href="/results/{{ poll.id }}" class="block text-center py-2 rounded-md" style="color: var(--teal-dark); font-weight: 600;">View results</a>
            {% if current_user.is_authenticated and poll.user_id == current_user.id %}
              <a href="/delete/{{ poll.id }}" class="block text-center text-xs" style="color: var(--danger);" onclick="return confirm('Delete this poll? This cannot be undone.');">Delete poll</a>
            {% endif %}
          </div>
        </div>
      {% endfor %}
    </div>
  {% else %}
    <div class="text-center py-16">
      <div class="empty-illustration text-5xl mb-4">🗳️</div>
      <p class="text-lg font-medium mb-1">No polls yet</p>
      <p class="text-sm" style="color: var(--muted);">
        {% if current_user.is_authenticated %}
          <a href="/create" style="color: var(--teal-dark); font-weight: 600;">Create the first one</a>
        {% else %}
          <a href="/login" style="color: var(--teal-dark); font-weight: 600;">Log in</a> to create one
        {% endif %}
      </p>
    </div>
  {% endif %}
</div>
'''

CREATE_BODY = '''
<div class="max-w-md mx-auto flex items-center justify-center" style="min-height: 60vh;">
  <div class="ticket w-full p-6 pt-7">
    <h2 class="text-2xl font-bold mb-4 text-center">Create a poll</h2>
    {{ flashes|safe }}
    <form method="post" class="space-y-4">
      <div>
        <label class="block text-sm font-medium mb-1">Question</label>
        <input name="question" required class="field mt-1 block w-full rounded-md px-3 py-2" placeholder="What should we decide?">
      </div>
      <div>
        <label class="block text-sm font-medium mb-1">Options <span style="color: var(--muted); font-weight: 400;">(minimum 2)</span></label>
        <div id="option-list" class="space-y-2">
          <input name="options" required class="field block w-full rounded-md px-3 py-2" placeholder="Option 1">
          <input name="options" required class="field block w-full rounded-md px-3 py-2" placeholder="Option 2">
          <input name="options" class="field block w-full rounded-md px-3 py-2" placeholder="Option 3 (optional)">
          <input name="options" class="field block w-full rounded-md px-3 py-2" placeholder="Option 4 (optional)">
        </div>
        <button type="button" id="add-option" class="mt-2 text-xs font-semibold" style="color: var(--teal-dark);">+ Add another option</button>
      </div>
      <div>
        <label class="block text-sm font-medium mb-1">Expiration <span style="color: var(--muted); font-weight: 400;">(days from now)</span></label>
        <input name="expiration_days" type="number" min="0" class="field mt-1 block w-full rounded-md px-3 py-2" placeholder="Defaults to 2 days &mdash; enter 0 for no expiration">
        <p class="text-xs mt-1" style="color: var(--muted);">Leave blank and the poll closes in 2 days. Enter 0 for a poll that never expires.</p>
      </div>
      <button type="submit" class="btn-primary w-full py-2 rounded-md">Create poll</button>
    </form>
  </div>
</div>
<script>
  document.getElementById('add-option').addEventListener('click', function () {
    var list = document.getElementById('option-list');
    var count = list.querySelectorAll('input').length;
    if (count >= 8) { return; }
    var input = document.createElement('input');
    input.name = 'options';
    input.className = 'field block w-full rounded-md px-3 py-2';
    input.placeholder = 'Option ' + (count + 1) + ' (optional)';
    list.appendChild(input);
  });
</script>
'''

SIGNUP_BODY = '''
<div class="max-w-md mx-auto flex items-center justify-center" style="min-height: 60vh;">
  <div class="ticket w-full p-6 pt-7">
    <h2 class="text-2xl font-bold mb-4 text-center">Create your account</h2>
    {{ flashes|safe }}
    <form method="post" class="space-y-4">
      <div>
        <label class="block text-sm font-medium mb-1">Username</label>
        <input name="username" required class="field block w-full rounded-md px-3 py-2">
      </div>
      <div>
        <label class="block text-sm font-medium mb-1">Email</label>
        <input name="email" type="email" required class="field block w-full rounded-md px-3 py-2">
      </div>
      <div>
        <label class="block text-sm font-medium mb-1">Password</label>
        <input name="password" type="password" required class="field block w-full rounded-md px-3 py-2">
      </div>
      <button type="submit" class="btn-primary w-full py-2 rounded-md">Sign up</button>
    </form>
    <p class="mt-4 text-center text-sm">Already have an account? <a href="/login" style="color: var(--teal-dark); font-weight: 600;">Log in</a></p>
  </div>
</div>
'''

LOGIN_BODY = '''
<div class="max-w-md mx-auto flex items-center justify-center" style="min-height: 60vh;">
  <div class="ticket w-full p-6 pt-7">
    <h2 class="text-2xl font-bold mb-4 text-center">Welcome back</h2>
    {{ flashes|safe }}
    <form method="post" class="space-y-4">
      <div>
        <label class="block text-sm font-medium mb-1">Email</label>
        <input name="email" type="email" required class="field block w-full rounded-md px-3 py-2">
      </div>
      <div>
        <label class="block text-sm font-medium mb-1">Password</label>
        <input name="password" type="password" required class="field block w-full rounded-md px-3 py-2">
      </div>
      <button type="submit" class="btn-primary w-full py-2 rounded-md">Log in</button>
    </form>
    <p class="mt-4 text-center text-sm">Don't have an account? <a href="/signup" style="color: var(--teal-dark); font-weight: 600;">Sign up</a></p>
  </div>
</div>
'''

VOTE_BODY = '''
<div class="max-w-md mx-auto flex items-center justify-center" style="min-height: 60vh;">
  <div class="ticket w-full p-6 pt-7">
    <h2 class="text-2xl font-bold mb-4">{{ question }}</h2>
    {{ flashes|safe }}
    {% if error %}
      <div class="flash flash-error mb-4 p-4">{{ error }}</div>
    {% endif %}
    <form method="post" class="space-y-3">
      {% for opt in options %}
        <label class="ballot-row">
          <input type="radio" name="vote" value="{{ opt.id }}" required {% if error %}disabled{% endif %}>
          <span class="ballot-box"></span>
          <span>{{ opt.text }}</span>
        </label>
      {% endfor %}
      {% if not error %}
        <button type="submit" class="btn-primary w-full py-2 rounded-md">Cast vote</button>
      {% endif %}
    </form>
    <a href="/results/{{ poll_id }}" class="block mt-4 text-center text-sm font-semibold" style="color: var(--teal-dark);">View results</a>
  </div>
</div>
'''

RESULTS_BODY = '''
<div class="max-w-xl mx-auto flex items-center justify-center" style="min-height: 60vh;">
  <div class="ticket w-full p-6 pt-7">
    <h2 class="text-2xl font-bold mb-1">{{ question }}</h2>
    {{ flashes|safe }}
    <p class="text-sm mb-4" style="color: var(--muted);">{{ total_votes }} vote{{ 's' if total_votes != 1 else '' }} total</p>
    <img src="data:image/png;base64,{{ chart }}" alt="Results Chart" class="w-full rounded-md mb-4">
    <div class="space-y-3">
      {% for opt in options %}
        <div>
          <div class="flex justify-between text-sm mb-1">
            <span class="font-medium">{{ opt.text }}</span>
            <span style="color: var(--muted);">{{ opt.votes|length }} vote{{ 's' if opt.votes|length != 1 else '' }} &middot; {{ (opt.votes|length / total_votes * 100)|round(1) if total_votes else 0 }}%</span>
          </div>
          <div class="bar-track">
            <div class="bar-fill" style="width: {{ (opt.votes|length / total_votes * 100) if total_votes else 0 }}%;"></div>
          </div>
        </div>
      {% endfor %}
    </div>
    <a href="/poll/{{ poll_id }}" class="block mt-6 text-center text-sm font-semibold" style="color: var(--teal-dark);">Back to voting</a>
  </div>
</div>
'''

# Create tables
with app.app_context():
    db.create_all()

def render(active, title, body_template, **context):
    body = render_template_string(body_template, flashes=flashes_html(), **context)
    return render_template_string(page_shell(active, title, body))

# Routes
@app.route('/', methods=['GET'])
def home():
    polls = Poll.query.filter(
        (Poll.expiration_datetime.is_(None)) |
        (Poll.expiration_datetime > datetime.utcnow())
    ).all()
    return render('home', 'Home', HOME_BODY, polls=polls)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
            flash('Username or email already exists!', 'error')
            return render('signup', 'Sign up', SIGNUP_BODY)
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash('Account created! Please log in.', 'success')
        return redirect(url_for('login'))
    return render('signup', 'Sign up', SIGNUP_BODY)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('home'))
        flash('Invalid email or password!', 'error')
    return render('login', 'Log in', LOGIN_BODY)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('home'))

@app.route('/create', methods=['GET', 'POST'])
@login_required
def create_poll():
    if request.method == 'POST':
        question = request.form['question']
        options = [opt for opt in request.form.getlist('options') if opt.strip()]
        if len(options) < 2:
            flash('Need at least 2 options!', 'error')
            return render('create', 'Create Poll', CREATE_BODY)
        expiration_days = request.form.get('expiration_days', '').strip()
        if expiration_days == '':
            # No expiration specified: default to 2 days.
            expiration = datetime.utcnow() + timedelta(days=2)
        else:
            days = int(expiration_days)
            expiration = datetime.utcnow() + timedelta(days=days) if days > 0 else None
        poll_id = str(uuid.uuid4())[:8]
        poll = Poll(id=poll_id, question=question, expiration_datetime=expiration, user_id=current_user.id)
        db.session.add(poll)
        for opt_text in options:
            option = Option(text=opt_text, poll_id=poll_id)
            db.session.add(option)
        db.session.commit()
        flash('Poll created!', 'success')
        return redirect(url_for('vote', poll_id=poll_id))
    return render('create', 'Create Poll', CREATE_BODY)

@app.route('/delete/<poll_id>', methods=['GET'])
@login_required
def delete(poll_id):
    poll = Poll.query.get_or_404(poll_id)
    if poll.user_id != current_user.id:
        flash('You can only delete your own polls!', 'error')
        return redirect(url_for('home'))
    db.session.delete(poll)
    db.session.commit()
    flash('Poll deleted!', 'success')
    return redirect(url_for('home'))

@app.route('/poll/<poll_id>', methods=['GET', 'POST'])
def vote(poll_id):
    poll = Poll.query.get_or_404(poll_id)
    if poll.expiration_datetime and poll.expiration_datetime < datetime.utcnow():
        flash('This poll has expired!', 'error')
        return redirect(url_for('home'))
    options = poll.options
    client_ip = request.remote_addr
    if Vote.query.filter_by(poll_id=poll_id, voter_ip=client_ip).first():
        return render('vote', 'Vote', VOTE_BODY, question=poll.question, options=options, poll_id=poll_id, error="You already voted!")
    if request.method == 'POST':
        option_id = request.form['vote']
        option = Option.query.get_or_404(option_id)
        if option.poll_id == poll_id:
            new_vote = Vote(poll_id=poll_id, option_id=option_id, voter_ip=client_ip)
            db.session.add(new_vote)
            db.session.commit()
        return redirect(url_for('results', poll_id=poll_id))
    return render('vote', 'Vote', VOTE_BODY, question=poll.question, options=options, poll_id=poll_id, error=None)

@app.route('/results/<poll_id>')
def results(poll_id):
    poll = Poll.query.get_or_404(poll_id)
    if poll.expiration_datetime and poll.expiration_datetime < datetime.utcnow():
        flash('This poll has expired!', 'error')
        return redirect(url_for('home'))
    options = poll.options
    total_votes = sum(len(opt.votes) for opt in options)
    plt.figure(figsize=(6, 4))
    plt.bar([opt.text for opt in options], [len(opt.votes) for opt in options], color='#0E9C8E')
    plt.title(poll.question, fontsize=12, pad=10)
    plt.ylabel('Votes', fontsize=10)
    plt.xticks(rotation=45, ha='right')
    plt.gca().spines['top'].set_visible(False)
    plt.gca().spines['right'].set_visible(False)
    plt.tight_layout()
    img = io.BytesIO()
    plt.savefig(img, format='png', dpi=140)
    img.seek(0)
    chart_url = base64.b64encode(img.getvalue()).decode()
    plt.close()
    return render('results', 'Results', RESULTS_BODY, question=poll.question, total_votes=total_votes, chart=chart_url, options=options, poll_id=poll_id)

if __name__ == '__main__':
    app.run(debug=True)