from flask import Flask, request, render_template_string, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
import uuid
import matplotlib.pyplot as plt
import io
import base64

app = Flask(__name__)

# Configure PostgreSQL database (update URI after Render setup)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://user:password@host:port/dbname'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Database models
class Poll(db.Model):
    id = db.Column(db.String(8), primary_key=True)
    question = db.Column(db.String(200), nullable=False)
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
    voter_ip = db.Column(db.String(45), nullable=False)  # Supports IPv4/IPv6

# HTML templates with Tailwind CSS
HOME_TEMPLATE = '''
<!doctype html>
<html>
<head>
  <title>Simple Polls</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-100 min-h-screen flex flex-col">
  <nav class="bg-blue-600 text-white p-4">
    <div class="container mx-auto flex justify-between items-center">
      <h1 class="text-xl font-bold">Simple Polls</h1>
      <a href="/create" class="hover:underline">Create Poll</a>
    </div>
  </nav>
  <div class="container mx-auto p-4 flex-grow">
    <h2 class="text-2xl font-semibold mb-4 text-center">Active Polls</h2>
    {% if polls %}
      <div class="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
        {% for poll in polls %}
          <div class="bg-white p-4 rounded-lg shadow-md">
            <h3 class="text-lg font-medium mb-2">{{ poll.question }}</h3>
            <div class="space-y-2">
              <a href="/poll/{{ poll.id }}" class="block text-blue-600 hover:underline">Vote</a>
              <a href="/results/{{ poll.id }}" class="block text-blue-600 hover:underline">View Results</a>
            </div>
          </div>
        {% endfor %}
      </div>
    {% else %}
      <p class="text-center text-gray-600">No polls available. <a href="/create" class="text-blue-600 hover:underline">Create one!</a></p>
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
  <nav class="bg-blue-600 text-white p-4">
    <div class="container mx-auto flex justify-between items-center">
      <h1 class="text-xl font-bold">Simple Polls</h1>
      <a href="/" class="hover:underline">Home</a>
    </div>
  </nav>
  <div class="container mx-auto p-4 flex-grow flex items-center justify-center">
    <div class="bg-white p-6 rounded-lg shadow-md w-full max-w-md">
      <h2 class="text-2xl font-semibold mb-4 text-center">Create a Poll</h2>
      {% if error %}
        <p class="text-red-500 mb-4">{{ error }}</p>
      {% endif %}
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
        <button type="submit" class="w-full bg-blue-600 text-white py-2 rounded-md hover:bg-blue-700 transition">Create Poll</button>
      </form>
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
  <nav class="bg-blue-600 text-white p-4">
    <div class="container mx-auto flex justify-between items-center">
      <h1 class="text-xl font-bold">Simple Polls</h1>
      <a href="/" class="hover:underline">Home</a>
    </div>
  </nav>
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
  <nav class="bg-blue-600 text-white p-4">
    <div class="container mx-auto flex justify-between items-center">
      <h1 class="text-xl font-bold">Simple Polls</h1>
      <a href="/" class="hover:underline">Home</a>
    </div>
  </nav>
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
    polls = Poll.query.all()
    return render_template_string(HOME_TEMPLATE, polls=polls)

@app.route('/create', methods=['GET', 'POST'])
def create_poll():
    if request.method == 'POST':
        question = request.form['question']
        options = [opt for opt in request.form.getlist('options') if opt.strip()]
        if len(options) < 2:
            return render_template_string(CREATE_TEMPLATE, error="Need at least 2 options!")
        poll_id = str(uuid.uuid4())[:8]
        poll = Poll(id=poll_id, question=question)
        db.session.add(poll)
        for opt_text in options:
            option = Option(text=opt_text, poll_id=poll_id)
            db.session.add(option)
        db.session.commit()
        return redirect(url_for('vote', poll_id=poll_id))
    return render_template_string(CREATE_TEMPLATE)

@app.route('/poll/<poll_id>', methods=['GET', 'POST'])
def vote(poll_id):
    poll = Poll.query.get_or_404(poll_id)
    options = poll.options
    client_ip = request.remote_addr
    if Vote.query.filter_by(poll_id=poll_id, voter_ip=client_ip).first():
        return render_template_string(VOTE_TEMPLATE, question=poll.question, options=options, poll_id=poll_id, error="You already voted!")
    if request.method == 'POST':
        option_id = request.form['vote']
        option = Option.query.get_or_404(option_id)
        if option.poll_id == poll_id:
            vote = Vote(poll_id=poll_id, option_id=option_id, voter_ip=client_ip)
            db.session.add(vote)
            db.session.commit()
        return redirect(url_for('results', poll_id=poll_id))
    return render_template_string(VOTE_TEMPLATE, question=poll.question, options=options, poll_id=poll_id)

@app.route('/results/<poll_id>')
def results(poll_id):
    poll = Poll.query.get_or_404(poll_id)
    options = poll.options
    total_votes = sum(len(opt.votes) for opt in options)

    # Generate chart
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

    return render_template_string(RESULTS_TEMPLATE, question=poll.question, total_votes=total_votes, chart=chart_url, options=options, poll_id=poll_id)

if __name__ == '__main__':
    app.run(debug=True)