from flask import Flask, render_template, request, redirect, url_for, session
from flask_bcrypt import Bcrypt
from flask_session import Session
from datetime import datetime, timedelta

# Initialize Flask app
app = Flask(__name__)
app.secret_key = 'your-secret-key'
bcrypt = Bcrypt(app)

# Session configuration
app.config['SESSION_TYPE'] = 'filesystem'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
Session(app)

# Task storage (In-memory for simplicity)
tasks = []

# Index route (Displays tasks if logged in)
@app.route('/')
def index():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('index.html', tasks=session.get('tasks', []), username=session['username'])

# Add a task
@app.route('/add', methods=['POST'])
def add_task():
    if 'username' not in session:
        return redirect(url_for('login'))

    task = request.form.get('task')
    if task:
        # Get the current date and time
        current_time = datetime.now()
        task_info = {
            'task': task,
            'username': session['username'],  # Add username to the task
            'date': current_time.strftime('%Y-%m-%d'),
            'time': current_time.strftime('%H:%M:%S'),
            'day': current_time.strftime('%A')  # Get the full weekday name
        }
        
        # Save tasks in session instead of a database
        if 'tasks' not in session:
            session['tasks'] = []
        session['tasks'].append(task_info)
    return redirect(url_for('index'))

# Remove a task
@app.route('/remove/<int:task_id>')
def remove_task(task_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    if 0 <= task_id < len(session.get('tasks', [])):
        session['tasks'].pop(task_id)
    return redirect(url_for('index'))

# Registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if password != confirm_password:
            error = "Passwords do not match."
        elif username in [user['username'] for user in session.get('users', [])]:
            error = "Username already exists."
        else:
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            new_user = {'username': username, 'password': hashed_password}
            if 'users' not in session:
                session['users'] = []
            session['users'].append(new_user)
            return redirect(url_for('login'))

    return render_template('register.html', error=error)

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = next((user for user in session.get('users', []) if user['username'] == username), None)
        if user and bcrypt.check_password_hash(user['password'], password):
            session['username'] = username
            return redirect(url_for('index'))
        else:
            error = "Invalid username or password."

    return render_template('login.html', error=error)

# Logout route
@app.route('/logout')
def logout():
    session.pop('username', None)  # Remove session data
    session.pop('tasks', None)  # Clear tasks from session when logging out
    return redirect(url_for('login'))

if __name__ == "__main__":
    app.run(debug=True)
