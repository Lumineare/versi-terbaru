from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_bcrypt import Bcrypt
from datetime import datetime

# Initialize Flask app
app = Flask(__name__)
app.secret_key = 'your-secret-key'
bcrypt = Bcrypt(app)

# Hardcoded admin credentials
admin_username = 'admin'
admin_password = '123'
hashed_admin_password = bcrypt.generate_password_hash(admin_password).decode('utf-8')

# Hardcoded user name and to-do list data
tasks = []  # Store tasks in memory (this will reset on every app restart)

# Index route
@app.route('/')
def index():
    if 'username' not in session:
        return redirect(url_for('login'))

    # If user has no name set, prompt them to enter their name
    if 'user_name' not in session:
        return redirect(url_for('set_name'))

    return render_template('index.html', tasks=tasks, username=session['username'], user_name=session['user_name'])

# Add a task (AJAX)
@app.route('/add', methods=['POST'])
def add_task():
    if 'username' not in session:
        return redirect(url_for('login'))

    task_name = request.form['task']
    if task_name:
        current_time = datetime.now()
        task_info = {
            'task': task_name,
            'date': current_time.strftime('%Y-%m-%d'),
            'time': current_time.strftime('%H:%M:%S'),
            'day': current_time.strftime('%A'),
            'created_by': session['user_name']
        }
        tasks.append(task_info)  # Add task to the in-memory list

    return jsonify(success=True)

# Remove a task (AJAX)
@app.route('/remove/<int:task_id>', methods=['POST'])
def remove_task(task_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    # Only admin can delete any task, others can only delete their own tasks
    if session['username'] == admin_username or tasks[task_id]['created_by'] == session['user_name']:
        if 0 <= task_id < len(tasks):
            tasks.pop(task_id)  # Remove task from the in-memory list

    return jsonify(success=True)

# Registration route (hardcoded to allow only 'admin' with password '123')
@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if username != admin_username:
            error = "Only 'admin' is allowed as a username."
        elif password != confirm_password:
            error = "Passwords do not match."
        else:
            # Automatically register the admin account (password is checked directly)
            if bcrypt.check_password_hash(hashed_admin_password, password):
                session['username'] = username
                return redirect(url_for('set_name'))  # After registering, go to set name
            else:
                error = "Invalid credentials."

    return render_template('register.html', error=error)

# Login route (hardcoded for 'admin' and password '123')
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Check for hardcoded admin credentials
        if username == admin_username and bcrypt.check_password_hash(hashed_admin_password, password):
            session['username'] = username
            return redirect(url_for('set_name'))  # After login, go to set name
        else:
            error = "Invalid username or password."

    return render_template('login.html', error=error)

# Set name route (user sets their name after login)
@app.route('/set_name', methods=['GET', 'POST'])
def set_name():
    if 'username' not in session:
        return redirect(url_for('login'))

    if 'user_name' in session:
        return redirect(url_for('index'))

    error = None
    if request.method == 'POST':
        user_name = request.form.get('user_name')
        if user_name:
            session['user_name'] = user_name  # Store the user's name in the session
            return redirect(url_for('index'))
        else:
            error = "Please enter your name."

    return render_template('set_name.html', error=error)

# Logout route
@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('user_name', None)
    return redirect(url_for('login'))

if __name__ == "__main__":
    app.run(debug=True)
