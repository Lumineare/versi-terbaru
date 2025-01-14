from flask import Flask, render_template, request, redirect, url_for, session
from flask_bcrypt import Bcrypt
from datetime import datetime, timedelta

# Initialize Flask app
app = Flask(__name__)
app.secret_key = 'your-secret-key'
bcrypt = Bcrypt(app)

# Session configuration
app.config['SESSION_TYPE'] = 'filesystem'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

# Hardcoded admin credentials
admin_username = 'admin'
admin_password = '123'

# Hash the admin password
hashed_admin_password = bcrypt.generate_password_hash(admin_password).decode('utf-8')

# Index route
@app.route('/')
def index():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    # Retrieve tasks from session (instead of Redis)
    task_list = session.get('tasks', [])  # Default to empty list if no tasks are stored
    return render_template('index.html', tasks=task_list, username=session['username'])

# Add a task
@app.route('/add', methods=['POST'])
def add_task():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    task = request.form.get('task')
    if task:
        current_time = datetime.now()
        task_info = {
            'task': task,
            'date': current_time.strftime('%Y-%m-%d'),
            'time': current_time.strftime('%H:%M:%S'),
            'day': current_time.strftime('%A'),
            'created_by': session['username']  # Store who created the task
        }
        
        # Retrieve tasks from session and add the new task
        task_list = session.get('tasks', [])
        task_list.append(task_info)
        session['tasks'] = task_list  # Save updated task list to session
        
    return redirect(url_for('index'))

# Remove a task
@app.route('/remove/<int:task_id>')
def remove_task(task_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    
    task_list = session.get('tasks', [])
    
    # Ensure only admin can delete any task or the creator can delete their own task
    if session['username'] == admin_username or task_list[task_id]['created_by'] == session['username']:
        if 0 <= task_id < len(task_list):
            task_list.pop(task_id)  # Remove the task at the specified index
            session['tasks'] = task_list  # Save updated task list to session
    else:
        # Redirect to the index page with a message if a user tries to delete a task they don't own
        return redirect(url_for('index', error="You are not authorized to delete this task."))
    
    return redirect(url_for('index'))

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
            if username == admin_username and bcrypt.check_password_hash(hashed_admin_password, password):
                session['username'] = username
                # Redirect to name input if username is admin
                return redirect(url_for('set_name'))
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
            # If no name is set in session, prompt to set name
            if 'name' not in session:
                return redirect(url_for('set_name'))
            return redirect(url_for('index'))
        else:
            error = "Invalid username or password."
    
    return render_template('login.html', error=error)

# Route to set user name after login
@app.route('/set_name', methods=['GET', 'POST'])
def set_name():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    error = None
    if request.method == 'POST':
        user_name = request.form.get('name')
        if user_name:
            session['name'] = user_name  # Store the name in session
            return redirect(url_for('index'))
        else:
            error = "Name cannot be empty."
    
    return render_template('set_name.html', error=error)

# Logout route
@app.route('/logout')
def logout():
    session.pop('username', None)  # Remove session data
    session.pop('name', None)       # Clear the name from session as well
    return redirect(url_for('login'))

if __name__ == "__main__":
    app.run(debug=True)
