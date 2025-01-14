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
    
    # Retrieve tasks (in this case, we can keep it hardcoded as well or mock tasks)
    task_list = []  # Example: A list of hardcoded tasks (could be empty or customized)
    return render_template('index.html', tasks=task_list, username=session['username'])

# Add a task
@app.route('/add', methods=['POST'])
def add_task():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    task = request.form.get('task')
    if task:
        # Add task logic (could save to a list or session instead of Redis)
        pass
    return redirect(url_for('index'))

# Remove a task
@app.route('/remove/<int:task_id>')
def remove_task(task_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    
    # Remove task logic (could be from a list or session)
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
                return redirect(url_for('index'))
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
            return redirect(url_for('index'))
        else:
            error = "Invalid username or password."
    
    return render_template('login.html', error=error)

# Logout route
@app.route('/logout')
def logout():
    session.pop('username', None)  # Remove session data
    return redirect(url_for('login'))

if __name__ == "__main__":
    app.run(debug=True)
