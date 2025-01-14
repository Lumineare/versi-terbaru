from flask import Flask, render_template, request, redirect, url_for, session
from flask_bcrypt import Bcrypt
from flask_session import Session
from datetime import datetime, timedelta
import os
import redis

# Initialize Flask app
app = Flask(__name__)
app.secret_key = 'your-secret-key'
bcrypt = Bcrypt(app)

# Session configuration
app.config['SESSION_TYPE'] = 'filesystem'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
Session(app)

# Redis Configuration
redis_client = redis.StrictRedis(
    host=os.environ.get('REDIS_HOST'),  # Redis host from environment variable
    port=6379,  # Default Redis port
    password=os.environ.get('REDIS_PASSWORD'),
    decode_responses=True
)

# Verify Redis connection at app startup
try:
    redis_client.ping()  # Verify Redis connection
except redis.exceptions.ConnectionError as e:
    print(f"Redis connection error: {e}")
    error = "Failed to connect to Redis."
    # You can handle this error by rendering an error page or logging it
    # return render_template('error.html', error=error)

# Ensure 'admin' account exists when the app starts
@app.before_first_request
def ensure_admin_account():
    admin_username = "admin"
    admin_password = "123"
    
    # Check if 'admin' already exists in Redis
    if not redis_client.exists(f"user:{admin_username}"):
        # Create hashed password for admin
        hashed_password = bcrypt.generate_password_hash(admin_password).decode('utf-8')
        # Save 'admin' user to Redis
        redis_client.set(f"user:{admin_username}", hashed_password)
        print(f"Admin account created with username: {admin_username}")

# Index route
@app.route('/')
def index():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    # Retrieve tasks from Redis
    task_list = redis_client.lrange(f"tasks:{session['username']}", 0, -1)
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
            'day': current_time.strftime('%A')
        }
        # Store task in Redis under the username key
        redis_client.rpush(f"tasks:{session['username']}", str(task_info))
    return redirect(url_for('index'))

# Remove a task
@app.route('/remove/<int:task_id>')
def remove_task(task_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    
    task_key = f"tasks:{session['username']}"
    task_list = redis_client.lrange(task_key, 0, -1)
    if 0 <= task_id < len(task_list):
        redis_client.lrem(task_key, 1, task_list[task_id])  # Remove specific task
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
        elif redis_client.exists(f"user:{username}"):
            error = "Username already exists."
        else:
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            redis_client.set(f"user:{username}", hashed_password)
            return redirect(url_for('login'))
    
    return render_template('register.html', error=error)

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        stored_password = redis_client.get(f"user:{username}")
        if stored_password and bcrypt.check_password_hash(stored_password, password):
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
