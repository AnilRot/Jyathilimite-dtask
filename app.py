from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import secrets
import time
import re

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# Rate limiting setup
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# In-memory "database" for demonstration
users_db = {}

# Security configurations
MAX_LOGIN_ATTEMPTS = 3
LOCKOUT_TIME = 300  # 5 minutes in seconds

@app.route('/')
def index():
    return render_template('login.html')

@app.route('/register', methods=['POST'])
def register():
    email = request.form.get('email')
    password = request.form.get('password')
    confirm_password = request.form.get('confirm_password')

    # Input validation
    if not all([email, password, confirm_password]):
        flash('All fields are required', 'error')
        return redirect(url_for('index'))

    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        flash('Invalid email format', 'error')
        return redirect(url_for('index'))

    if password != confirm_password:
        flash('Passwords do not match', 'error')
        return redirect(url_for('index'))

    if len(password) < 8:
        flash('Password must be at least 8 characters', 'error')
        return redirect(url_for('index'))

    if email in users_db:
        flash('Email already registered', 'error')
        return redirect(url_for('index'))

    # Hash password
    hashed_password = generate_password_hash(
        password,
        method='pbkdf2:sha256',
        salt_length=16
    )

    # Store user
    users_db[email] = {
        'password_hash': hashed_password,
        'login_attempts': 0,
        'last_attempt': 0,
        'locked': False
    }

    flash('Registration successful! Please login.', 'success')
    return redirect(url_for('index'))

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    email = request.form.get('email')
    password = request.form.get('password')

    # Basic validation
    if not email or not password:
        flash('Email and password are required', 'error')
        return redirect(url_for('index'))

    # Check if user exists
    user = users_db.get(email)
    if not user:
        time.sleep(1)  # Prevent timing attacks
        flash('Invalid credentials', 'error')
        return redirect(url_for('index'))

    # Check if account is locked
    current_time = time.time()
    if user['locked'] and (current_time - user['last_attempt']) < LOCKOUT_TIME:
        flash('Account temporarily locked. Try again later.', 'error')
        return redirect(url_for('index'))
    elif user['locked'] and (current_time - user['last_attempt']) >= LOCKOUT_TIME:
        user['locked'] = False
        user['login_attempts'] = 0

    # Verify password
    if check_password_hash(user['password_hash'], password):
        # Successful login
        user['login_attempts'] = 0
        session['user_email'] = email
        flash('Login successful!', 'success')
        return redirect(url_for('index'))
    else:
        # Failed login
        user['login_attempts'] += 1
        user['last_attempt'] = current_time
        
        if user['login_attempts'] >= MAX_LOGIN_ATTEMPTS:
            user['locked'] = True
            flash('Account locked due to too many failed attempts. Try again later.', 'error')
        else:
            flash('Invalid credentials', 'error')
        
        return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)