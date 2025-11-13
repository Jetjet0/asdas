from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3
import os
from datetime import datetime

# -----------------------------
# Flask app setup
# -----------------------------
app = Flask(__name__)
app.secret_key = 'abella_secret_key'
app.config['PERMANENT_SESSION_LIFETIME'] = 1800  # 30 minutes

# -----------------------------
# The SQLite database configuration
# -----------------------------
DATABASE = 'abella_travel.db'


def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def is_valid_email(email):
    return '@' in email and '.' in email


def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            address TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS contact_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            message TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    conn.commit()
    conn.close()


# -----------------------------
# ROOT → ALWAYS SHOW LOGIN FIRST
# -----------------------------
@app.route('/')
def root():
    return redirect(url_for('login'))


# -----------------------------
# Login (FIRST PAGE)
# -----------------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()

        if not email or not password:
            flash('Please fill in both email and password!', 'error')
            return render_template('login.html')

        conn = get_db_connection()
        account = conn.execute(
            'SELECT * FROM users WHERE email = ? AND password = ?',
            (email, password)
        ).fetchone()
        conn.close()

        if account:
            session['logged_in'] = True
            session['id'] = account['id']
            session['username'] = account['username']
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Incorrect email or password.', 'error')

    return render_template('login.html')


# -----------------------------
# Signup / Register
# -----------------------------
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()

        if not all([username, email, password]):
            flash('Please fill out all fields!', 'error')
            return render_template('signup.html')

        if len(password) < 6:
            flash('Password must be at least 6 characters long!', 'error')
            return render_template('signup.html')

        if not is_valid_email(email):
            flash('Please enter a valid email address!', 'error')
            return render_template('signup.html')

        conn = get_db_connection()
        existing_user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()

        if existing_user:
            flash('Account already exists with this email!', 'error')
            conn.close()
            return render_template('signup.html')

        try:
            conn.execute(
                'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
                (username, email, password)
            )
            conn.commit()
            conn.close()
            flash('You have successfully registered! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Registration failed. Email already exists.', 'error')
            conn.close()

    return render_template('signup.html')


# -----------------------------
# Update Profile
# -----------------------------
@app.route('/update_profile', methods=['GET', 'POST'])
def update_profile():
    if 'logged_in' not in session:
        flash('Please log in to access this page.', 'error')
        return redirect(url_for('login'))

    user_id = session['id']

    if request.method == 'POST':
        new_username = request.form.get('username', '').strip()
        new_address = request.form.get('address', '').strip()
        new_password = request.form.get('password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()

        if not new_username:
            flash('Username cannot be empty!', 'error')
            return redirect(url_for('update_profile'))

        # Check if passwords match (if user wants to change password)
        if new_password:
            if new_password != confirm_password:
                flash('Passwords do not match!', 'error')
                return redirect(url_for('update_profile'))
            if len(new_password) < 6:
                flash('Password must be at least 6 characters long!', 'error')
                return redirect(url_for('update_profile'))

        conn = get_db_connection()

        try:
            # Update username and address
            if new_password:
                conn.execute(
                    'UPDATE users SET username = ?, address = ?, password = ? WHERE id = ?',
                    (new_username, new_address, new_password, user_id)
                )
            else:
                conn.execute(
                    'UPDATE users SET username = ?, address = ? WHERE id = ?',
                    (new_username, new_address, user_id)
                )

            conn.commit()
            conn.close()

            # Update session username
            session['username'] = new_username

            flash('Profile updated successfully!', 'success')
            return redirect(url_for('update_profile'))

        except Exception as e:
            flash('An error occurred while updating your profile.', 'error')
            conn.close()
            return redirect(url_for('update_profile'))

    # GET request - fetch current user data
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()

    return render_template('update.html',
                           current_username=user['username'],
                           current_email=user['email'],
                           current_address=user['address'])


# -----------------------------
# Delete Account
# -----------------------------
@app.route('/delete_account', methods=['POST'])
def delete_account():
    if 'logged_in' not in session:
        flash('Please log in to access this page.', 'error')
        return redirect(url_for('login'))

    user_id = session['id']

    conn = get_db_connection()
    conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()

    session.clear()
    flash('Your account has been deleted successfully.', 'success')
    return redirect(url_for('signup'))


# -----------------------------
# Logout
# -----------------------------
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))


# -----------------------------
# Home Page (after login)
# -----------------------------
@app.route('/index')
def index():
    if 'logged_in' not in session:
        flash('Please log in to access the site.', 'error')
        return redirect(url_for('login'))
    return render_template('index.html', username=session['username'])


# -----------------------------
# About Page (Public)
# -----------------------------
@app.route('/about')
def about():
    return render_template('about.html')


# -----------------------------
# Contact Page (Public)
# -----------------------------
@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        message = request.form.get('message', '').strip()

        if not all([name, email, message]):
            flash('Please fill out all fields!', 'error')
            return render_template('contact.html')

        if not is_valid_email(email):
            flash('Please enter a valid email address!', 'error')
            return render_template('contact.html')

        conn = get_db_connection()
        conn.execute(
            'INSERT INTO contact_messages (name, email, message) VALUES (?, ?, ?)',
            (name, email, message)
        )
        conn.commit()
        conn.close()

        flash('Thank you for your message! We will get back to you soon.', 'success')
        return redirect(url_for('contact'))

    return render_template('contact.html')


# -----------------------------
# PROTECTED PAGES (Require Login)
# -----------------------------
@app.route('/destinations')
def destinations():
    if 'logged_in' not in session:
        flash('Please log in to view this page.', 'error')
        return redirect(url_for('login'))
    return render_template('destinations.html', username=session.get('username'))


@app.route('/local')
def local():
    if 'logged_in' not in session:
        flash('Please log in to view this page.', 'error')
        return redirect(url_for('login'))
    return render_template('local.html', username=session['username'])


@app.route('/guide')
def guide():
    if 'logged_in' not in session:
        flash('Please log in to view this page.', 'error')
        return redirect(url_for('login'))
    return render_template('guide.html', username=session['username'])


@app.route('/try')
def try_page():
    if 'logged_in' not in session:
        flash('Please log in to view this page.', 'error')
        return redirect(url_for('login'))
    return render_template('try.html', username=session['username'])


# -----------------------------
# NEW: Naga Tour Page
# -----------------------------
@app.route('/nagatour')
def nagatour():
    if 'logged_in' not in session:
        flash('Please log in to view this page.', 'error')
        return redirect(url_for('login'))

    # Get user's address from database
    conn = get_db_connection()
    user = conn.execute('SELECT address FROM users WHERE id = ?', (session['id'],)).fetchone()
    conn.close()

    user_address = user['address'] if user and user['address'] else None
    return render_template('nagatour.html', username=session['username'], user_address=user_address)


# -----------------------------
# NEW: Minglanilla Tour Page
# -----------------------------
@app.route('/mingtour')
def mingtour():
    if 'logged_in' not in session:
        flash('Please log in to view this page.', 'error')
        return redirect(url_for('login'))

    # Get user's address from database
    conn = get_db_connection()
    user = conn.execute('SELECT address FROM users WHERE id = ?', (session['id'],)).fetchone()
    conn.close()

    user_address = user['address'] if user and user['address'] else None
    return render_template('mingtour.html', username=session['username'], user_address=user_address)


# -----------------------------
# NEW: Inayagan Tour Page
# -----------------------------
@app.route('/inayagantour')
def inayagantour():
    if 'logged_in' not in session:
        flash('Please log in to view this page.', 'error')
        return redirect(url_for('login'))

    # Get user's address from database
    conn = get_db_connection()
    user = conn.execute('SELECT address FROM users WHERE id = ?', (session['id'],)).fetchone()
    conn.close()

    user_address = user['address'] if user and user['address'] else None
    return render_template('inayagantour.html', username=session['username'], user_address=user_address)


# -----------------------------
# Error Handlers
# -----------------------------
@app.errorhandler(404)
def not_found(error):
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500


# -----------------------------
# Initialize and Run
# -----------------------------
if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)