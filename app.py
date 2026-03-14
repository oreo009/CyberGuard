from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import logging
import os
from ai.decision import decide_action

app = Flask(__name__)
#app.secret_key = 'your_secret_key_here'  # Change this in production

# Database setup
def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE,
                    password TEXT
                )''')
    # Insert default user if not exists
    c.execute("INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)", ('admin', 'admin123'))
    conn.commit()
    conn.close()

# Logging setup
if not os.path.exists('logs'):
    os.makedirs('logs')
security_logger = logging.getLogger('security')
security_logger.setLevel(logging.INFO)
handler = logging.FileHandler('logs/security.log', encoding='utf-8')
handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
security_logger.addHandler(handler)

# Test log
security_logger.info('App started')

# Threat score global (in real app, use database or session)
threat_score = 0

def detect_sql_injection(input_str):
    """Detect SQL injection patterns"""
    sql_patterns = ["'", "OR", "UNION", "SELECT", "--", "/*", "*/"]
    return any(pattern in input_str.upper() for pattern in sql_patterns)

def detect_brute_force(threat_score):
    """Detect brute force based on threat score"""
    return threat_score >= 5

def detect_dos(threat_score):
    """Detect DoS based on threat score"""
    return threat_score >= 10

@app.route('/', methods=['GET', 'POST'])
def login():
    global threat_score
    ip = request.remote_addr
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check for SQL injection patterns
        if detect_sql_injection(username) or detect_sql_injection(password):
            print("SQL injection detected for", username, password)
            security_logger.info(f'SQL_INJECTION_ATTEMPT from {ip}')
            threat_score += 5
            action = decide_action(threat_score)
            security_logger.info(f'AI_RESPONSE for {ip}: {action}')
            flash(f'SQL Injection detected! AI Response: {action}')
            return redirect(url_for('login'))

        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
        user = c.fetchone()
        conn.close()

        if user:
            session['username'] = username
            security_logger.info(f'SUCCESS LOGIN from {ip}')
            threat_score = 0  # Reset on successful login
            return redirect(url_for('dashboard'))
        else:
            security_logger.info(f'FAILED LOGIN from {ip}')
            threat_score += 1
            # Check for brute force
            if detect_brute_force(threat_score):
                security_logger.info(f'BRUTE_FORCE_SUSPECTED from {ip}')
                action = decide_action(threat_score)
                security_logger.info(f'AI RESPONSE for {ip}: {action}')
                flash(f'Brute Force suspected! AI Response: {action}')
            else:
                flash('Invalid credentials')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html', username=session['username'])

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if 'username' not in session:
        return redirect(url_for('login'))
    ip = request.remote_addr
    if request.method == 'POST':
        file = request.files['file']
        if file:
            filename = file.filename
            security_logger.info(f'UPLOAD_ATTEMPT {filename} from {ip}')
            # Simulate DoS by checking request count (simplified)
            global threat_score
            threat_score += 1
            if detect_dos(threat_score):
                security_logger.info(f'DOS_ATTACK from {ip}')
                action = decide_action(threat_score)
                security_logger.info(f'AI RESPONSE for {ip}: {action}')
                flash(f'DoS suspected! AI Response: {action}')
            else:
                flash('File uploaded successfully')
        return redirect(url_for('upload'))
    return render_template('upload.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)