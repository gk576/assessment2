import os
import sqlite3
import hashlib
import datetime
import random
from flask import Flask, request, render_template, flash, session, redirect, url_for, jsonify
from functools import wraps

app = Flask(__name__)
# Configure session to store data on the server filesystem
app.config['SESSION_TYPE'] = 'filesystem'
# Secret key is required for session security and flash messages
app.secret_key = "super_secret_key_change_this_in_production"

# --- Database setup ---
def get_db_conn():
    db = sqlite3.connect('crm.db')
    # Row factory allows accessing columns by name instead of index
    db.row_factory = sqlite3.Row
    return db

def initialize_db():
    db = get_db_conn()
    cursor = db.cursor()
    # Enable foreign key constraints for relational integrity
    cursor.execute("PRAGMA foreign_keys=ON")

    # Users table, storing login info and roles
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            uid INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            salt TEXT NOT NULL,
            role TEXT DEFAULT 'employee',
            phone TEXT DEFAULT '+30 0000000000',
            is_active INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Customers Table, stores client data linked to the employee who created them
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS customers (
            cid INTEGER PRIMARY KEY AUTOINCREMENT,
            created_by_user_id INTEGER,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            email TEXT NOT NULL,
            phone TEXT,
            status TEXT DEFAULT 'Active', 
            interaction_date DATE DEFAULT CURRENT_DATE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Interactions table: stores logs for the charts/reports
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS interactions (
            interaction_id INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_id INTEGER,
            user_id INTEGER,
            type TEXT,
            interaction_date DATE,
            notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # We create a secure hash for the default password 'password123'
    # This ensures even default accounts follow security protocols
    default_salt = os.urandom(32).hex()
    default_pw_hash = hashlib.pbkdf2_hmac(
        'sha256', 
        'password123'.encode('utf-8'), 
        bytes.fromhex(default_salt), 
        100000
    ).hex()

    # Admin account (checks if exists, otherwise creates it)
    if not cursor.execute("SELECT * FROM users WHERE username='admin'").fetchone():
        cursor.execute("INSERT INTO users (username, email, password, salt, role) VALUES (?, ?, ?, ?, ?)", 
                       ("admin", "admin@crm.com", default_pw_hash, default_salt, "admin"))

    # Manager account
    if not cursor.execute("SELECT * FROM users WHERE username='manager'").fetchone():
        cursor.execute("INSERT INTO users (username, email, password, salt, role) VALUES (?, ?, ?, ?, ?)", 
                       ("manager", "manager@crm.com", default_pw_hash, default_salt, "manager"))

    # Employee account
    if not cursor.execute("SELECT * FROM users WHERE username='employee'").fetchone():
        cursor.execute("INSERT INTO users (username, email, password, salt, role) VALUES (?, ?, ?, ?, ?)", 
                       ("employee", "employee@crm.com", default_pw_hash, default_salt, "employee"))
    
    # Extra employees (for the manager dashboard)
    extra_employees = [
        ("Robert Johnson", "rjohnson@email.com"), ("Max Payne", "mpayne@email.com"),
        ("Sandra Smith", "ssmith@email.com"), ("John Walsh", "jwalsh@email.com"),
        ("Kevin Fletcher", "kfletcher@email.com"), ("Joel Moore", "jmoore@email.com"),
        ("Nathan Wright", "nwright@email.com")
    ]
    for name, email in extra_employees:
        if not cursor.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone():
             cursor.execute("INSERT INTO users (username, email, password, salt, role) VALUES (?, ?, ?, ?, ?)", 
                           (name, email, default_pw_hash, default_salt, "employee"))

    # Customers
    if not cursor.execute("SELECT * FROM customers").fetchone():
        customers = [
            ("John", "Doe", "27/11/2025"), ("Adam", "Smith", "20/11/2025"),
            ("Tyler", "Durden", "16/11/2025"), ("Emma", "Jones", "14/11/2025"),
            ("Gerry", "Miller", "11/11/2025"), ("James", "Brown", "9/11/2025"),
            ("Harry", "Johnson", "4/11/2025")
        ]
        for f, l, d in customers:
            date_obj = datetime.datetime.strptime(d, "%d/%m/%Y").date()
            cursor.execute("INSERT INTO customers (first_name, last_name, email, interaction_date) VALUES (?, ?, ?, ?)", 
                           (f, l, f"{f.lower()}@mail.com", date_obj))

    db.commit()
    db.close()

# --- Security Functions ---
# Verifies the password using salt + hash
def check_password(stored_password, stored_salt, provided_password):
    key = hashlib.pbkdf2_hmac('sha256', provided_password.encode('utf-8'), bytes.fromhex(stored_salt), 100000)
    return key.hex() == stored_password

# --- Decorators ---
# Custom decorator to handle role based access
def roles_permitted(roles):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            # Check if user is logged in and has the correct role
            if 'uid' in session and session.get('role') in roles:
                return f(*args, **kwargs)
            elif 'uid' not in session:
                return redirect('/login')
            else:
                flash(f'Access Denied.')
                return redirect('/')
        return wrapper
    return decorator

# --- Routes ---

@app.route('/')
def index():
    return render_template('select_user.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    role_preselect = request.args.get('role', 'employee')
    
    if request.method == 'POST':
        # Get the input
        user_input = request.form.get('email') 
        password = request.form.get('password')
        remember = request.form.get('remember')
        
        db = get_db_conn()
        
        user = db.execute("SELECT * FROM users WHERE email=? OR username=?", (user_input, user_input)).fetchone()
        
        # Validate user and password hash
        if user and check_password(user['password'], user['salt'], password):
            if user['is_active'] == 0:
                flash("Your account has been deactivated.")
                return render_template('login.html', role=role_preselect)
            
            # Create session
            session['uid'] = user['uid']
            session['username'] = user['username']
            session['role'] = user['role']
            
            # "Remember Me" checkbox
            if remember:
                session.permanent = True
                app.permanent_session_lifetime = datetime.timedelta(days=7) # Login lasts 7 days
            else:
                session.permanent = False
            
            # Redirect based on role
            if user['role'] == 'employee': return redirect('/employee')
            elif user['role'] == 'manager': return redirect('/manager')
            elif user['role'] == 'admin': return redirect('/admin')
        else:
            flash("Invalid credentials")
            
    return render_template('login.html', role=role_preselect)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        db = get_db_conn()
        existing_user = db.execute("SELECT * FROM users WHERE email=? OR username=?", (email, username)).fetchone()
        
        if existing_user:
            flash("Username or Email already taken.")
        else:
            # Hash new password before storing
            salt = os.urandom(32).hex()
            pw_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), bytes.fromhex(salt), 100000).hex()
            db.execute("INSERT INTO users (username, email, password, salt, role) VALUES (?, ?, ?, ?, ?)",
                       (username, email, pw_hash, salt, 'employee'))
            db.commit()
            flash("Registration successful! Please sign in.")
            return redirect('/login')

    return render_template('register.html')

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        flash(f"If an account exists for {email}, a reset link has been sent to your inbox.")
        return redirect('/login')
    return render_template('forgot_password.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

# --- Employee Routes ---
@app.route('/employee')
@roles_permitted(['employee']) # Only employees can access
def employee_dashboard():
    db = get_db_conn()
    
    # Stats logic
    try:
        new_customers = db.execute("SELECT count(*) FROM customers WHERE created_by_user_id=? AND created_at >= date('now','-7 days')", (session['uid'],)).fetchone()[0]
        total_active = db.execute("SELECT count(*) FROM customers WHERE status='Active'").fetchone()[0]
        total_interactions = db.execute("SELECT count(*) FROM interactions WHERE user_id=?", (session['uid'],)).fetchone()[0]
    except:
        new_customers = 0
        total_active = 0
        total_interactions = 0

    # Data for chart.js (calculate weekly activity)
    chart_labels = []
    chart_data = []
    today = datetime.date.today()
    has_data = False
    
    for i in range(5):
        day = today - datetime.timedelta(days=i)
        try:
            count = db.execute("SELECT count(*) FROM interactions WHERE interaction_date = ?", (day,)).fetchone()[0]
        except:
            count = 0
        if count > 0: has_data = True
        chart_labels.append(day.strftime("%A")) 
        chart_data.append(count)
    
    if not has_data:
        final_days = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday']
        final_data = [50, 110, 80, 150, 180]
    else:
        final_days = chart_labels[::-1]
        final_data = chart_data[::-1]

    return render_template('employee_dashboard.html', 
                           new_customers=new_customers, 
                           total_active=total_active,
                           total_interactions=total_interactions,
                           days=final_days, 
                           chart_data=final_data)

@app.route('/reports')
@roles_permitted(['employee', 'manager'])
def reports():
    return render_template('reports.html')

@app.route('/customers', methods=['GET', 'POST'])
@roles_permitted(['employee', 'manager', 'admin'])
def customers():
    db = get_db_conn()
    all_customers = db.execute("SELECT * FROM customers ORDER BY interaction_date DESC").fetchall()
    return render_template('customers.html', customers=all_customers)

# --- Manager Routes ---
@app.route('/manager')
@roles_permitted(['manager'])
def manager_dashboard():
    db = get_db_conn()
    # Fetch all employees to display in the list
    employees = db.execute("SELECT username, phone FROM users WHERE role='employee'").fetchall()
    return render_template('manager_dashboard.html', employees=employees)

# --- Admin Routes ---
@app.route('/admin')
@roles_permitted(['admin'])
def admin_dashboard():
    db = get_db_conn()
    users = db.execute("SELECT * FROM users WHERE role != 'admin'").fetchall()
    return render_template('admin_dashboard.html', users=users)

@app.route('/toggle_user/<int:uid>', methods=['POST'])
@roles_permitted(['admin'])
def toggle_user(uid):
    db = get_db_conn()
    # Toggle user active status
    user = db.execute("SELECT is_active FROM users WHERE uid=?", (uid,)).fetchone()
    if user:
        new_status = 0 if user['is_active'] == 1 else 1
        db.execute("UPDATE users SET is_active=? WHERE uid=?", (new_status, uid))
        db.commit()
    return redirect('/admin')

if __name__ == '__main__':
    initialize_db()
    app.run(debug=True, port=5000)