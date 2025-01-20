from flask import Flask, request, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user, login_manager
import os
import subprocess
from sqlalchemy.sql import text

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///supplychain.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.secret_key = 'supersecretkey'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    role = db.Column(db.String(20), nullable=False)

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    customer_name = db.Column(db.String(80), nullable=False)
    credit_card = db.Column(db.String(16), nullable=False)
    details = db.Column(db.String(200), nullable=False)

@app.before_request
def setup():
    db.create_all()
    if not User.query.filter_by(username='admin').first():
        db.session.add(User(username='admin', password='admin', role='admin'))
        db.session.add(User(username='user', password='user', role='user'))
        db.session.commit()
    if not Order.query.first():
        db.session.add(Order(customer_name='John Doe', credit_card='1234567812345678', details='Order #1'))
        db.session.commit()

@app.route('/')
def home():
    try:
        role = current_user.role
    except:
        role = "None"
    return render_template('index.html',role=role)

'''
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # Vulnerable SQL query (SQL Injection - OR Attack)
        query = text(f"SELECT * FROM user WHERE username='{username}' AND password='{password}'")
        result = db.session.execute(query).fetchone()

        if result:
            user = User.query.filter_by(username=username).first()
            login_user(user) # Insecure Session Token
            flash('Login successful!', 'success')
            if user.role == 'admin':
                return redirect(url_for('admin'))
            else:
                return redirect(url_for('user_dashboard'))
        else:
            flash('Invalid credentials!', 'danger')
            return redirect(url_for('login'))
    return render_template("login.html")
'''

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # Vulnerable SQL query (SQL Injection)
        query = text(f"SELECT * FROM user WHERE username='{username}' AND password='{password}'")
        result = db.session.execute(query).fetchone()

        if result:
            # Create a User object and login the user
            user = User.query.filter_by(username=username).first()
            login_user(user)
            flash('Login successful!', 'success')
            if user.role == 'admin':
                return redirect(url_for('admin'))
            else:
                return redirect(url_for('user_dashboard'))
        else:
            flash('Invalid credentials!', 'danger')
            return redirect(url_for('login'))
    return render_template("login.html")


@app.route('/admin')
@login_required
def admin():
    if current_user.role != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('user_dashboard'))
    return render_template("admin.html")

@app.route('/user_dashboard')
@login_required
def user_dashboard():
    return render_template("user_dashboard.html",username=current_user.username)

@app.route('/view_orders')
@login_required
def view_orders():
    orders = Order.query.all()
    return render_template("view_orders.html", orders=orders,role=current_user.role)

@app.route('/get-report', methods=['GET', 'POST'])
@login_required
def get_report():
    if current_user.role != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('user_dashboard'))
    if request.method == 'POST':
        file = request.files['file']
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(file_path)
        # RCE: Execute uploaded file without validation
        try:
            file_path = file_path.replace('\\', '/')
            subprocess.Popen(['start', 'cmd', '/K', f'python {file_path}'], shell=True)
            return f"Python script {file.filename} executed successfully."
        except Exception as e:
            return f"Error executing file: {str(e)}"
    return render_template("file_uploads.html")

@app.route('/inventory')
@login_required
def inventory():
    return render_template("inventory.html")

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

if __name__ == '__main__':
    app.run(debug=True, host="127.0.0.1", port=5000)
