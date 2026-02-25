from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
import string
import random
import requests

app = Flask(__name__)
app.secret_key = 'advanced_super_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login' # Redirects here if not logged in

# --- Database Models ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(9), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    # Relationship: One user can have many URLs
    urls = db.relationship('URLMap', backref='owner', lazy=True)

class URLMap(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    original_url = db.Column(db.String(500), nullable=False)
    short_id = db.Column(db.String(10), unique=True, nullable=False)
    # Foreign Key linking to the User
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Helper Functions ---
def generate_short_id():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=6))

def is_valid_url(url):
    try:
        response = requests.head(url, timeout=3, allow_redirects=True)
        return response.status_code < 400
    except requests.RequestException:
        return False

# --- Routes ---
@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Rule Check: Valid Length
        if len(username) < 5 or len(username) > 9:
            flash('Username must be between 5 to 9 characters long', 'danger')
            return redirect(url_for('signup'))

        # Rule Check: Unique Username
        if User.query.filter_by(username=username).first():
            flash('This username already exists...', 'danger')
            return redirect(url_for('signup'))

        # Create new user
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        
        flash('Signup successful! Please log in.', 'success')
        return redirect(url_for('login'))
        
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')
            
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    shortened_url = None
    
    if request.method == 'POST':
        original_url = request.form.get('original_url')
        if not original_url.startswith(('http://', 'https://')):
            original_url = 'http://' + original_url

        if not is_valid_url(original_url):
            flash('Error: The URL you entered does not exist or is unreachable.', 'danger')
        else:
            # Check if this specific user already shortened this URL
            existing_url = URLMap.query.filter_by(original_url=original_url, user_id=current_user.id).first()
            if existing_url:
                short_id = existing_url.short_id
            else:
                short_id = generate_short_id()
                new_url = URLMap(original_url=original_url, short_id=short_id, user_id=current_user.id)
                db.session.add(new_url)
                db.session.commit()
                
            shortened_url = request.host_url + short_id

    # Get history ONLY for the logged-in user
    user_urls = URLMap.query.filter_by(user_id=current_user.id).order_by(URLMap.id.desc()).all()
    return render_template('dashboard.html', shortened_url=shortened_url, urls=user_urls)

@app.route('/<short_id>')
def redirect_to_url(short_id):
    link = URLMap.query.filter_by(short_id=short_id).first_or_404()
    return redirect(link.original_url)

if __name__ == '__main__':
    app.run(debug=True)