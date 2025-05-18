from flask import Flask, request, render_template, redirect, url_for, flash, Response, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin, current_user
from flask_bcrypt import Bcrypt
from cryptography.fernet import Fernet
import os
from io import BytesIO
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'

UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Your generated Fernet key
FERNET_KEY = b'oUbBIPPzFejC308ZUa_HcrnXU8E9GQot4ILOE-urNdk='
fernet = Fernet(FERNET_KEY)

def encrypt_file(file_data):
    return fernet.encrypt(file_data)

def decrypt_file(file_data):
    return fernet.decrypt(file_data)

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    action = db.Column(db.String(50), nullable=False)  # 'uploaded', 'deleted'
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))
        if User.query.filter_by(email=email).first():
            flash('Email already exists')
            return redirect(url_for('register'))
        user = User(username=username, email=email, password=password)
        db.session.add(user)
        db.session.commit()
        flash('Account created! Please log in.')
        return redirect(url_for('login'))
    return render_template('register.html')

# Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('upload'))
        else:
            flash('Login failed. Check your username and password.')
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return f'Hello, {current_user.username}! Welcome to your dashboard.'

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
def home():
    return redirect(url_for('login'))

# Upload and list files
@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], current_user.username)
    os.makedirs(user_folder, exist_ok=True)
    if request.method == 'POST':
        file = request.files['file']
        if file:
            encrypted_data = encrypt_file(file.read())
            filepath = os.path.join(user_folder, file.filename + '.enc')
            with open(filepath, 'wb') as f:
                f.write(encrypted_data)
            new_file = File(filename=file.filename, user_id=current_user.id)
            db.session.add(new_file)
            # Log upload
            log = Log(username=current_user.username, filename=file.filename, action='uploaded')
            db.session.add(log)
            db.session.commit()
            flash('File uploaded and encrypted successfully!')
    user_files = File.query.filter_by(user_id=current_user.id).all()
    return render_template('upload.html', files=user_files)

# Delete file
@app.route('/delete/<int:file_id>', methods=['POST'])
@login_required
def delete_file(file_id):
    file_record = File.query.get_or_404(file_id)
    if file_record.user_id != current_user.id:
        flash('Access denied!')
        return redirect(url_for('upload'))
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], current_user.username)
    enc_path = os.path.join(user_folder, file_record.filename + '.enc')
    if os.path.exists(enc_path):
        os.remove(enc_path)
    # Log delete
    log = Log(username=current_user.username, filename=file_record.filename, action='deleted')
    db.session.add(log)
    db.session.delete(file_record)
    db.session.commit()
    flash('File deleted successfully!')
    return redirect(url_for('upload'))

# Preview file
@app.route('/preview/<int:file_id>')
@login_required
def preview(file_id):
    file_record = File.query.get_or_404(file_id)
    if file_record.user_id != current_user.id:
        flash('Access denied!')
        return redirect(url_for('upload'))
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], current_user.username)
    enc_path = os.path.join(user_folder, file_record.filename + '.enc')
    if not os.path.exists(enc_path):
        flash('File not found!')
        return redirect(url_for('upload'))
    with open(enc_path, 'rb') as f:
        decrypted_data = decrypt_file(f.read())
    # Image preview
    if file_record.filename.lower().endswith(('.png', '.jpg', '.jpeg', '.gif')):
        ext = file_record.filename.split('.')[-1].lower()
        mimetype = f'image/{ext if ext != "jpg" else "jpeg"}'
        return Response(decrypted_data, mimetype=mimetype)
    # Text preview
    elif file_record.filename.lower().endswith('.txt'):
        return f"<pre>{decrypted_data.decode('utf-8')}</pre>"
    # Other files: force download
    else:
        return send_file(BytesIO(decrypted_data), download_name=file_record.filename, as_attachment=True)

@app.route('/logs')
@login_required
def logs():
    user_logs = Log.query.filter_by(username=current_user.username).order_by(Log.timestamp.desc()).all()
    return render_template('logs.html', logs=user_logs)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
