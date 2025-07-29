import os
import logging
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from crypto_utils import encrypt_message, decrypt_message

# Configure logging
logging.basicConfig(level=logging.DEBUG)

class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)

# Create the app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key-change-in-production")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Configure the database
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///secure_messaging.db"
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}

# Initialize the app with the extension
db.init_app(app)

with app.app_context():
    # Import models here to ensure they're registered
    from models import User, Message
    db.create_all()

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Get current user
    user = User.query.get(session['user_id'])
    if not user:
        session.clear()
        return redirect(url_for('login'))
    
    # Get all messages for the current user
    messages = Message.query.filter_by(user_id=user.id).order_by(Message.timestamp.desc()).all()
    
    # Decrypt messages for display
    decrypted_messages = []
    for message in messages:
        try:
            decrypted_content = decrypt_message(message.encrypted_content, message.cipher_type)
            decrypted_messages.append({
                'content': decrypted_content,
                'cipher_type': message.cipher_type,
                'timestamp': message.timestamp
            })
        except Exception as e:
            logging.error(f"Failed to decrypt message: {e}")
            decrypted_messages.append({
                'content': '[Decryption failed]',
                'cipher_type': message.cipher_type,
                'timestamp': message.timestamp
            })
    
    return render_template('index.html', user=user, messages=decrypted_messages)

@app.route('/send_message', methods=['POST'])
def send_message():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    content = request.form.get('content', '').strip()
    cipher_type = request.form.get('cipher_type', 'fernet')
    
    if not content:
        flash('Message content cannot be empty.', 'error')
        return redirect(url_for('index'))
    
    if cipher_type not in ['fernet', 'xor']:
        flash('Invalid cipher type.', 'error')
        return redirect(url_for('index'))
    
    try:
        # Encrypt the message
        encrypted_content = encrypt_message(content, cipher_type)
        
        # Save to database
        message = Message(
            user_id=session['user_id'],
            encrypted_content=encrypted_content,
            cipher_type=cipher_type
        )
        db.session.add(message)
        db.session.commit()
        
        flash('Message sent successfully!', 'success')
    except Exception as e:
        logging.error(f"Failed to send message: {e}")
        flash('Failed to send message. Please try again.', 'error')
    
    return redirect(url_for('index'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        if not username or not password:
            flash('Please enter both username and password.', 'error')
            return render_template('login.html')
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            flash(f'Welcome back, {user.username}!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password.', 'error')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        if not username or not password:
            flash('Please enter both username and password.', 'error')
            return render_template('register.html')
        
        if len(username) < 3:
            flash('Username must be at least 3 characters long.', 'error')
            return render_template('register.html')
        
        if len(password) < 6:
            flash('Password must be at least 6 characters long.', 'error')
            return render_template('register.html')
        
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('register.html')
        
        # Check if username already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.', 'error')
            return render_template('register.html')
        
        try:
            # Create new user
            password_hash = generate_password_hash(password)
            new_user = User(username=username, password_hash=password_hash)
            db.session.add(new_user)
            db.session.commit()
            
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            logging.error(f"Registration failed: {e}")
            flash('Registration failed. Please try again.', 'error')
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
