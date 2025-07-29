import os
import logging
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_file
from extensions import db, Base
from sqlalchemy import or_, and_
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.utils import secure_filename
import base64
import io
from crypto_utils import encrypt_message, decrypt_message, encrypt_file_content, decrypt_file_content

# Configure logging
logging.basicConfig(level=logging.DEBUG)



# Create the app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key-change-in-production")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Configure the database
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///./secure_messaging.db"
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}

# Initialize the app with the extension
db.init_app(app)

with app.app_context():
    # Import models here to ensure they're registered
    from models import User, Message, Group, GroupMembership, EncryptedFile, MessageFile
    db.create_all()

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Get current user and update last login
    user = User.query.get(session['user_id'])
    if not user or not user.is_active:
        session.clear()
        return redirect(url_for('login'))
    
    user.last_login = datetime.utcnow()
    db.session.commit()
    
    # Get direct messages (sent and received)
    direct_messages = Message.query.filter(
        and_(
            Message.group_id.is_(None),
            or_(
                Message.sender_id == user.id,
                Message.recipient_id == user.id
            )
        )
    ).order_by(Message.timestamp.desc()).limit(10).all()
    
    # Get user's groups
    user_groups = db.session.query(Group).join(GroupMembership).filter(
        GroupMembership.user_id == user.id
    ).all()
    
    # Get recent group messages
    group_messages = []
    if user_groups:
        group_ids = [g.id for g in user_groups]
        group_messages = Message.query.filter(
            Message.group_id.in_(group_ids)
        ).order_by(Message.timestamp.desc()).limit(10).all()
    
    # Decrypt messages for display
    decrypted_direct = []
    for message in direct_messages:
        try:
            decrypted_content = decrypt_message(message.encrypted_content, message.cipher_type)
            decrypted_direct.append({
                'id': message.id,
                'content': decrypted_content,
                'cipher_type': message.cipher_type,
                'timestamp': message.timestamp,
                'sender': message.sender,
                'recipient': message.recipient,
                'is_sent': message.sender_id == user.id
            })
        except Exception as e:
            logging.error(f"Failed to decrypt message: {e}")
    
    decrypted_group = []
    for message in group_messages:
        try:
            decrypted_content = decrypt_message(message.encrypted_content, message.cipher_type)
            decrypted_group.append({
                'id': message.id,
                'content': decrypted_content,
                'cipher_type': message.cipher_type,
                'timestamp': message.timestamp,
                'sender': message.sender,
                'group': message.group
            })
        except Exception as e:
            logging.error(f"Failed to decrypt message: {e}")
    
    # Get other users for direct messaging
    other_users = User.query.filter(
        and_(User.id != user.id, User.is_active == True)
    ).all()
    
    return render_template('dashboard.html', 
                         user=user, 
                         direct_messages=decrypted_direct,
                         group_messages=decrypted_group,
                         user_groups=user_groups,
                         other_users=other_users)

@app.route('/send_direct_message', methods=['POST'])
def send_direct_message():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    content = request.form.get('content', '').strip()
    recipient_id = request.form.get('recipient_id')
    cipher_type = request.form.get('cipher_type', 'fernet')
    
    if not content:
        flash('Message content cannot be empty.', 'error')
        return redirect(url_for('index'))
    
    if not recipient_id:
        flash('Please select a recipient.', 'error')
        return redirect(url_for('index'))
    
    if cipher_type not in ['fernet', 'xor']:
        flash('Invalid cipher type.', 'error')
        return redirect(url_for('index'))
    
    try:
        recipient = User.query.get(recipient_id)
        if not recipient or not recipient.is_active:
            flash('Invalid recipient.', 'error')
            return redirect(url_for('index'))
        
        # Encrypt the message
        encrypted_content = encrypt_message(content, cipher_type)
        
        # Save to database
        message = Message()
        message.sender_id = session['user_id']
        message.recipient_id = recipient_id
        message.encrypted_content = encrypted_content
        message.cipher_type = cipher_type
        db.session.add(message)
        db.session.commit()
        
        flash(f'Message sent to {recipient.username}!', 'success')
    except Exception as e:
        logging.error(f"Failed to send message: {e}")
        flash('Failed to send message. Please try again.', 'error')
    
    return redirect(url_for('index'))

@app.route('/send_group_message', methods=['POST'])
def send_group_message():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    content = request.form.get('content', '').strip()
    group_id = request.form.get('group_id')
    cipher_type = request.form.get('cipher_type', 'fernet')
    
    if not content:
        flash('Message content cannot be empty.', 'error')
        return redirect(url_for('groups'))
    
    if not group_id:
        flash('Invalid group.', 'error')
        return redirect(url_for('groups'))
    
    try:
        # Check if user is member of the group
        membership = GroupMembership.query.filter_by(
            user_id=session['user_id'], 
            group_id=group_id
        ).first()
        
        if not membership:
            flash('You are not a member of this group.', 'error')
            return redirect(url_for('groups'))
        
        # Encrypt the message
        encrypted_content = encrypt_message(content, cipher_type)
        
        # Save to database
        message = Message()
        message.sender_id = session['user_id']
        message.group_id = group_id
        message.encrypted_content = encrypted_content
        message.cipher_type = cipher_type
        db.session.add(message)
        db.session.commit()
        
        flash('Message sent to group!', 'success')
    except Exception as e:
        logging.error(f"Failed to send group message: {e}")
        flash('Failed to send message. Please try again.', 'error')
    
    return redirect(url_for('view_group', group_id=group_id))

@app.route('/groups')
def groups():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    if not user or not user.is_active:
        session.clear()
        return redirect(url_for('login'))
    
    # Get user's groups
    user_groups = db.session.query(Group).join(GroupMembership).filter(
        GroupMembership.user_id == user.id
    ).all()
    
    # Get all public groups (for joining)
    all_groups = Group.query.filter_by(is_active=True).all()
    available_groups = [g for g in all_groups if g not in user_groups]
    
    return render_template('groups.html', 
                         user=user, 
                         user_groups=user_groups,
                         available_groups=available_groups)

@app.route('/create_group', methods=['GET', 'POST'])
def create_group():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        description = request.form.get('description', '').strip()
        
        if not name:
            flash('Group name is required.', 'error')
            return render_template('create_group.html')
        
        try:
            # Create new group
            group = Group()
            group.name = name
            group.description = description
            group.created_by = session['user_id']
            db.session.add(group)
            db.session.commit()
            
            # Add creator as admin
            membership = GroupMembership()
            membership.user_id = session['user_id']
            membership.group_id = group.id
            membership.role = 'admin'
            db.session.add(membership)
            db.session.commit()
            
            flash(f'Group "{name}" created successfully!', 'success')
            return redirect(url_for('groups'))
        except Exception as e:
            logging.error(f"Failed to create group: {e}")
            flash('Failed to create group. Please try again.', 'error')
    
    return render_template('create_group.html')

@app.route('/join_group/<int:group_id>')
def join_group(group_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    try:
        group = Group.query.get(group_id)
        if not group or not group.is_active:
            flash('Group not found.', 'error')
            return redirect(url_for('groups'))
        
        # Check if already a member
        existing = GroupMembership.query.filter_by(
            user_id=session['user_id'],
            group_id=group_id
        ).first()
        
        if existing:
            flash('You are already a member of this group.', 'info')
            return redirect(url_for('groups'))
        
        # Add membership
        membership = GroupMembership()
        membership.user_id = session['user_id']
        membership.group_id = group_id
        membership.role = 'member'
        db.session.add(membership)
        db.session.commit()
        
        flash(f'Successfully joined "{group.name}"!', 'success')
    except Exception as e:
        logging.error(f"Failed to join group: {e}")
        flash('Failed to join group. Please try again.', 'error')
    
    return redirect(url_for('groups'))

@app.route('/view_group/<int:group_id>')
def view_group(group_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    
    # Check if user is member of the group
    membership = GroupMembership.query.filter_by(
        user_id=session['user_id'],
        group_id=group_id
    ).first()
    
    if not membership:
        flash('You are not a member of this group.', 'error')
        return redirect(url_for('groups'))
    
    group = Group.query.get(group_id)
    if not group or not group.is_active:
        flash('Group not found.', 'error')
        return redirect(url_for('groups'))
    
    # Get group messages
    messages = Message.query.filter_by(group_id=group_id).order_by(Message.timestamp.desc()).limit(50).all()
    
    # Decrypt messages
    decrypted_messages = []
    for message in messages:
        try:
            decrypted_content = decrypt_message(message.encrypted_content, message.cipher_type)
            decrypted_messages.append({
                'id': message.id,
                'content': decrypted_content,
                'cipher_type': message.cipher_type,
                'timestamp': message.timestamp,
                'sender': message.sender
            })
        except Exception as e:
            logging.error(f"Failed to decrypt message: {e}")
    
    # Get group members
    members = db.session.query(User, GroupMembership).join(GroupMembership).filter(
        GroupMembership.group_id == group_id
    ).all()
    
    return render_template('view_group.html',
                         user=user,
                         group=group,
                         messages=decrypted_messages,
                         members=members,
                         user_role=membership.role)

@app.route('/upload_file', methods=['POST'])
def upload_file():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if 'file' not in request.files:
        flash('No file selected.', 'error')
        return redirect(url_for('index'))
    
    file = request.files['file']
    if file.filename == '':
        flash('No file selected.', 'error')
        return redirect(url_for('index'))
    
    cipher_type = request.form.get('cipher_type', 'fernet')
    recipient_id = request.form.get('recipient_id')
    group_id = request.form.get('group_id')
    
    if not recipient_id and not group_id:
        flash('Please specify a recipient or group.', 'error')
        return redirect(url_for('index'))
    
    try:
        # Read file content
        file_content = file.read()
        if len(file_content) > 10 * 1024 * 1024:  # 10MB limit
            flash('File too large. Maximum size is 10MB.', 'error')
            return redirect(url_for('index'))
        
        # Encrypt file content
        encrypted_content = encrypt_file_content(file_content, cipher_type)
        
        # Save encrypted file
        encrypted_file = EncryptedFile()
        encrypted_file.filename = secure_filename(file.filename or 'unnamed_file')
        encrypted_file.encrypted_content = encrypted_content
        encrypted_file.file_size = len(file_content)
        encrypted_file.mime_type = file.content_type or 'application/octet-stream'
        encrypted_file.cipher_type = cipher_type
        encrypted_file.uploader_id = session['user_id']
        db.session.add(encrypted_file)
        db.session.commit()
        
        # Create message with file attachment
        message = Message()
        message.sender_id = session['user_id']
        message.recipient_id = recipient_id if recipient_id else None
        message.group_id = group_id if group_id else None
        message.encrypted_content = encrypt_message(f"[File: {file.filename}]", cipher_type)
        message.cipher_type = cipher_type
        message.message_type = 'file'
        db.session.add(message)
        db.session.commit()
        
        # Link file to message
        message_file = MessageFile()
        message_file.message_id = message.id
        message_file.file_id = encrypted_file.id
        db.session.add(message_file)
        db.session.commit()
        
        flash(f'File "{file.filename}" uploaded and encrypted successfully!', 'success')
    except Exception as e:
        logging.error(f"Failed to upload file: {e}")
        flash('Failed to upload file. Please try again.', 'error')
    
    return redirect(url_for('index'))

@app.route('/download_file/<int:file_id>')
def download_file(file_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    try:
        encrypted_file = EncryptedFile.query.get(file_id)
        if not encrypted_file:
            flash('File not found.', 'error')
            return redirect(url_for('index'))
        
        # Check if user has access to this file
        message_file = MessageFile.query.filter_by(file_id=file_id).first()
        if not message_file:
            flash('Access denied.', 'error')
            return redirect(url_for('index'))
        
        message = Message.query.get(message_file.message_id)
        user_id = session['user_id']
        
        # Check access permissions
        has_access = False
        if message:
            if message.recipient_id == user_id or message.sender_id == user_id:
                has_access = True
            elif message.group_id:
                membership = GroupMembership.query.filter_by(
                    user_id=user_id,
                    group_id=message.group_id
                ).first()
                if membership:
                    has_access = True
        
        if not has_access:
            flash('Access denied.', 'error')
            return redirect(url_for('index'))
        
        # Decrypt and serve file
        decrypted_content = decrypt_file_content(encrypted_file.encrypted_content, encrypted_file.cipher_type)
        
        # Update access count
        encrypted_file.access_count += 1
        db.session.commit()
        
        return send_file(
            io.BytesIO(decrypted_content),
            as_attachment=True,
            download_name=encrypted_file.filename,
            mimetype=encrypted_file.mime_type
        )
    except Exception as e:
        logging.error(f"Failed to download file: {e}")
        flash('Failed to download file.', 'error')
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
            session['is_admin'] = user.is_admin
            user.last_login = datetime.utcnow()
            db.session.commit()
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
            new_user = User()
            new_user.username = username
            new_user.password_hash = password_hash
            
            # Make first user an admin
            user_count = User.query.count()
            if user_count == 0:
                new_user.is_admin = True
                flash('You are the first user and have been granted admin privileges.', 'info')
            
            db.session.add(new_user)
            db.session.commit()
            
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            logging.error(f"Registration failed: {e}")
            flash('Registration failed. Please try again.', 'error')
    
    return render_template('register.html')

@app.route('/admin')
def admin_panel():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    if not user or not user.is_admin:
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('index'))
    
    # Get statistics
    total_users = User.query.count()
    active_users = User.query.filter_by(is_active=True).count()
    total_groups = Group.query.count()
    active_groups = Group.query.filter_by(is_active=True).count()
    total_messages = Message.query.count()
    total_files = EncryptedFile.query.count()
    
    # Get recent users
    recent_users = User.query.order_by(User.created_at.desc()).limit(10).all()
    
    # Get recent activity
    recent_messages = Message.query.order_by(Message.timestamp.desc()).limit(10).all()
    
    return render_template('admin_panel.html',
                         user=user,
                         stats={
                             'total_users': total_users,
                             'active_users': active_users,
                             'total_groups': total_groups,
                             'active_groups': active_groups,
                             'total_messages': total_messages,
                             'total_files': total_files
                         },
                         recent_users=recent_users,
                         recent_messages=recent_messages)

@app.route('/admin/users')
def admin_users():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    if not user or not user.is_admin:
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('index'))
    
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template('admin_users.html', user=user, users=users)

@app.route('/admin/toggle_user/<int:user_id>')
def admin_toggle_user(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    admin_user = User.query.get(session['user_id'])
    if not admin_user or not admin_user.is_admin:
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('index'))
    
    target_user = User.query.get(user_id)
    if not target_user:
        flash('User not found.', 'error')
        return redirect(url_for('admin_users'))
    
    if target_user.id == admin_user.id:
        flash('You cannot deactivate your own account.', 'error')
        return redirect(url_for('admin_users'))
    
    target_user.is_active = not target_user.is_active
    db.session.commit()
    
    status = "activated" if target_user.is_active else "deactivated"
    flash(f'User {target_user.username} has been {status}.', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/make_admin/<int:user_id>')
def admin_make_admin(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    admin_user = User.query.get(session['user_id'])
    if not admin_user or not admin_user.is_admin:
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('index'))
    
    target_user = User.query.get(user_id)
    if not target_user:
        flash('User not found.', 'error')
        return redirect(url_for('admin_users'))
    
    target_user.is_admin = not target_user.is_admin
    db.session.commit()
    
    status = "granted" if target_user.is_admin else "revoked"
    flash(f'Admin privileges {status} for {target_user.username}.', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/encrypted_messages')
def admin_encrypted_messages():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    if not user or not user.is_admin:
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('index'))
    
    # Get recent messages with their encrypted format
    messages = Message.query.order_by(Message.timestamp.desc()).limit(50).all()
    
    encrypted_data = []
    for message in messages:
        try:
            # Get decrypted content for comparison
            decrypted_content = decrypt_message(message.encrypted_content, message.cipher_type)
            
            encrypted_data.append({
                'id': message.id,
                'sender': message.sender,
                'recipient': message.recipient,
                'group': message.group,
                'encrypted_content': message.encrypted_content,
                'decrypted_content': decrypted_content,
                'cipher_type': message.cipher_type,
                'message_type': message.message_type,
                'timestamp': message.timestamp,
                'content_length': len(message.encrypted_content),
                'original_length': len(decrypted_content)
            })
        except Exception as e:
            encrypted_data.append({
                'id': message.id,
                'sender': message.sender,
                'recipient': message.recipient,
                'group': message.group,
                'encrypted_content': message.encrypted_content,
                'decrypted_content': f'[Decryption Error: {str(e)}]',
                'cipher_type': message.cipher_type,
                'message_type': message.message_type,
                'timestamp': message.timestamp,
                'content_length': len(message.encrypted_content),
                'original_length': 0
            })
    
    return render_template('admin_encrypted_messages.html', 
                         user=user, 
                         encrypted_data=encrypted_data)

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
