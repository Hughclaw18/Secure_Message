from app import db
from datetime import datetime

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    is_admin = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    
    # Relationships
    sent_messages = db.relationship('Message', foreign_keys='Message.sender_id', backref='sender', lazy=True, cascade='all, delete-orphan')
    received_messages = db.relationship('Message', foreign_keys='Message.recipient_id', backref='recipient', lazy=True)
    group_memberships = db.relationship('GroupMembership', backref='user', lazy=True, cascade='all, delete-orphan')
    uploaded_files = db.relationship('EncryptedFile', backref='uploader', lazy=True, cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<User {self.username}>'

class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    # Relationships
    creator = db.relationship('User', backref='created_groups')
    members = db.relationship('GroupMembership', backref='group', lazy=True, cascade='all, delete-orphan')
    messages = db.relationship('Message', backref='group', lazy=True, cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<Group {self.name}>'

class GroupMembership(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=False)
    role = db.Column(db.String(20), default='member')  # 'admin', 'moderator', 'member'
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    __table_args__ = (db.UniqueConstraint('user_id', 'group_id'),)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # None for group messages
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=True)  # None for direct messages
    encrypted_content = db.Column(db.Text, nullable=False)
    cipher_type = db.Column(db.String(20), nullable=False)  # 'fernet' or 'xor'
    message_type = db.Column(db.String(20), default='text')  # 'text', 'file'
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)
    
    # For threading/replies
    parent_message_id = db.Column(db.Integer, db.ForeignKey('message.id'), nullable=True)
    replies = db.relationship('Message', backref=db.backref('parent_message', remote_side=[id]), lazy=True)
    
    def __repr__(self):
        return f'<Message {self.id} by User {self.sender_id}>'

class EncryptedFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    encrypted_content = db.Column(db.LargeBinary, nullable=False)  # Store encrypted file content
    file_size = db.Column(db.Integer, nullable=False)
    mime_type = db.Column(db.String(100), nullable=False)
    cipher_type = db.Column(db.String(20), nullable=False)
    uploader_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    upload_timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    access_count = db.Column(db.Integer, default=0)
    
    def __repr__(self):
        return f'<EncryptedFile {self.filename}>'

class MessageFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message_id = db.Column(db.Integer, db.ForeignKey('message.id'), nullable=False)
    file_id = db.Column(db.Integer, db.ForeignKey('encrypted_file.id'), nullable=False)
    
    message = db.relationship('Message', backref='attached_files')
    file = db.relationship('EncryptedFile', backref='message_attachments')
    
    __table_args__ = (db.UniqueConstraint('message_id', 'file_id'),)
