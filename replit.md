# Secure Messaging Application

## Overview

This is a Flask-based secure messaging application that allows users to register, login, and send encrypted messages to themselves. The application demonstrates different encryption methods (Fernet and XOR cipher) and provides a simple web interface for managing encrypted messages.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Backend Architecture
- **Framework**: Flask (Python web framework)
- **Database**: SQLite with SQLAlchemy ORM
- **Authentication**: Session-based with password hashing using Werkzeug
- **Encryption**: Custom crypto utilities supporting Fernet (AES-based) and XOR cipher methods
- **Template Engine**: Jinja2 for server-side rendering

### Frontend Architecture
- **UI Framework**: Bootstrap 5 with dark theme
- **Icons**: Feather Icons
- **Styling**: Responsive design using Bootstrap grid system
- **JavaScript**: Minimal client-side scripting for UI enhancements

## Key Components

### 1. Application Core (`app.py`)
- Flask application factory pattern
- Database configuration and initialization
- Session management setup
- ProxyFix middleware for deployment compatibility

### 2. Database Models (`models.py`)
- **User Model**: Stores user credentials and metadata
- **Message Model**: Stores encrypted messages with cipher type information
- Relationships: One-to-many (User → Messages) with cascade delete

### 3. Cryptography Module (`crypto_utils.py`)
- **Fernet Encryption**: Industry-standard symmetric encryption
- **XOR Cipher**: Simple demonstration cipher
- Unified interface for multiple encryption methods
- Base64 encoding for database storage

### 4. Template System
- **Base Template**: Common layout with navigation and flash messages
- **Authentication Templates**: Login and registration forms
- **Dashboard Template**: Message sending and history display

## Data Flow

1. **User Registration/Login**: 
   - Passwords hashed using Werkzeug security functions
   - Session-based authentication with user ID storage

2. **Message Creation**:
   - User submits plain text message
   - Message encrypted using selected cipher type
   - Encrypted content stored in database with cipher metadata

3. **Message Display**:
   - Encrypted messages retrieved from database
   - Messages decrypted using original cipher type
   - Plain text displayed to authenticated user

## External Dependencies

### Python Packages
- **Flask**: Web framework and extensions (SQLAlchemy)
- **cryptography**: Fernet encryption implementation
- **Werkzeug**: Password hashing and security utilities

### Frontend Dependencies (CDN)
- **Bootstrap 5**: UI framework and styling
- **Feather Icons**: Icon library for UI elements

### Environment Variables
- `SESSION_SECRET`: Flask session encryption key
- `FERNET_KEY`: Fernet encryption key (auto-generated if not provided)
- `XOR_KEY`: XOR cipher key (default provided)

## Deployment Strategy

### Local Development
- SQLite database for simplicity
- Debug mode enabled
- Development server on port 5000

### Production Considerations
- Environment-based configuration for secrets
- ProxyFix middleware configured for reverse proxy deployment
- Database connection pooling configured
- Session security with proper secret key

### Replit Deployment
- Configured for Replit's Flask template
- Host binding to 0.0.0.0 for external access
- File-based SQLite database for persistence
- Bootstrap CDN integration for styling

## Security Features

1. **Password Security**: Werkzeug password hashing
2. **Message Encryption**: Multiple cipher options (Fernet/XOR)
3. **Session Management**: Secure session handling
4. **Input Validation**: Form validation and CSRF protection via Flask
5. **Environment-based Secrets**: Configurable encryption keys

## Database Schema

### Users Table
- `id`: Primary key
- `username`: Unique username
- `password_hash`: Hashed password
- `created_at`: Account creation timestamp

### Messages Table
- `id`: Primary key
- `user_id`: Foreign key to users
- `encrypted_content`: Base64 encoded encrypted message
- `cipher_type`: Encryption method used ('fernet' or 'xor')
- `timestamp`: Message creation time