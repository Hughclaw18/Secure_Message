# Secure Messaging Application

A comprehensive Flask-based local messaging platform featuring user authentication, direct messaging, group conversations, encrypted file sharing, and admin management.

## Features

- **User Authentication**: Secure registration and login system
- **Direct Messaging**: Send encrypted messages between users
- **Group Messaging**: Create and manage group conversations
- **File Sharing**: Upload and share encrypted files (10MB limit)
- **Admin Panel**: Comprehensive user and message management
- **Multiple Encryption**: Support for Fernet (AES) and XOR cipher methods
- **Responsive Design**: Modern Bootstrap 5 interface with dark theme

## Architecture

### Backend
- **Framework**: Flask with SQLAlchemy ORM
- **Database**: SQLite for development, PostgreSQL ready
- **Authentication**: Session-based with password hashing
- **Encryption**: Custom crypto utilities with multiple cipher support

### Frontend
- **UI Framework**: Bootstrap 5 with dark theme
- **Icons**: Feather Icons
- **Responsive**: Mobile-friendly design

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/secure-messaging-app.git
cd secure-messaging-app
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Set environment variables:
```bash
export SESSION_SECRET="your-secret-key-here"
export DATABASE_URL="sqlite:///secure_messaging.db"
```

4. Run the application:
```bash
python main.py
```

The application will be available at `http://localhost:5000`

## Usage

1. **Registration**: Create a new account with username and password
2. **Login**: Access your account securely
3. **Dashboard**: View and send messages
4. **Groups**: Create or join group conversations
5. **File Sharing**: Upload and share encrypted files
6. **Admin Features**: First registered user becomes admin automatically

## Security Features

- Password hashing using Werkzeug security
- Message encryption with multiple cipher options
- Secure session management
- Input validation and CSRF protection
- Environment-based configuration for secrets

## Database Schema

### Core Models
- **User**: User accounts and authentication
- **Message**: Encrypted messages with cipher metadata
- **Group**: Group conversation management
- **GroupMembership**: User-group relationships
- **EncryptedFile**: File storage and encryption
- **MessageFile**: Message-file associations

## Development

### Project Structure
```
├── app.py              # Flask application setup
├── main.py             # Application entry point
├── models.py           # Database models
├── crypto_utils.py     # Encryption utilities
├── templates/          # HTML templates
├── static/             # Static assets
└── instance/           # Database files
```

### Environment Variables
- `SESSION_SECRET`: Flask session encryption key
- `DATABASE_URL`: Database connection string
- `FERNET_KEY`: Fernet encryption key (auto-generated)
- `XOR_KEY`: XOR cipher key

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Deployment
Local

### Other Platforms
Configure environment variables and ensure database connectivity for deployment on other platforms.
