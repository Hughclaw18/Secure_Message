import os
import base64
from cryptography.fernet import Fernet

# Generate a key for Fernet encryption (in production, this should be stored securely)
FERNET_KEY = os.environ.get('FERNET_KEY', Fernet.generate_key().decode())
fernet = Fernet(FERNET_KEY.encode() if isinstance(FERNET_KEY, str) else FERNET_KEY)

# XOR key for XOR cipher (simple key for demonstration)
XOR_KEY = os.environ.get('XOR_KEY', 'secure_messaging_xor_key_2024')

def encrypt_message(message, cipher_type):
    """
    Encrypt a message using the specified cipher type.
    
    Args:
        message (str): The message to encrypt
        cipher_type (str): Either 'fernet' or 'xor'
    
    Returns:
        str: Base64 encoded encrypted message
    """
    if cipher_type == 'fernet':
        return encrypt_fernet(message)
    elif cipher_type == 'xor':
        return encrypt_xor(message)
    else:
        raise ValueError(f"Unsupported cipher type: {cipher_type}")

def decrypt_message(encrypted_message, cipher_type):
    """
    Decrypt a message using the specified cipher type.
    
    Args:
        encrypted_message (str): Base64 encoded encrypted message
        cipher_type (str): Either 'fernet' or 'xor'
    
    Returns:
        str: Decrypted message
    """
    if cipher_type == 'fernet':
        return decrypt_fernet(encrypted_message)
    elif cipher_type == 'xor':
        return decrypt_xor(encrypted_message)
    else:
        raise ValueError(f"Unsupported cipher type: {cipher_type}")

def encrypt_fernet(message):
    """Encrypt message using Fernet symmetric encryption."""
    message_bytes = message.encode('utf-8')
    encrypted_bytes = fernet.encrypt(message_bytes)
    return base64.b64encode(encrypted_bytes).decode('utf-8')

def decrypt_fernet(encrypted_message):
    """Decrypt message using Fernet symmetric encryption."""
    encrypted_bytes = base64.b64decode(encrypted_message.encode('utf-8'))
    decrypted_bytes = fernet.decrypt(encrypted_bytes)
    return decrypted_bytes.decode('utf-8')

def encrypt_xor(message):
    """Encrypt message using XOR cipher."""
    message_bytes = message.encode('utf-8')
    key_bytes = XOR_KEY.encode('utf-8')
    
    encrypted_bytes = bytearray()
    for i, byte in enumerate(message_bytes):
        key_byte = key_bytes[i % len(key_bytes)]
        encrypted_bytes.append(byte ^ key_byte)
    
    return base64.b64encode(encrypted_bytes).decode('utf-8')

def decrypt_xor(encrypted_message):
    """Decrypt message using XOR cipher."""
    encrypted_bytes = base64.b64decode(encrypted_message.encode('utf-8'))
    key_bytes = XOR_KEY.encode('utf-8')
    
    decrypted_bytes = bytearray()
    for i, byte in enumerate(encrypted_bytes):
        key_byte = key_bytes[i % len(key_bytes)]
        decrypted_bytes.append(byte ^ key_byte)
    
    return decrypted_bytes.decode('utf-8')

def encrypt_file_content(file_content, cipher_type):
    """
    Encrypt file content using the specified cipher type.
    
    Args:
        file_content (bytes): The file content to encrypt
        cipher_type (str): Either 'fernet' or 'xor'
    
    Returns:
        bytes: Encrypted file content
    """
    if cipher_type == 'fernet':
        return fernet.encrypt(file_content)
    elif cipher_type == 'xor':
        key_bytes = XOR_KEY.encode('utf-8')
        encrypted_bytes = bytearray()
        for i, byte in enumerate(file_content):
            key_byte = key_bytes[i % len(key_bytes)]
            encrypted_bytes.append(byte ^ key_byte)
        return bytes(encrypted_bytes)
    else:
        raise ValueError(f"Unsupported cipher type: {cipher_type}")

def decrypt_file_content(encrypted_content, cipher_type):
    """
    Decrypt file content using the specified cipher type.
    
    Args:
        encrypted_content (bytes): The encrypted file content
        cipher_type (str): Either 'fernet' or 'xor'
    
    Returns:
        bytes: Decrypted file content
    """
    if cipher_type == 'fernet':
        return fernet.decrypt(encrypted_content)
    elif cipher_type == 'xor':
        key_bytes = XOR_KEY.encode('utf-8')
        decrypted_bytes = bytearray()
        for i, byte in enumerate(encrypted_content):
            key_byte = key_bytes[i % len(key_bytes)]
            decrypted_bytes.append(byte ^ key_byte)
        return bytes(decrypted_bytes)
    else:
        raise ValueError(f"Unsupported cipher type: {cipher_type}")
