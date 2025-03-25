from cryptography.fernet import Fernet
import os
from datetime import datetime

# Encryption key (static for demonstration purposes)
encryption_key = Fernet.generate_key()
cipher_suite = Fernet(encryption_key)

def encrypt_file(file_path, content):
    encrypted_content = cipher_suite.encrypt(content.encode('utf-8'))
    with open(file_path, 'wb') as f:
        f.write(encrypted_content)

def decrypt_file(file_path):
    try:
        with open(file_path, 'rb') as f:
            encrypted_content = f.read()
        return cipher_suite.decrypt(encrypted_content).decode('utf-8')
    except Exception as e:
        return f"Error decrypting file: {e}"

def get_file_metadata(file_path):
    metadata = os.stat(file_path)
    return {
        "name": os.path.basename(file_path),
        "creator": os.getlogin(),
        "size": metadata.st_size,
        "created": datetime.fromtimestamp(metadata.st_ctime).strftime('%d/%m/%Y'),
        "modified": datetime.fromtimestamp(metadata.st_mtime).strftime('%d/%m/%Y'),
    }
