from cryptography.fernet import Fernet
import os
import json
from datetime import datetime
from module1_auth import users

# Store file-specific symmetric keys
file_symmetric_keys = {}

def load_file_keys():
    global file_symmetric_keys
    try:
        with open('file_keys.json', 'r') as f:
            file_symmetric_keys = json.load(f)
    except FileNotFoundError:
        file_symmetric_keys = {}

def save_file_keys():
    with open('file_keys.json', 'w') as f:
        json.dump(file_symmetric_keys, f)

load_file_keys()

def get_cipher_suite(username):
    user_data = users.get(username)
    if not user_data or "secret_key" not in user_data:
        raise ValueError(f"No valid secret_key found for user: {username}")
    encryption_key = user_data["secret_key"].encode("utf-8")
    return Fernet(encryption_key)

def encrypt_file(username, file_path, content):
    cipher_suite = get_cipher_suite(username)
    # Generate a new symmetric key for this file
    file_symmetric_key = Fernet.generate_key()
    fernet_file = Fernet(file_symmetric_key)
    encrypted_content = fernet_file.encrypt(content.encode('utf-8'))
    with open(file_path, 'wb') as f:
        f.write(encrypted_content)
    # Encrypt the file's symmetric key with the owner's secret key
    encrypted_file_key = cipher_suite.encrypt(file_symmetric_key)
    # Store it as hex string for JSON compatibility
    file_symmetric_keys[file_path] = {
        "key": encrypted_file_key.hex(),
        "creator": username
    }
    save_file_keys()

def decrypt_file(username, file_path):
    try:
        file_data = file_symmetric_keys[file_path]
        encrypted_file_key_hex = file_data["key"]
        encrypted_file_key = bytes.fromhex(encrypted_file_key_hex)
    except KeyError:
        return f"Error: File not found or no key available."
    cipher_suite = get_cipher_suite(username)
    try:
        file_symmetric_key = cipher_suite.decrypt(encrypted_file_key)
    except Exception as e:
        return f"Error decrypting file key: {e}"
    fernet_file = Fernet(file_symmetric_key)
    with open(file_path, 'rb') as f:
        encrypted_content = f.read()
    return fernet_file.decrypt(encrypted_content).decode('utf-8')

def get_file_metadata(file_path):
    metadata = os.stat(file_path)
    creator = file_symmetric_keys.get(file_path, {}).get("creator", os.getlogin())
    return {
        "name": os.path.basename(file_path),
        "creator": creator,
        "size": metadata.st_size,
        "created": datetime.fromtimestamp(metadata.st_ctime).strftime('%d/%m/%Y'),
        "modified": datetime.fromtimestamp(metadata.st_mtime).strftime('%d/%m/%Y'),
    }