import json
from module2_p1_file_ops import file_symmetric_keys

permissions = {}

def load_permissions():
    global permissions
    try:
        with open('access_matrix.json', 'r') as f:
            permissions = json.load(f)
    except FileNotFoundError:
        permissions = {}

def save_permissions():
    with open('access_matrix.json', 'w') as f:
        json.dump(permissions, f)

load_permissions()

def get_permissions(file_path):
    return permissions.get(file_path, {"read": [], "write": []})

def set_initial_permissions(file_path, creator):
    permissions[file_path] = {
        "read": [creator],
        "write": [creator]
    }
    save_permissions()

def add_permission(file_path, username, permission_type):
    if file_path not in permissions:
        return False
    creator = file_symmetric_keys.get(file_path, {}).get("creator")
    if not creator:
        return False
    if permission_type not in ["read", "write"]:
        return False
    if username not in permissions[file_path][permission_type]:
        permissions[file_path][permission_type].append(username)
        save_permissions()
    return True

def remove_permission(file_path, username, permission_type):
    if file_path not in permissions:
        return False
    creator = file_symmetric_keys.get(file_path, {}).get("creator")
    if not creator or username == creator:
        return False  # Cannot remove creator's permissions
    if permission_type not in ["read", "write"]:
        return False
    if username in permissions[file_path][permission_type]:
        permissions[file_path][permission_type].remove(username)
        save_permissions()
    return True

def has_permission(file_path, username, permission_type):
    if file_path not in permissions:
        return False
    return username in permissions[file_path].get(permission_type, [])