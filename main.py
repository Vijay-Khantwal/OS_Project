import tkinter as tk
from tkinter import ttk
from tkinter import messagebox, filedialog, simpledialog
from module1_auth import register_user, authenticate_user, generate_static_otp, users
from module2_p1_file_ops import encrypt_file, decrypt_file, get_file_metadata
from module3_threat_detect import detect_malware, log_threat, validate_input
from module2_p2_access_matrix import get_permissions, set_initial_permissions, add_permission, remove_permission, has_permission
import tkinter as tk
import os

logged_in_user = "user"

def check_login_required():
    global logged_in_user
    if not logged_in_user:
        messagebox.showerror("Access Denied", "You must log in first!")
        return False
    return True

def register():
    username = reg_username_entry.get()
    password = reg_password_entry.get()
    result = register_user(username, password)
    messagebox.showinfo("Registration", result)

def login():
    username = login_username_entry.get()
    password = login_password_entry.get()
    otp = otp_entry.get() 
    result = authenticate_user(username, password, otp)
    if result:
        global logged_in_user
        logged_in_user = username
        notebook.select(file_ops_frame)
        messagebox.showinfo("Login", "Login successful.")

def send_otp():
    username = login_username_entry.get()
    if username not in users:
        messagebox.showerror("Error", "User does not exist.")
        return
    otp = generate_static_otp(username)
    messagebox.showinfo("OTP Sent", f"Your OTP is: {otp}")

def read_file():
    if not check_login_required():
        return
    file_path = filedialog.askopenfilename()
    if not file_path:
        return
    if not has_permission(file_path, logged_in_user, "read"):
        messagebox.showerror("Access Denied", "You do not have read permission for this file.")
        return
    content = decrypt_file(logged_in_user, file_path)
    messagebox.showinfo("File Content", content)

def write_file():
    if not check_login_required():
        return
    popup = tk.Toplevel(root)
    popup.title("Write File")

    tk.Label(popup, text="Enter text to save:").pack(pady=5)
    text_area = tk.Text(popup, height=10, width=50)
    text_area.pack(padx=10, pady=10)

    def save_file():
        content = text_area.get("1.0", "end-1c")
        popup.destroy()
        if detect_malware(content):
            messagebox.showerror("Error", "Malicious content detected! File not saved.")
            return
        if not validate_input(content):
            messagebox.showerror("Error", "Suspicious content detected! Chance of Buffer Overflow. File not saved.")
            return
        file_path = filedialog.asksaveasfilename(defaultextension=".enc")
        if file_path:
            encrypt_file(logged_in_user, file_path, content)
            set_initial_permissions(file_path, logged_in_user)  # Set creator as initial reader/writer
            messagebox.showinfo("Success", "File saved and encrypted.")

    tk.Button(popup, text="Save", command=save_file).pack(pady=10)

def view_metadata():
    if not check_login_required():
        return
    file_path = filedialog.askopenfilename()
    if not file_path:
        return
    if not has_permission(file_path, logged_in_user, "read"):
        messagebox.showerror("Access Denied", "You do not have read permission for this file.")
        return
    metadata = get_file_metadata(file_path)
    messagebox.showinfo("File Metadata", f"Name: {metadata['name']}\nSize: {metadata['size']} bytes\nCreator: {metadata['creator']}\nCreated: {metadata['created']}\nModified: {metadata['modified']}")

def scan_file():
    if not check_login_required():
        return
    file_path = filedialog.askopenfilename()
    if not file_path:
        return
    if not has_permission(file_path, logged_in_user, "read"):
        messagebox.showerror("Access Denied", "You do not have read permission for this file.")
        return
    is_malware = detect_malware(decrypt_file(logged_in_user, file_path))
    if is_malware:
        messagebox.showerror("Threat Detected", f"Malware detected in file: {file_path}")
        log_threat(file_path, "Malware detected")
    else:
        messagebox.showinfo("Safe", "No threats detected.")

def manage_permissions():
    if not check_login_required():
        return
    file_path = filedialog.askopenfilename()
    if not file_path:
        return
    current_perms = get_permissions(file_path)
    # Fetch the first user with write permission (or read if no writers)
    owner = current_perms["write"][0] if current_perms["write"] else (current_perms["read"][0] if current_perms["read"] else None)
    if not owner or owner != logged_in_user:
        messagebox.showerror("Access Denied", "Only the first authorized user can manage permissions.")
        return

    perm_window = tk.Toplevel(root)
    perm_window.title(f"Manage Permissions for {os.path.basename(file_path)}")

    user_list = list(users.keys())
    current_perms = get_permissions(file_path)

    read_listbox = tk.Listbox(perm_window, height=10, width=20)
    write_listbox = tk.Listbox(perm_window, height=10, width=20)
    read_listbox.grid(row=0, column=0, padx=10, pady=10)
    write_listbox.grid(row=0, column=1, padx=10, pady=10)

    tk.Label(perm_window, text="Readers").grid(row=1, column=0)
    tk.Label(perm_window, text="Writers").grid(row=1, column=1)

    def update_listboxes():
        read_listbox.delete(0, tk.END)
        write_listbox.delete(0, tk.END)
        for user in current_perms["read"]:
            read_listbox.insert(tk.END, user)
        for user in current_perms["write"]:
            write_listbox.insert(tk.END, user)

    update_listboxes()

    def add_user(permission_type):
        username = simpledialog.askstring(f"Add {permission_type.capitalize()}", f"Enter username to add to {permission_type}:")
        if not username or username not in user_list:
            messagebox.showerror("Error", "Invalid username.")
            return
        if add_permission(file_path, username, permission_type):
            nonlocal current_perms
            current_perms = get_permissions(file_path)
            update_listboxes()

    def remove_user(permission_type):
        username = simpledialog.askstring(f"Remove {permission_type.capitalize()}", f"Enter username to remove from {permission_type}:")
        if not username or username not in user_list:
            messagebox.showerror("Error", "Invalid username.")
            return
        if remove_permission(file_path, username, permission_type):
            nonlocal current_perms
            current_perms = get_permissions(file_path)
            update_listboxes()

    tk.Button(perm_window, text="Add Reader", command=lambda: add_user("read")).grid(row=2, column=0, pady=5)
    tk.Button(perm_window, text="Add Writer", command=lambda: add_user("write")).grid(row=2, column=1, pady=5)
    tk.Button(perm_window, text="Remove Reader", command=lambda: remove_user("read")).grid(row=3, column=0, pady=5)
    tk.Button(perm_window, text="Remove Writer", command=lambda: remove_user("write")).grid(row=3, column=1, pady=5)

# GUI setup
root = tk.Tk()
root.title("Secure File Management System")

# Tabs setup
notebook = tk.ttk.Notebook(root)

# Authentication tab
auth_frame = tk.Frame(notebook)
notebook.add(auth_frame, text="Authentication")

tk.Label(auth_frame, text="Register").pack()
reg_username_entry = tk.Entry(auth_frame)
reg_username_entry.pack()
reg_password_entry = tk.Entry(auth_frame, show="*")
reg_password_entry.pack()
tk.Button(auth_frame, text="Register", command=register).pack()

tk.Label(auth_frame, text="Login").pack()
login_username_entry = tk.Entry(auth_frame)
login_username_entry.pack()
login_password_entry = tk.Entry(auth_frame, show="*")
login_password_entry.pack()
otp_entry = tk.Entry(auth_frame)
otp_entry.pack()
tk.Button(auth_frame, text="Send OTP", command=send_otp).pack()
tk.Button(auth_frame, text="Login", command=login).pack()

# File operations tab
file_ops_frame = tk.Frame(notebook)
notebook.add(file_ops_frame, text="File Operations")

button_frame = tk.Frame(file_ops_frame)
button_frame.pack(expand=True)

tk.Button(button_frame, text="Read File", command=read_file).grid(row=0, column=0, padx=10, pady=10)
tk.Button(button_frame, text="Write File", command=write_file).grid(row=0, column=1, padx=10, pady=10)
tk.Button(button_frame, text="View Metadata", command=view_metadata).grid(row=1, column=0, padx=10, pady=10)
tk.Button(button_frame, text="Scan File", command=scan_file).grid(row=1, column=1, padx=10, pady=10)
tk.Button(button_frame, text="Manage Permissions", command=manage_permissions).grid(row=2, column=0, columnspan=2, padx=10, pady=10)

notebook.pack(expand=True, fill="both")
root.mainloop()