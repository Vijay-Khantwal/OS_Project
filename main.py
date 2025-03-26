import tkinter as tk
from tkinter import ttk
from tkinter import messagebox, filedialog
from module1_auth import register_user, authenticate_user, generate_static_otp, users
from module2_file_ops import encrypt_file, decrypt_file, get_file_metadata
from module3_threat_detect import detect_malware, log_threat, detect_malware, validate_input

logged_in_user = None

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
    if(result):
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
    content = decrypt_file(logged_in_user,file_path)
    messagebox.showinfo("File Content", content)

def write_file():
    if not check_login_required():
        return

    # Create a popup window for text input
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
            encrypt_file(logged_in_user,file_path, content)
            messagebox.showinfo("Success", "File saved and encrypted.")
            popup.destroy()

    tk.Button(popup, text="Save", command=save_file).pack(pady=10)

def view_metadata():
    if not check_login_required():
        return
    file_path = filedialog.askopenfilename()
    metadata = get_file_metadata(file_path)
    messagebox.showinfo("File Metadata", f"Name: {metadata['name']}\nSize: {metadata['size']} bytes\nCreator: {metadata['creator']}\nCreated: {metadata['created']}\nModified: {metadata['modified']}")

def scan_file():
    if not check_login_required():
        return
    file_path = filedialog.askopenfilename()
    is_malware = detect_malware(decrypt_file(file_path))
    if is_malware:
        messagebox.showerror("Threat Detected", f"Malware detected in file: {file_path}")
        log_threat(file_path, "Malware detected")
    else:
        messagebox.showinfo("Safe", "No threats detected.")


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

# Clear any existing layout manager in the frame
for widget in file_ops_frame.winfo_children():
    widget.pack_forget()

# Add a text area above the grid layout
# text_area = tk.Text(file_ops_frame, height=5)
# text_area.grid(row=2, column=0, columnspan=2, padx=10, pady=10)

# Arrange buttons in a grid layout
# Create a frame to center the buttons
button_frame = tk.Frame(file_ops_frame)
button_frame.pack(expand=True)

# Arrange buttons in a grid layout within the centered frame
tk.Button(button_frame, text="Read File", command=read_file).grid(row=0, column=0, padx=10, pady=10)
tk.Button(button_frame, text="Write File", command=write_file).grid(row=0, column=1, padx=10, pady=10)
tk.Button(button_frame, text="View Metadata", command=view_metadata).grid(row=1, column=0, padx=10, pady=10)
tk.Button(button_frame, text="Scan File", command=scan_file).grid(row=1, column=1, padx=10, pady=10)

notebook.pack(expand=True, fill="both")
root.mainloop()
