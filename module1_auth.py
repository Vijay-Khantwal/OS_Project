import bcrypt
import hashlib
import smtplib
import base64
from tkinter import messagebox
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import random
import string
import time

# Store static OTPs and their expiration times
static_otps = {}

# Helper function to hash passwords
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(10))

# Example user with a hashed password
password_hash = hash_password("123")
users = {
    "user": {
        "password": password_hash,
        "secret_key": "nmgWMPkXMnRFGY6sHqShTFeiCSg5x7VMCKjVmcDFLIk=",
    },
}

# Helper function to verify hashed passwords
def verify_password(password, hashed):
    return bcrypt.checkpw(password.encode('utf-8'), hashed)

# Function to register a new user
def register_user(username, password):
    if username in users:
        return "User already exists."
    
    # Hash the password
    hashed_password = hash_password(password)
    
    # Generate a unique secret key based on the username
    hashed_username = hashlib.sha256(username.encode('utf-8')).digest()
    secret_key = base64.urlsafe_b64encode(hashed_username[:32])
    
    # Store the hashed password and valid Fernet key in the users dictionary
    users[username] = {
        "password": hashed_password,
        "secret_key": secret_key.decode('utf-8'),
    }
    print(f"Generated secret key for {username}: {secret_key.decode('utf-8')}")
    return "User registered successfully."

# Function to generate a static OTP
def generate_static_otp(username, validity=300):
    """Generate a static OTP valid for a specific duration (default: 300 seconds)."""
    if username not in users:
        return "User not found."

    otp = ''.join(random.choices(string.digits, k=6))  # Generate a 6-digit OTP
    expiration_time = time.time() + validity
    static_otps[username] = {"otp": otp, "expires_at": expiration_time}
    user_email = "user-email"
    try:
        # SMTP Configuration
        sender_email = "sender-email"
        sender_password = ""
        smtp_server = "smtp.gmail.com"
        smtp_port = 587

        # Email Message
        subject = "Your Static OTP Code"
        message = f"Hello {username},\n\nYour static OTP code is: {otp}\n\nThis code will expire in {validity//60} minutes.\n\nThank you!"

        msg = MIMEMultipart()
        msg["From"] = sender_email
        msg["To"] = user_email
        msg["Subject"] = subject
        msg.attach(MIMEText(message, "plain"))

        # Sending Email
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, user_email, msg.as_string())
        server.quit()

        messagebox.showinfo("OTP Sent", f"Static OTP has been sent to {user_email}")
    except Exception as e:
        with open("threat_log.txt", "a") as log_file:
            log_file.write(f"Failed to send static OTP: {e}\n")
        messagebox.showerror("Error", f"Failed to send static OTP: {e}")

    return otp

# Function to validate a static OTP
def validate_static_otp(username, otp):
    if username not in static_otps:
        return False
    otp_data = static_otps[username]
    if time.time() > otp_data["expires_at"]:
        del static_otps[username]  # Remove expired OTP
        return False
    if otp_data["otp"] == otp:
        del static_otps[username]  # OTP is valid, remove it after use
        return True
    return False

# Updated authentication to support both static and time-based OTPs
def authenticate_user(username, password, otp):
    if username not in users:
        return False
    user = users[username]
    if not verify_password(password, user["password"]):
        return False
    # Check static OTP
    if validate_static_otp(username, otp):
        return True
    return False
