import bcrypt
import pyotp
import smtplib
from tkinter import messagebox
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(10))


password_hash = hash_password("123")
users = {
    "user": {
        "password": password_hash,
        "secret_key": "LGE5ODS2UGBJECQFXG2V6Z3ENXKVB2ZS",
    },
}


def verify_password(password, hashed):
    ans =  bcrypt.checkpw(password.encode('utf-8'), hashed)
    # print(bcrypt.hashpw(password.encode('utf-8'),bcrypt.gensalt(10)), " ",hashed)
    return ans

def register_user(username, password):
    if username in users:
        return "User already exists."
    hashed_password = hash_password(password)
    secret_key = pyotp.random_base32()
    users[username] = {"password": hashed_password, "secret_key": secret_key}
    # print("password:",hashed_password)
    # print()
    # print(users[username]["secret_key"])
    return "User registered successfully."

def generate_otp(username):
    secret_key = users[username]["secret_key"]
    totp = pyotp.TOTP(secret_key)
    otp = totp.now()
    user_email = "user-email"
    try:
        # SMTP Configuration
        sender_email = "sender-email"
        sender_password = ""
        smtp_server = "smtp.gmail.com"
        smtp_port = 587

        # Email Message
        subject = "Your OTP Code"
        message = f"Hello {username},\n\nYour OTP code is: {otp}\n\nThank you!"

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

        messagebox.showinfo("OTP Sent", f"OTP has been sent to {user_email}")
    except Exception as e:
        with open("threat_log.txt", "a") as log_file:
            log_file.write(f"Failed to send OTP: {e}\n")
        messagebox.showerror("Error", f"Failed to send OTP: {e}")

    return otp

def verify_otp(secret_key, otp):
    totp = pyotp.TOTP(secret_key)
    return totp.verify(otp)

def authenticate_user(username, password, otp):
    # print(username, password, otp)
    if username not in users:
        return False
    user = users[username]
    if not verify_password(password, user["password"]):
        return False
    if not verify_otp(user["secret_key"], otp):
        return False
    return True
