# Secure File Management System

## Description

The Secure File Management System is a Python-based application designed to provide secure file handling, robust authentication, and threat detection. It incorporates:

1. **Authentication mechanisms** (password-based, two-factor authentication)
2. **Protection measures** (access control, encryption)
3. **Detection of common security threats** (buffer overflow, malware)

Users can securely perform file operations like reading, writing, sharing, and viewing metadata while ensuring protection against unauthorized access and malicious threats.

---

## 1. Project Overview

### Goals

- Create a secure system for managing files with authentication, encryption, access control, and threat detection.
- Ensure secure handling of file operations (read, write, share, view metadata).
- Protect against common security threats like unauthorized access, malware, and buffer overflow.

### Expected Outcomes

- A functional system where users can securely authenticate, perform file operations, and detect security threats.
- Implementation of two-factor authentication (2FA) for added security.
- Encryption and decryption of files to prevent unauthorized access.
- Threat detection algorithms to identify and flag potential security risks.

---

## 2. Module-Wise Breakdown

### Module 1: Authentication

**Purpose:** Ensure secure access to the system using robust authentication mechanisms.

**Functionalities:**

- **Password-based authentication:**
    - Passwords are hashed using `bcrypt` for secure storage.
    - Users can register and manage their credentials.

- **Two-Factor Authentication (2FA):**
    - OTPs are generated randomly and validated during login.
    - OTPs can be displayed or sent via email (email functionality is commented out for now).

**Workflow:**

1. **Registration:**
    - Users register with a username and password.
    - Passwords are hashed and stored securely.
    - A unique secret key is generated for each user for OTP-based 2FA.

2. **Login:**
    - Users log in with their username, password, and OTP.
    - Passwords are verified against the stored hash.
    - OTPs are validated using the user's secret key.

---

### Module 2: Secure File Operations

**Purpose:** Provide secure mechanisms for performing file operations.

**Functionalities:**

- **File Encryption/Decryption:**
    - Files are encrypted using AES-256 encryption (`cryptography` library).
    - Only authorized users can decrypt and access the file contents.

- **Access Control:**
    - File operations are restricted to logged-in users.

- **File Metadata Management:**
    - Metadata such as file size, creation date, and modification date is displayed.

- **File Sharing:**
    - Files can be securely shared with others using encryption.

**Workflow:**

1. **Encrypt File:**
    - Users can write content to a file, which is encrypted and saved with a `.enc` extension.

2. **Decrypt File:**
    - Users can select an encrypted file to decrypt and view its contents.

3. **View Metadata:**
    - Users can view metadata (e.g., size, creation date) of any file.

---

### Module 3: Security Threat Detection

**Purpose:** Identify and mitigate common security risks like malware and buffer overflow.

**Functionalities:**

- **Malware Detection:**
    - Files are scanned for known malware signatures using hash comparison.
    - If a match is found, the file is flagged as malicious.

- **Buffer Overflow Protection:**
    - Input sizes are validated to prevent buffer overflow attacks.
    - Suspicious patterns (e.g., long sequences of characters) are logged.

- **Threat Reporting:**
    - Detected threats are logged in `threat_log.txt`.

**Workflow:**

1. **Scan File:**
    - Users can scan files for malware.
    - If a file matches a known malicious hash, it is flagged, and the threat is logged.

2. **Validate Input:**
    - User inputs are validated against common buffer overflow patterns.
    - Suspicious inputs are flagged and logged.

---

## 3. Functionalities (Key Features)

| **Module**           | **Features**                                                                 |
|-----------------------|-----------------------------------------------------------------------------|
| **Authentication**   | Password hashing, 2FA (OTP generation and validation), Role-based authentication. |
| **Secure File Operations** | File encryption/decryption, access control, metadata viewing, secure sharing with expirable links. |
| **Threat Detection**  | Malware pattern scanning, buffer overflow prevention, security logs and alerts. |

---

## 4. Technology Stack

### Programming Language

- **Python:** Used for implementing encryption, authentication, and threat detection.

### Libraries and Tools

- **Authentication:**
    - `bcrypt` for password hashing.

- **File Encryption:**
    - `cryptography` library for AES-256 encryption.

- **Threat Detection:**
    - `hashlib` for malware detection using hash comparison.
    - `re` for input validation against buffer overflow patterns.

- **GUI:**
    - `tkinter` for building the graphical user interface.

---

## 5. Execution Plan

### Step 1: Set Up the Environment

Install the required libraries:

```bash
pip install bcrypt cryptography

python main.py
```

## 6. File Structure

```
OS_Project/
├── module1_auth.py
├── module2_file_ops.py
├── module3_threat_detect.py
├── main.py
├── readme.md
├── threat_log.txt
```

---

## 7. Logging and Debugging

- **Threat Logs:**
    - All detected threats (e.g., malware, buffer overflow attempts) are logged in `threat_log.txt`.

- **Debugging:**
    - Print statements are used in the authentication module for debugging purposes.

---


## 8. Future Enhancements

- **Email Integration:**
    - Enable email-based OTP delivery by uncommenting the SMTP code in `module1_auth.py`.

- **Dynamic Malware Database:**
    - Integrate with an external malware signature database for real-time updates.

- **Role-Based Access Control:**
    - Implement roles (e.g., Admin, User) to restrict access to certain features.

- **Web-Based Interface:**
    - Replace the `tkinter` GUI with a web-based interface using Flask or Django.

---
