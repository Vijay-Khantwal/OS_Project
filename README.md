  # Secure File Management System

  ## Description

  The Secure File Management System is a Python-based application designed to provide secure file handling, robust authentication, and threat detection. It incorporates:

  1. **Authentication mechanisms** (password-based, two-factor authentication)
  2. **Protection measures** (access control, encryption)
  3. **Detection of common security threats** (buffer overflow, malware)

  Users can securely perform file operations like reading, writing, sharing, and viewing metadata while ensuring protection against unauthorized access and malicious threats.

  ---
## Project Overview
The **Secure File Management System** is a Python-based application designed to provide a secure environment for file handling. It integrates robust authentication, protection mechanisms, and threat detection to ensure users can safely perform file operations such as reading, writing, sharing, and viewing metadata.

### Goals:
- Implement password-based and two-factor authentication (2FA) for secure access.
- Use encryption and access control to protect files.
- Detect and mitigate security threats like buffer overflow and malware.

### Expected Outcomes:
- A functional system with a **Tkinter GUI**, offering secure file operations and real-time threat detection.
- Persistent user, file key, and permission data across sessions via JSON files.

### Scope:
- Focuses on local file management for individual users, with secure sharing controlled by file creators.

---

## Module-Wise Breakdown

### **Module 1: Authentication (module1_auth.py)**
- **Purpose:** Ensures only authorized users access the system.
- **Role:** Manages user registration, login, and OTP-based 2FA, with persistent storage in `users.json`.

### **Module 2: Secure File Operations (module2_p1_file_ops.py & module2_p2_access_matrix.py)**
- **Purpose:** Provides secure mechanisms for file handling and sharing.
- **Role:** 
  - Encrypts files and manages file-specific keys in `file_keys.json`.
  - Controls access via an access matrix stored in `access_matrix.json`.

### **Module 3: Security Threat Detection (module3_threat_detect.py)**
- **Purpose:** Identifies and mitigates security risks.
- **Role:**
  - Scans files for malware.
  - Validates inputs to prevent buffer overflow.
  - Logs threats in `threat_log.txt`.

---

## Functionalities

### **Module 1: Authentication**
- **User Registration:**
  - Hashes passwords with `bcrypt`.
  - Generates secret keys stored in `users.json`.
- **Login with 2FA:**
  - Verifies password and OTP (displayed or optionally emailed).
- **Persistence:**
  - User data is stored persistently in `users.json`.

### **Module 2: Secure File Operations**
- **Encryption/Decryption:**
  - Uses AES-256 (`Fernet`) for file encryption.
  - Keys are encrypted by the creator’s secret key.
- **Access Control:**
  - Manages read/write permissions through an access matrix (`access_matrix.json`).
  - Only the first authorized user can share files.
- **Metadata Viewing:**
  - Displays file details such as name, size, creator, and dates.
- **Sharing:**
  - File creator assigns permissions via a GUI, stored in `access_matrix.json`.

### **Module 3: Security Threat Detection**
- **Malware Detection:**
  - Compares file hashes against a static malware database.
- **Buffer Overflow Prevention:**
  - Validates inputs with `regex` to detect suspicious patterns (e.g., NOP sleds).
- **Threat Logging:**
  - Records detected threats in `threat_log.txt`.

---

## Technology Used

### **Programming Languages**
- **Python:** Core language for implementation, chosen for its versatility and extensive library support.

### **Libraries and Tools**
- **bcrypt:** Secure password hashing.
- **cryptography:** AES-256 encryption via Fernet.
- **hashlib:** Malware detection using MD5 hashing.
- **re:** Regex-based input validation.
- **tkinter:** GUI framework (standard library).
- **json:** Persistent storage for users, keys, and permissions.


  ## Execution Plan
  1. Install the required libraries:
    ```bash
    pip install bcrypt cryptography
    python main.py
  2. Run the application:
    ```bash
    python main.py


 ## File Structure
  ```bash
  OS_Project/
  ├── module1_auth.py         # Authentication module
  ├── module2_file_ops.py     # File operations module
  ├── module3_threat_detect.py # Threat detection module
  ├── main.py                 # Main entry point
  ├── readme.md               # Documentation
  ├── threat_log.txt          # Threat logs
  |
  |__ users.json              # Store users across sessions
  |__ file_keys.json          # Encrypted Keys for file access 
  |__ access_matrix.json      # Storing permissions for file sharing
  ```


  ## Logging and Debugging

  - **Threat Logs:**
      - All detected threats (e.g., malware, buffer overflow attempts) are logged in threat_log.txt.

  - **Debugging:**
      - Print statements are used in the authentication module for debugging purposes.

  ---