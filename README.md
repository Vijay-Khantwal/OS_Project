# Secure File Management System

## Description
Develop a secure file management system that incorporates authentication
mechanisms (password-based, two-factor), protection measures (access control,
encryption), and detection of common security threats (buffer overflow, malware). Users
should be able to perform file operations like read, write, share, and view metadata
securely.

## Goals
- Implement authentication mechanisms (password-based, 2FA).
- Secure file operations (encryption, metadata, sharing).
- Detect and log common security threats (malware, buffer overflow).

## Features (Planned)
1. **Authentication:**
   - Password hashing.
   - Two-Factor Authentication (2FA) with OTP.

2. **File Operations:**
   - AES-256 encryption for files.
   - Access control for secure file management.
   - Metadata display and secure sharing.

3. **Threat Detection:**
   - Malware scanning via hash comparison.
   - Buffer overflow prevention.
   - Logging detected threats.

## Technology Stack
- **Python**
