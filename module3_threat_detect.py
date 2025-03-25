import hashlib
import re

# Mock antivirus hash database (to simulate malware detection)
KNOWN_MALICIOUS_HASHES = {
    "098f6bcd4621d373cade4e832627b4f6",  # Example hash for "test"
}

def calculate_file_hash(file_path):
    hash_md5 = hashlib.md5()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
    except Exception as e:
        return None, str(e)
    return hash_md5.hexdigest(), None


def detect_malware(file_content):

    file_hash = hashlib.md5(file_content.encode('utf-8')).hexdigest()
    if file_hash in KNOWN_MALICIOUS_HASHES:
        with open("threat_log.txt", "a") as log_file:
            log_file.write(f"Malware Detected: File hash {file_hash} matches known malicious hash.\n")
        return True
    return False

def validate_input(input_data):
    """
    Validate input against common buffer overflow patterns.
    """
    patterns = [
        r"(?:\x90{3,})",  # NOP sleds
        r"(?:A{5,})",     # Long sequence of 'A's
    ]
    for pattern in patterns:
        if re.search(pattern, input_data):
            with open("threat_log.txt", "a") as log_file:
                log_file.write(f"Suspicious Pattern Detected: {pattern} found in input.\n")
            return False
    return True

def log_threat(file_path, threat_type):
    with open("threat_log.txt", "a") as log_file:
        log_file.write(f"Threat: {threat_type}\nFile: {file_path}\n\n")
