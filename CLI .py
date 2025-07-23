import os                                                                                                                                  
import hashlib
import json
import socket
from datetime import datetime


# File to store access count
access_count_file = "file_access_log.json"

def load_access_count():
    if os.path.exists(access_count_file):
        with open(access_count_file, 'r') as f:
            return json.load(f)
    return {}

def save_access_count(data):
    with open(access_count_file, 'w') as f:
        json.dump(data, f)

def increment_access_count(file_path):
    data = load_access_count()
    key = os.path.abspath(file_path)
    data[key] = data.get(key, 0) + 1
    save_access_count(data)
    return data[key]

# Compute hashes
def get_hashes(file_path):
    md5_hash = hashlib.md5()
    sha1_hash = hashlib.sha1()
    sha256_hash = hashlib.sha256()

    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            md5_hash.update(chunk)
            sha1_hash.update(chunk)
            sha256_hash.update(chunk)

    return {
        'md5': md5_hash.hexdigest(),
        'sha1': sha1_hash.hexdigest(),
        'sha256': sha256_hash.hexdigest()
    }

# Get file metadata
def get_file_details(file_path):
    stat = os.stat(file_path)
    created = datetime.fromtimestamp(os.path.getctime(file_path)).strftime('%Y-%m-%d %H:%M:%S')
    modified = datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
    accessed = datetime.fromtimestamp(stat.st_atime).strftime('%Y-%m-%d %H:%M:%S')
    size = stat.st_size
    access_count = increment_access_count(file_path)

    # Detect binary files
    try:
        with open(file_path, 'rb') as f:
            chunk = f.read(1024)
            if b'\x00' in chunk:  # Binary if contains null byte
                line_count = "Error: File appears to be binary"
            else:
                # Try counting lines as UTF-8
                with open(file_path, 'r', encoding='utf-8', errors='replace') as text_f:
                    line_count = sum(1 for _ in text_f)
    except Exception as e:
        line_count = f"Error: {e}"

    return {
        'created': created,
        'modified': modified,
        'accessed': accessed,
        'size': f"{size} bytes",
        'access_count': access_count,
        'line_count': line_count
    }

# Send file over TCP
def send_file_over_tcp(ip, port, file_path):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((ip, port))
            print(f"[+] Connected to {ip}:{port}")

            # Optional: Send filename first
            filename = os.path.basename(file_path)
            s.sendall(f"{filename}\n".encode())

            # Send file content in chunks
            with open(file_path, 'rb') as f:
                while chunk := f.read(4096):
                    s.sendall(chunk)
            print("[+] File sent successfully.")
    except Exception as e:
        print(f"[!] Error sending file: {e}")

# CLI Interface (for running manually)
def cli_mode(input_func=input, print_func=print):
    print_func("=== Nirmal's ox033 File Detailer & Sender ===")
    print_func("Welcome to Nirmal's ox033 File Detailers and Sender\n")

    choice = input_func("Would you like to start? (y/n): ").strip().lower()
    if choice != 'y':
        print_func("Exiting program. Goodbye!")
        return

    file_path = input_func("Enter file path: ").strip()

    # Expand ~ and resolve relative paths
    try:
        file_path = os.path.abspath(os.path.expanduser(file_path))
    except Exception as e:
        print_func(f"[-] Error resolving path: {e}")
        return

    if not os.path.isfile(file_path):
        print_func(f"[-] Invalid file path. File does not exist:\n{file_path}")
        return

    # Show file details
    try:
        details = get_file_details(file_path)
        hashes = get_hashes(file_path)
        print_func("\n[+] File Details:")
        for k, v in details.items():
            print_func(f"{k}: {v}")
        print_func("\nHashes:")
        for k, v in hashes.items():
            print_func(f"{k.upper()}: {v}")
    except Exception as e:
        print_func(f"[-] Error reading file: {e}")
        return

    # Send over network
    if input_func("\nSend file over network? (y/n): ").lower() == 'y':
        ip = input_func("Enter receiver IP: ")
        try:
            port = int(input_func("Enter receiver port: "))
        except ValueError:
            print_func("[-] Port must be a number.")
            return

        send_file_over_tcp(ip, port, file_path)
        print_func("[+] File sent successfully.")

# Main Entry Point
if __name__ == "__main__":
    cli_mode()

    


   















