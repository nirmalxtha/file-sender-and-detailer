import os
import hashlib
import json
import socket
from datetime import datetime
import tkinter as tk
from tkinter import filedialog, messagebox
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

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

def get_file_details(file_path):
    stat = os.stat(file_path)
    created = datetime.fromtimestamp(os.path.getctime(file_path)).strftime('%Y-%m-%d %H:%M:%S')
    modified = datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
    accessed = datetime.fromtimestamp(stat.st_atime).strftime('%Y-%m-%d %H:%M:%S')
    size = stat.st_size
    access_count = increment_access_count(file_path)

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            line_count = sum(1 for _ in f)
    except Exception as e:
        line_count = f"Error: {e}"

    print(f"{Fore.YELLOW}[Info]{Style.RESET_ALL} Retrieved file details for: {file_path}")
    return {
        'created': created,
        'modified': modified,
        'accessed': accessed,
        'size': f"{size} bytes",
        'access_count': access_count,
        'line_count': line_count
    }

def send_file_over_tcp(ip, port, file_path):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((ip, port))
            print(f"{Fore.GREEN}[+] Connected to {ip}:{port}{Style.RESET_ALL}")

            filename = os.path.basename(file_path)
            s.sendall(f"{filename}\n".encode())

            with open(file_path, 'rb') as f:
                while chunk := f.read(4096):
                    s.sendall(chunk)

            print(f"{Fore.GREEN}[+] File sent successfully.{Style.RESET_ALL}")

    except ConnectionRefusedError:
        print(f"{Fore.RED}[!] Connection refused: Receiver is not listening.{Style.RESET_ALL}")
        messagebox.showerror("Connection Refused", "File not sent because the receiver is not listening.")

    except socket.gaierror:
        print(f"{Fore.RED}[!] Invalid IP address or host unreachable.{Style.RESET_ALL}")
        messagebox.showerror("Error", "Invalid IP address or unreachable host.")

    except Exception as e:
        print(f"{Fore.RED}[!] Error sending file: {e}{Style.RESET_ALL}")
        messagebox.showerror("Error", f"Failed to send file:\n{e}")

class FileToolGUI:
    def __init__(self, root):
        self.root = root
        self.file_path = None
        self.root.title("Nirmal's ox033 File Detailer & Sender")

        # File Details Section
        self.details_frame = tk.LabelFrame(root, text="File Details", padx=10, pady=10)
        self.details_frame.pack(pady=10, fill="both", expand="yes")

        self.details_box = tk.Text(self.details_frame, height=10, bg="white", font=("Courier", 10), state='disabled')
        self.details_box.pack(fill="both", expand=True)

        # Hash Values Section
        self.hashes_frame = tk.LabelFrame(root, text="Hash Values", padx=10, pady=10)
        self.hashes_frame.pack(pady=10, fill="both", expand="yes")

        self.hashes_box = tk.Text(self.hashes_frame, height=6, bg="white", font=("Courier", 10), state='disabled')
        self.hashes_box.pack(fill="both", expand=True)

        # Controls
        self.browse_button = tk.Button(root, text="Browse File", command=self.browse_file)
        self.browse_button.pack(pady=5)

        self.ip_entry = tk.Entry(root, width=20)
        self.ip_entry.insert(0, "Receiver IP")
        self.ip_entry.pack(pady=5)

        self.port_entry = tk.Entry(root, width=10)
        self.port_entry.insert(0, "Port")
        self.port_entry.pack(pady=5)

        self.send_button = tk.Button(root, text="Send File", command=self.send_file)
        self.send_button.pack(pady=5)

    def update_text_box(self, box, text):
        box.config(state='normal')
        box.delete(1.0, tk.END)
        box.insert(tk.END, text)
        box.config(state='disabled')

    def browse_file(self):
        self.file_path = filedialog.askopenfilename()
        if self.file_path:
            print(f"{Fore.CYAN}[Selected]{Style.RESET_ALL} {self.file_path}")
            details = get_file_details(self.file_path)

            info_text = (
                f"Path: {self.file_path}\n"
                f"Size: {details['size']}\n"
                f"Created: {details['created']}\n"
                f"Modified: {details['modified']}\n"
                f"Accessed: {details['accessed']}\n"
                f"Opened Times: {details['access_count']}\n"
                f"Lines: {details['line_count']}"
            )
            self.update_text_box(self.details_box, info_text)

            hashes = get_hashes(self.file_path)
            hash_text = (
                f"MD5: {hashes['md5']}\n"
                f"SHA1: {hashes['sha1']}\n"
                f"SHA256: {hashes['sha256']}"
            )
            self.update_text_box(self.hashes_box, hash_text)
            print(f"{Fore.GREEN}[Success]{Style.RESET_ALL} File details and hashes updated in GUI.")

    def send_file(self):
        if not self.file_path:
            messagebox.showerror("Error", "No file selected.")
            print(f"{Fore.RED}[!] Send failed: No file selected.{Style.RESET_ALL}")
            return
        ip = self.ip_entry.get()
        try:
            port = int(self.port_entry.get())
        except ValueError:
            messagebox.showerror("Error", "Invalid port number.")
            print(f"{Fore.RED}[!] Send failed: Invalid port.{Style.RESET_ALL}")
            return
        confirm = messagebox.askyesno("Confirm", f"Send file to {ip}:{port}?")
        if confirm:
            send_file_over_tcp(ip, port, self.file_path)
            print(f"{Fore.BLUE}[Info]{Style.RESET_ALL} Attempted to send file to {ip}:{port}")

class StartScreen:
    def __init__(self, root):
        self.root = root
        self.root.title("Startup")

        self.frame = tk.Frame(root)
        self.frame.pack(padx=100, pady=50)

        self.welcome_label = tk.Label(self.frame, text="Welcome to Nirmal's ox033\nFile Detailer & Sender", font=("Helvetica", 16), justify='center')
        self.welcome_label.pack(pady=20)

        self.start_button = tk.Button(self.frame, text="Start", width=10, command=self.start_app)
        self.start_button.pack(pady=10)

        self.exit_button = tk.Button(self.frame, text="Exit", width=10, command=root.quit)
        self.exit_button.pack(pady=5)

        print(f"{Fore.BLUE}[Startup]{Style.RESET_ALL} Application initialized. Ready to start.")

    def start_app(self):
        self.frame.destroy()
        FileToolGUI(self.root)

if __name__ == "__main__":
    root = tk.Tk()
    StartScreen(root)
    root.mainloop()




   















