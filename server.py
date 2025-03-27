import os
import shutil
import json
import ssl
import signal
import base64
from http.server import SimpleHTTPRequestHandler, HTTPServer
from urllib.parse import unquote, parse_qs
from collections import defaultdict
import time
import smtplib
from email.mime.text import MIMEText
import requests
from pathlib import Path
import pyotp  # For 2FA
import zipfile  # For file compression
import threading  # For scheduled backups

CONFIG_PATH = "/etc/filehosting-server/config.json"
LOG_FILE = "/var/log/filehosting-server.log"

# Load configuration
def load_config():
    with open(CONFIG_PATH, "r") as config_file:
        return json.load(config_file)

config = load_config()

EXTERNAL_DRIVE_PATHS = config.get("drives", ["/mnt/external_drive"])
PORT = config.get("port", 8080)
EXTERNAL_DOMAIN = config.get("external_domain", None)
ADMIN_CREDENTIALS = config.get("admin_credentials", {"username": "admin", "password": "admin"})
SSL_CERT = config.get("ssl_cert", None)
SSL_KEY = config.get("ssl_key", None)
RATE_LIMIT_WINDOW = config.get("rate_limit_window", 60)  # seconds
RATE_LIMIT_REQUESTS = config.get("rate_limit_requests", 100)  # max requests per IP per window
ENABLE_DYNAMIC_RELOAD = config.get("enable_dynamic_reload", True)
LOG_ROTATION_SIZE = config.get("log_rotation_size", 5 * 1024 * 1024)  # 5 MB
ALERT_EMAIL = config.get("alert_email", None)
WEBHOOK_URL = config.get("webhook_url", None)
ENABLE_DARK_MODE = config.get("enable_dark_mode", False)
EXTERNAL_SERVICES = config.get("external_services", {})
BACKUP_SCHEDULE = config.get("backup_schedule", {"enabled": False, "interval_hours": 24, "backup_path": "/backups"})

# Initialize 2FA
TOTP_SECRET = config.get("totp_secret", pyotp.random_base32())
totp = pyotp.TOTP(TOTP_SECRET)

rate_limit_data = defaultdict(list)

def reload_config(signum, frame):
    global config, EXTERNAL_DRIVE_PATHS, PORT, EXTERNAL_DOMAIN, ADMIN_CREDENTIALS, SSL_CERT, SSL_KEY
    config = load_config()
    EXTERNAL_DRIVE_PATHS = config.get("drives", ["/mnt/external_drive"])
    PORT = config.get("port", 8080)
    EXTERNAL_DOMAIN = config.get("external_domain", None)
    ADMIN_CREDENTIALS = config.get("admin_credentials", {"username": "admin", "password": "admin"})
    SSL_CERT = config.get("ssl_cert", None)
    SSL_KEY = config.get("ssl_key", None)
    print("Configuration reloaded.")

if ENABLE_DYNAMIC_RELOAD:
    signal.signal(signal.SIGHUP, reload_config)

def send_alert(subject, message):
    if ALERT_EMAIL:
        msg = MIMEText(message)
        msg["Subject"] = subject
        msg["From"] = "server@example.com"
        msg["To"] = ALERT_EMAIL
        with smtplib.SMTP("localhost") as server:
            server.sendmail("server@example.com", [ALERT_EMAIL], msg.as_string())
    if WEBHOOK_URL:
        requests.post(WEBHOOK_URL, json={"text": f"{subject}: {message}"})

def rotate_log():
    if os.path.exists(LOG_FILE) and os.path.getsize(LOG_FILE) > LOG_ROTATION_SIZE:
        os.rename(LOG_FILE, f"{LOG_FILE}.1")

def schedule_backups():
    if BACKUP_SCHEDULE["enabled"]:
        backup_path = BACKUP_SCHEDULE["backup_path"]
        os.makedirs(backup_path, exist_ok=True)
        while True:
            timestamp = time.strftime("%Y%m%d%H%M%S")
            backup_file = os.path.join(backup_path, f"backup_{timestamp}.zip")
            with zipfile.ZipFile(backup_file, "w") as backup_zip:
                for drive in EXTERNAL_DRIVE_PATHS:
                    for root, _, files in os.walk(drive):
                        for file in files:
                            file_path = os.path.join(root, file)
                            backup_zip.write(file_path, os.path.relpath(file_path, drive))
            print(f"Backup created: {backup_file}")
            time.sleep(BACKUP_SCHEDULE["interval_hours"] * 3600)

class FileHostingHandler(SimpleHTTPRequestHandler):
    def translate_path(self, path):
        # Serve files from the first accessible drive
        path = super().translate_path(path)
        for drive in EXTERNAL_DRIVE_PATHS:
            potential_path = os.path.join(drive, os.path.relpath(path, os.getcwd()))
            if os.path.exists(potential_path):
                return potential_path
        return os.path.join(EXTERNAL_DRIVE_PATHS[0], os.path.relpath(path, os.getcwd()))

    def do_GET(self):
        if not self.rate_limit():
            self.send_response(429, "Too Many Requests")
            self.end_headers()
            return

        if self.path == "/":
            # Serve the admin dashboard
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(self.generate_dashboard().encode())
        elif self.path == "/log":
            # Serve the log file
            self.send_response(200)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            with open(LOG_FILE, "r") as log_file:
                self.wfile.write(log_file.read().encode())
        elif self.path.startswith("/files"):
            # Serve a list of files or search results
            query = parse_qs(self.path.split("?")[1]) if "?" in self.path else {}
            search_query = query.get("search", [None])[0]
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            files = self.list_files(search_query)
            self.wfile.write(json.dumps(files).encode())
        elif self.path == "/status":
            # Serve server health status
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            status = self.get_status()
            self.wfile.write(json.dumps(status).encode())
        elif self.path.startswith("/share"):
            # Generate a file sharing link
            query = parse_qs(self.path.split("?")[1]) if "?" in self.path else {}
            file_name = query.get("file", [None])[0]
            if file_name:
                share_link = f"{EXTERNAL_DOMAIN}/files/{file_name}"
                self.send_response(200)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"share_link": share_link}).encode())
            else:
                self.send_response(400, "Bad Request")
                self.end_headers()
        elif self.path.startswith("/compress"):
            # Compress a file or directory
            query = parse_qs(self.path.split("?")[1]) if "?" in self.path else {}
            file_name = query.get("file", [None])[0]
            if file_name:
                file_path = os.path.join(EXTERNAL_DRIVE_PATHS[0], file_name)
                compressed_file = f"{file_path}.zip"
                with zipfile.ZipFile(compressed_file, "w") as zipf:
                    if os.path.isdir(file_path):
                        for root, _, files in os.walk(file_path):
                            for file in files:
                                zipf.write(os.path.join(root, file), os.path.relpath(os.path.join(root, file), file_path))
                    else:
                        zipf.write(file_path, os.path.basename(file_path))
                self.send_response(200)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"compressed_file": compressed_file}).encode())
            else:
                self.send_response(400, "Bad Request")
                self.end_headers()
        elif self.path == "/2fa":
            # Serve the 2FA QR code
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            qr_code = totp.provisioning_uri(name="FileHostingServer", issuer_name="FileHosting")
            self.wfile.write(f"<h1>Scan this QR code with your 2FA app</h1><p>{qr_code}</p>".encode())
        elif self.path.startswith("/api/resource-pack"):
            # Serve a Minecraft resource pack
            query = parse_qs(self.path.split("?")[1]) if "?" in self.path else {}
            file_name = query.get("file", [None])[0]
            if file_name:
                file_path = os.path.join(EXTERNAL_DRIVE_PATHS[0], file_name)
                if os.path.exists(file_path):
                    self.send_response(200)
                    self.send_header("Content-Type", "application/octet-stream")
                    self.send_header("Content-Disposition", f"attachment; filename={os.path.basename(file_path)}")
                    self.send_header("Access-Control-Allow-Origin", "*")
                    self.end_headers()
                    with open(file_path, "rb") as f:
                        shutil.copyfileobj(f, self.wfile)
                else:
                    self.send_response(404, "File Not Found")
                    self.end_headers()
            else:
                self.send_response(400, "Bad Request")
                self.end_headers()
        elif self.path.startswith("/api/share"):
            # Generate a shareable link for a file
            query = parse_qs(self.path.split("?")[1]) if "?" in self.path else {}
            file_name = query.get("file", [None])[0]
            if file_name:
                share_link = f"{EXTERNAL_DOMAIN}/api/resource-pack?file={file_name}"
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"share_link": share_link}).encode())
            else:
                self.send_response(400, "Bad Request")
                self.end_headers()
        else:
            super().do_GET()

    def do_POST(self):
        # Handle file uploads and dark mode toggle
        if self.path == "/upload":
            file_length = int(self.headers['Content-Length'])
            file_data = self.rfile.read(file_length)
            file_name = self.headers.get("X-File-Name", "uploaded_file")
            file_path = os.path.join(EXTERNAL_DRIVE_PATHS[0], file_name)
            with open(file_path, "wb") as f:
                f.write(file_data)
            self.send_response(201, "Created")
            self.end_headers()
        elif self.path == "/toggle-dark-mode":
            global ENABLE_DARK_MODE
            ENABLE_DARK_MODE = not ENABLE_DARK_MODE
            self.send_response(200, "OK")
            self.end_headers()
        else:
            # Authenticate admin credentials
            if not self.authenticate():
                self.send_response(401, "Unauthorized")
            else:
                self.send_response(404, "Not Found")
            self.end_headers()

    def do_MKCOL(self):
        # Authenticate admin credentials
        if not self.authenticate():
            self.send_response(401, "Unauthorized")
            self.end_headers()
            return
        # Handle directory creation
        dir_path = self.translate_path(self.path)
        if not os.path.exists(dir_path):
            os.makedirs(dir_path)
            self.send_response(201, "Created")
        else:
            self.send_response(405, "Method Not Allowed")
        self.end_headers()

    def authenticate(self):
        # Basic authentication for admin credentials with optional 2FA
        auth_header = self.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Basic "):
            return False
        encoded_credentials = auth_header.split(" ")[1]
        decoded_credentials = base64.b64decode(encoded_credentials).decode()
        username, password = decoded_credentials.split(":")
        if username == ADMIN_CREDENTIALS["username"] and password == ADMIN_CREDENTIALS["password"]:
            # Check 2FA if enabled
            if config.get("enable_2fa", False):
                totp_token = self.headers.get("X-TOTP-Token")
                return totp.verify(totp_token)
            return True
        return False

    def generate_dashboard(self):
        # Generate a responsive HTML dashboard with dark mode toggle
        dark_mode_class = "dark-mode" if ENABLE_DARK_MODE else ""
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>File Hosting Server</title>
            <style>
                body {{ font-family: Arial, sans-serif; }}
                .dark-mode {{ background-color: #121212; color: #ffffff; }}
                .file-manager {{ margin-top: 20px; }}
                .file {{ margin: 5px 0; }}
            </style>
        </head>
        <body class="{dark_mode_class}">
            <h1>Welcome to the File Hosting Server</h1>
            <p>Admin Username: {ADMIN_CREDENTIALS['username']}</p>
            <p>Admin Password: {ADMIN_CREDENTIALS['password']}</p>
            <h2>Logs</h2>
            <a href="/log">View Logs</a>
            <h2>Files</h2>
            <div class="file-manager">
                <a href="/files">Browse Files</a>
                <form action="/upload" method="post" enctype="multipart/form-data">
                    <input type="file" name="file">
                    <button type="submit">Upload</button>
                </form>
            </div>
            <h2>Dark Mode</h2>
            <form action="/toggle-dark-mode" method="post">
                <button type="submit">Toggle Dark Mode</button>
            </form>
        </body>
        </html>
        """

    def rate_limit(self):
        client_ip = self.client_address[0]
        current_time = time.time()
        request_times = rate_limit_data[client_ip]

        # Remove outdated requests
        rate_limit_data[client_ip] = [t for t in request_times if current_time - t < RATE_LIMIT_WINDOW]

        # Check if the client exceeds the rate limit
        if len(rate_limit_data[client_ip]) >= RATE_LIMIT_REQUESTS:
            return False

        # Record the current request
        rate_limit_data[client_ip].append(current_time)
        return True

    def list_files(self, search_query=None):
        # List all files in the external drives or filter by search query
        files = []
        for drive in EXTERNAL_DRIVE_PATHS:
            for root, _, filenames in os.walk(drive):
                for filename in filenames:
                    if not search_query or search_query.lower() in filename.lower():
                        files.append(os.path.relpath(os.path.join(root, filename), drive))
        return files

    def get_status(self):
        # Include server health and disk space monitoring
        status = {"drives": []}
        for drive in EXTERNAL_DRIVE_PATHS:
            total, used, free = shutil.disk_usage(drive)
            status["drives"].append({
                "path": drive,
                "total_space": total,
                "used_space": used,
                "free_space": free
            })
            if free < 100 * 1024 * 1024:  # 100 MB
                send_alert("Low Disk Space", f"Drive {drive['path']} is running low on space.")
        return status

    def log_message(self, format, *args):
        # Enhanced logging with client IP and request details
        rotate_log()
        log_entry = f"{self.log_date_time_string()} - {self.client_address[0]} - {self.command} {self.path} - {format % args}\n"
        with open(LOG_FILE, "a") as log_file:
            log_file.write(log_entry)

def run_server():
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)  # Ensure log directory exists
    os.chdir(EXTERNAL_DRIVE_PATHS[0])  # Change to the first external drive directory
    server_address = ('', PORT)
    httpd = HTTPServer(server_address, FileHostingHandler)
    if SSL_CERT and SSL_KEY:
        httpd.socket = ssl.wrap_socket(httpd.socket, certfile=SSL_CERT, keyfile=SSL_KEY, server_side=True)
        print("HTTPS enabled")
    print(f"Serving files on port {PORT} from {EXTERNAL_DRIVE_PATHS}")
    if EXTERNAL_DOMAIN:
        print(f"Accessible externally via: {EXTERNAL_DOMAIN}")
    httpd.serve_forever()

# Start backup scheduler in a separate thread
if BACKUP_SCHEDULE["enabled"]:
    threading.Thread(target=schedule_backups, daemon=True).start()

# Start IP monitoring in a separate thread
if DDNS_CONFIG["enabled"]:
    threading.Thread(target=monitor_ip_changes, daemon=True).start()

if __name__ == "__main__":
    run_server()
