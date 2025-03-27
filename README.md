# Linux-OrangePi
# File Hosting Server

A lightweight file hosting server for ARM64-based systems running Debian. This server allows you to host files from external drives, share files via links, and serve Minecraft resource packs. It also supports advanced features like 2FA, file compression, scheduled backups, dynamic DNS, and more.

## Features

- Serve files from external drives.
- Generate shareable links for files.
- Serve Minecraft resource packs.
- Two-Factor Authentication (2FA) for admin access.
- File compression (ZIP) for files and directories.
- Scheduled backups of hosted files.
- Dynamic DNS (DDNS) support for custom domains and dynamic IPs.
- Dark mode for the web interface.
- Rate limiting to prevent abuse.
- Log rotation to manage log file size.
- Alerts via email and webhooks for critical events.
- Integration with external services like Dropbox, Google Drive, and AWS S3.

## Installation

### Prerequisites

- ARM64-based Debian system.
- Python 3 installed.
- External drive mounted at `/mnt/external_drive` (or configure a different path in `config.json`).

### Steps

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd /workspaces/Linux-OrangePi
   ```

2. Build the Debian package:
   ```bash
   dpkg-buildpackage -b -us -uc
   ```

3. Install the `.deb` package:
   ```bash
   sudo dpkg -i ../filehosting-server_<version>_arm64.deb
   ```

4. Start the service:
   ```bash
   sudo systemctl start filehosting-server.service
   ```

5. Enable the service to start on boot:
   ```bash
   sudo systemctl enable filehosting-server.service
   ```

## Configuration

The configuration file is located at `/etc/filehosting-server/config.json`. Below are the key settings:

- **`drives`**: List of external drive paths to host files from.
- **`port`**: Port number for the server.
- **`external_domain`**: Custom domain or IP for generating shareable links.
- **`admin_credentials`**: Admin username and password.
- **`ssl_cert`** and **`ssl_key`**: Paths to SSL certificate and key for HTTPS.
- **`rate_limit_window`** and **`rate_limit_requests`**: Rate limiting settings.
- **`enable_2fa`**: Enable or disable Two-Factor Authentication.
- **`backup_schedule`**: Configure scheduled backups.
- **`ddns`**: Dynamic DNS settings for custom domains and dynamic IPs.

## Usage

### Web Interface

Access the web interface at `http://<server-ip>:<port>` (default port: 8080). The dashboard allows you to:

- Browse and upload files.
- Toggle dark mode.
- View logs.
- Generate shareable links.

### API Endpoints

- **`/api/resource-pack?file=<filename>`**: Serve a file as a Minecraft resource pack.
- **`/api/share?file=<filename>`**: Generate a shareable link for a file.

### 2FA Setup

1. Enable 2FA in `config.json` by setting `"enable_2fa": true`.
2. Access the `/2fa` endpoint to get a QR code.
3. Scan the QR code with a TOTP app (e.g., Google Authenticator).

### Scheduled Backups

Backups are stored in the directory specified in `backup_schedule.backup_path`. The default interval is 24 hours.

### Dynamic DNS

Configure your DDNS provider in the `ddns` section of `config.json`. The server will automatically update the IP address with the DDNS provider.

## Logs

Logs are stored at `/var/log/filehosting-server.log`. Log rotation is enabled to prevent excessive file size.

## Contributing

Contributions are welcome! Please submit a pull request or open an issue for any suggestions or bug reports.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.