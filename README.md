# Firewall-Auto-Blocker
A Python script to enhance server security by analyzing login attempt logs and automatically blocking suspicious IP addresses. It detects failed logins exceeding a custom threshold, utilizes `firewalld` to create a block zone, and efficiently manages IP blocking to mitigate brute-force attacks.

# Firewall Auto Blocker

A Python script to enhance server security by analyzing login attempt logs and automatically blocking suspicious IP addresses. It helps mitigate brute-force attacks by leveraging `firewalld` to create a block zone and efficiently manage IP blocking.

## Features
- Automatically analyzes login attempt logs for failed logins (e.g., `Invalid user`, `Failed password`).
- Blocks IPs that exceed a predefined threshold of failed login attempts.
- Uses a custom block zone in `firewalld` to manage blocked IPs.
- Excludes trusted IPs from blocking via an ignore list.
- Logs performance metrics for analysis efficiency.

## Requirements
1. Python 3.6+
2. `firewalld` must be installed and running on the server.

## Installation
1. Clone this repository:
   ```bash
   git clone https://github.com/Bartos-Pol/firewall-auto-blocker.git
   cd firewall-auto-blocker
   ```
2. Ensure Python 3.x is installed on your server.
3. Verify that `firewalld` is installed and running:
   ```bash
   sudo systemctl status firewalld
   ```
4. Run the script with sufficient permissions (requires root for firewall interactions).

## Usage
1. Update the log file path in the script (default: `/var/log/secure` for CentOS/RHEL-based systems).
   ```python
   log_file = "/var/log/secure"
   ```
2. Run the script as root or with elevated permissions:
   ```bash
   sudo python3 script.py
   ```

## Configuration
The script provides customizable settings:
- **Ignored IPs**: Modify the `IGNORED_IPS` set to include IP addresses you want to exclude from blocking.
- **Blocking Threshold**: Configure `ATTEMPT_THRESHOLD` to set the number of failed attempts before an IP is blocked.
- **Firewall Block Zone**: Define a custom block zone name in the `BLOCK_ZONE` variable.

### Example
Change the following variables in the script as needed:
```python
IGNORED_IPS = {"127.0.0.1", "192.168.0.1"}  # List of IPs to ignore
BLOCK_ZONE = "SecurityBlock"  # Name of the firewall block zone
ATTEMPT_THRESHOLD = 3  # Minimum number of failed attempts to block an IP
```

## How It Works
1. Reads the system logs to count failed login attempts (keywords: `Invalid user`, `Failed password`).
2. Matches and extracts IP addresses using regex.
3. Ignores IPs listed in `IGNORED_IPS`.
4. Identifies IPs that exceed the `ATTEMPT_THRESHOLD`.
5. Automatically adds offending IPs to the `firewalld` block zone (creates the zone if not present).
6. Reloads the firewall to apply new rules.

## Example Output
After analyzing the logs, the script will display a summary like this:
