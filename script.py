import re
import subprocess
from collections import Counter
from time import time  # Used for performance measurement

# List of IPs to ignore and block zone name
IGNORED_IPS = {"127.0.0.1", "192.168.0.1"}  # Using a set for faster membership checks
BLOCK_ZONE = "SecurityBlock"  # Name of the firewall block zone
ATTEMPT_THRESHOLD = 3  # Minimum number of login attempts to trigger IP blocking


def run_command(command):
    """
    Executes a system command using subprocess and returns the output.

    Args:
        command (list): The system command to be executed as a list of strings.

    Returns:
        str: Standard output of the command if successfully executed.
        str: Empty string in case of an error.
    """
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"Error executing command '{' '.join(command)}': {e.stderr.strip()}")
        return ""
    except Exception as e:
        print(f"Unexpected error: {e}")
        return ""


def ensure_block_zone():
    """
    Ensures that the firewall block zone exists, or creates it if missing.

    Returns:
        bool: True if the block zone exists or is successfully created. False otherwise.
    """
    zones = run_command(["firewall-cmd", "--get-zones"])
    if BLOCK_ZONE in zones.split():
        return True

    print(f"The block zone '{BLOCK_ZONE}' does not exist. Creating it...")
    if run_command(["firewall-cmd", "--permanent", "--new-zone=" + BLOCK_ZONE]):
        print(f"The block zone '{BLOCK_ZONE}' has been created.")
        if run_command(["firewall-cmd", "--reload"]):
            print("Firewall reloaded successfully.")
            return True
    return False


def get_blocked_ips():
    """
    Retrieves the list of IPs currently blocked in the firewall block zone.

    Returns:
        set: A set of currently blocked IP addresses.
    """
    result = run_command(["firewall-cmd", "--zone", BLOCK_ZONE, "--list-sources"])
    return set(result.split()) if result else set()


def add_ips_to_zone(ips):
    """
    Permanently blocks a list of IPs by adding them to the block zone.

    Args:
        ips (set): A set of IP addresses to be added to the block zone.
    """
    for ip in ips:
        if run_command(["firewall-cmd", "--permanent", "--zone", BLOCK_ZONE, "--add-source", ip]):
            print(f"Added IP {ip} to the block zone '{BLOCK_ZONE}'.")
    print(f"{len(ips)} IPs have been blocked. Reloading firewall...")
    run_command(["firewall-cmd", "--reload"])
    print("Firewall reloaded successfully.")


def analyze_login_attempts(log_file_path):
    """
    Analyzes login attempts from the provided log file and blocks IPs with more
    than a defined threshold of login attempts.

    Args:
        log_file_path (str): Path to the log file containing login attempt entries.
    """
    if not ensure_block_zone():
        print("Failed to create/ensure the block zone exists. Exiting...")
        return

    blocked_ips = get_blocked_ips()  # Retrieve already blocked IPs
    start_time = time()  # Start the timer to measure performance

    try:
        ip_pattern = re.compile(r'(\d{1,3}(?:\.\d{1,3}){3})')  # Pattern to extract IP addresses
        ip_counts = Counter()  # Counts login attempts per IP

        # Process the log file line by line
        with open(log_file_path, 'r') as log_file:
            for line in log_file:
                if 'Invalid user' in line or 'Failed password' in line:  # Relevant log entries
                    match = ip_pattern.search(line)
                    if match:
                        ip = match.group(1)
                        if ip not in IGNORED_IPS:  # Ignore addresses in the ignore list
                            ip_counts[ip] += 1

        # Identify new IPs to block (exceeding the threshold and not already blocked)
        new_ips_to_block = {ip for ip, count in ip_counts.items()
                            if count > ATTEMPT_THRESHOLD and ip not in blocked_ips}
        if new_ips_to_block:
            print(f"Blocking the following IPs (more than {ATTEMPT_THRESHOLD} attempts): {new_ips_to_block}")
            add_ips_to_zone(new_ips_to_block)
        else:
            print(f"No IPs found with more than {ATTEMPT_THRESHOLD} login attempts to block.")

        # Summary
        print(f"\n{'IP Address':<20}{'Attempts':<10}{'Status':<15}")
        print("=" * 45)
        for ip, count in ip_counts.most_common():
            status = "BLOCKED" if ip in blocked_ips or ip in new_ips_to_block else "IGNORED"
            print(f"{ip:<20}{count:<10}{status:<15}")

    except FileNotFoundError:
        print(f"The log file '{log_file_path}' was not found. Please check the path.")
    except PermissionError:
        print(f"Insufficient permissions to read the log file '{log_file_path}'.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

    # Measure and print performance metrics
    end_time = time()  # End the timer
    print(f"\nAnalysis completed in {end_time - start_time:.2f} seconds.")


if __name__ == "__main__":
    # Specify the path to the log file to be analyzed
    log_file = "/var/log/secure"  # Update this if using a different log file
    analyze_login_attempts(log_file)
