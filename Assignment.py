import re
import csv
from collections import defaultdict

# Configuration for suspicious activity
FAILED_LOGIN_THRESHOLD = 10

def parse_log_file(log_file_path):
    with open(log_file_path, 'r') as log_file:
        return log_file.readlines()

def count_requests_per_ip(log_lines):
    ip_count = defaultdict(int)
    for line in log_lines:
        # Assuming the IP address is the first element in each log entry
        match = re.match(r'^(\S+)', line)
        if match:
            ip = match.group(1)
            ip_count[ip] += 1
    return ip_count

def identify_most_accessed_endpoint(log_lines):
    endpoint_count = defaultdict(int)
    for line in log_lines:
        # Assuming the endpoint is in the second part of the log entry (e.g., "/home")
        match = re.search(r'\"(?:GET|POST|PUT|DELETE)\s+([^\s]+)', line)
        if match:
            endpoint = match.group(1)
            endpoint_count[endpoint] += 1
    # Find the most accessed endpoint
    if endpoint_count:
        most_accessed_endpoint = max(endpoint_count, key=endpoint_count.get)
        return most_accessed_endpoint, endpoint_count[most_accessed_endpoint]
    return None, 0

def detect_suspicious_activity(log_lines):
    failed_logins = defaultdict(int)
    for line in log_lines:
        # Look for failed login attempts (e.g., HTTP 401 or "Invalid credentials")
        if "401" in line or "Invalid credentials" in line:
            match = re.match(r'^(\S+)', line)
            if match:
                ip = match.group(1)
                failed_logins[ip] += 1
    # Filter IPs with failed logins exceeding the threshold
    suspicious_ips = {ip: count for ip, count in failed_logins.items() if count > FAILED_LOGIN_THRESHOLD}
    return suspicious_ips

def save_results_to_csv(ip_counts, most_accessed_endpoint, suspicious_ips):
    with open('log_analysis_results.csv', 'w', newline='') as csvfile:
        fieldnames = ['IP Address', 'Request Count']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for ip, count in ip_counts.items():
            writer.writerow({'IP Address': ip, 'Request Count': count})
        
        writer.writerow({'IP Address': 'Most Accessed Endpoint', 'Request Count': most_accessed_endpoint[0]})
        writer.writerow({'IP Address': 'Access Count', 'Request Count': most_accessed_endpoint[1]})

        writer.writerow({'IP Address': 'Suspicious Activity Detected', 'Request Count': ''})
        for ip, count in suspicious_ips.items():
            writer.writerow({'IP Address': ip, 'Request Count': count})

def print_results(ip_counts, most_accessed_endpoint, suspicious_ips):
    print(f"IP Address           Request Count")
    for ip, count in ip_counts.items():
        print(f"{ip:<20} {count}")
    
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")
    
    print("\nSuspicious Activity Detected:")
    print(f"IP Address           Failed Login Attempts")
    for ip, count in suspicious_ips.items():
        print(f"{ip:<20} {count}")

def main(log_file_path):
    log_lines = parse_log_file(log_file_path)
    
    # Count requests per IP
    ip_counts = count_requests_per_ip(log_lines)
    
    # Identify the most accessed endpoint
    most_accessed_endpoint, endpoint_count = identify_most_accessed_endpoint(log_lines)
    
    # Detect suspicious activity (failed logins)
    suspicious_ips = detect_suspicious_activity(log_lines)
    
    # Output results to terminal
    print_results(ip_counts, (most_accessed_endpoint, endpoint_count), suspicious_ips)
    
    # Save results to CSV
    save_results_to_csv(ip_counts, (most_accessed_endpoint, endpoint_count), suspicious_ips)

if __name__ == '__main__':
    log_file_path = 'logfile.txt'  # o Replace with the path to your log file
    main(log_file_path)
