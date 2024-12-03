import re
import csv
import os
from collections import defaultdict

def parse_log_file(log_file_path):
    ip_requests = defaultdict(int)
    endpoint_counts = defaultdict(int)
    failed_logins = defaultdict(int)
    

    if not os.path.exists(log_file_path):
        print(f"error: log file not found at {log_file_path}")
        print("please ensure the log file exists in the correct location.")
        return ip_requests, endpoint_counts, failed_logins
    
    
    if os.path.getsize(log_file_path) == 0:
        print(f"Error: Log file at {log_file_path} is empty.")
        return ip_requests, endpoint_counts, failed_logins
    
    try:
        with open(log_file_path, 'r') as file:
            for line in file:
                
                ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                if ip_match:
                    ip = ip_match.group(1)
                    ip_requests[ip] += 1
                
                
                endpoint_match = re.search(r'"[A-Z]+ (/\w+)', line)
                if endpoint_match:
                    endpoint = endpoint_match.group(1)
                    endpoint_counts[endpoint] += 1
                
                
                if '401' in line or 'Invalid credentials' in line:
                    if ip_match:
                        failed_logins[ip] += 1
    except IOError as e:
        print(f"Error reading log file: {e}")
        return ip_requests, endpoint_counts, failed_logins
    
    return ip_requests, endpoint_counts, failed_logins

def analyze_log_data(log_file_path, failed_login_threshold=10):
    ip_requests, endpoint_counts, failed_logins = parse_log_file(log_file_path)
    
    
    if not ip_requests and not endpoint_counts and not failed_logins:
        print("No log data to analyze. Exiting.")
        return
    
    
    print("Requests per IP Address:")
    if ip_requests:
        sorted_ip_requests = sorted(ip_requests.items(), key=lambda x: x[1], reverse=True)
        for ip, count in sorted_ip_requests:
            print(f"{ip:<20} {count}")
    else:
        print("No IP request data found.")
    print("\n")
    
    
    if endpoint_counts:
        most_accessed_endpoint = max(endpoint_counts, key=endpoint_counts.get)
        print(f"Most Frequently Accessed Endpoint:")
        print(f"{most_accessed_endpoint} (Accessed {endpoint_counts[most_accessed_endpoint]} times)\n")
    else:
        print("No endpoint data found.\n")
    
    suspicious_ips = {ip: count for ip, count in failed_logins.items() if count > failed_login_threshold}
    print("Suspicious Activity Detected:")
    if suspicious_ips:
        for ip, failed_count in suspicious_ips.items():
            print(f"{ip:<20} {failed_count}")
    else:
        print("No suspicious activities detected.")
    
    try:
        with open('log_analysis_results.csv', 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            
            writer.writerow(["Requests per IP"])
            writer.writerow(["IP Address", "Request Count"])
            for ip, count in (sorted_ip_requests if ip_requests else []):
                writer.writerow([ip, count])
            
            writer.writerow([])
            writer.writerow(["Most Accessed Endpoint"])
            writer.writerow(["Endpoint", "Access Count"])
            if endpoint_counts:
                writer.writerow([most_accessed_endpoint, endpoint_counts[most_accessed_endpoint]])
            

            writer.writerow([])
            writer.writerow(["Suspicious Activity"])
            writer.writerow(["IP Address", "Failed Login Count"])
            for ip, failed_count in suspicious_ips.items():
                writer.writerow([ip, failed_count])
        
        print("\nResults saved to log_analysis_results.csv")
    except IOError as e:
        print(f"Error writing to CSV file: {e}")

def main():
    log_file_path = os.path.join(os.path.dirname(__file__), 'sample.log')
    
    print(f"Looking for log file at: {log_file_path}")
    
    analyze_log_data(log_file_path)

if __name__ == "__main__":
    main()