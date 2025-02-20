import requests
import re
import os

# Configuration
BLOCKLIST_URL = "https://snort-org-site.s3.amazonaws.com/production/document_files/files/000/037/227/original/ip-filter.blf?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAU7AK5ITMMOXGB2W5%2F20250220%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20250220T195222Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&X-Amz-Signature=08455a306f6864ba144c8f8e018d2fe3bdf9060273e3d5f5315f156074d40b24"
BLOCKLIST_FILE = "../IPs/blocklist.txt"

def fetch_ip_list(url):
    """Fetches IPs from a threat feed and extracts valid IP addresses."""
    response = requests.get(url)
    if response.status_code == 200:
        ip_list = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", response.text)
        return set(ip_list)
    else:
        print(f"Failed to fetch IPs. HTTP Status: {response.status_code}")
        return set()

def update_blocklist(new_ips, blocklist_file):
    """Updates the blocklist file with new IPs, avoiding duplicates."""
    if os.path.exists(blocklist_file):
        with open(blocklist_file, "r") as file:
            existing_ips = set(file.read().splitlines())
    else:
        existing_ips = set()

    updated_ips = existing_ips.union(new_ips)

    with open(blocklist_file, "w") as file:
        file.write("\n".join(sorted(updated_ips)))

    print(f"Blocklist updated: {len(updated_ips)} total IPs.")

if __name__ == "__main__":
    new_ips = fetch_ip_list(BLOCKLIST_URL)
    if new_ips:
        update_blocklist(new_ips, BLOCKLIST_FILE)
    else:
        print("No new IPs retrieved.")
