import requests

# List of common vulnerabilities to check
vulnerabilities = [
    "SQL injection",
    "Cross-site scripting (XSS)",
    "Remote code execution",
    "Directory traversal",
    # Add more vulnerabilities to check as needed
]

def scan_website(url):
    try:
        response = requests.get(url)
        if response.status_code == 200:
            print(f"Scanning {url}...")
            page_content = response.text
            vulnerabilities_found = []

            for vulnerability in vulnerabilities:
                if vulnerability.lower() in page_content.lower():
                    vulnerabilities_found.append(vulnerability)

            if vulnerabilities_found:
                print("Vulnerabilities found:")
                for vulnerability in vulnerabilities_found:
                    print(vulnerability)
            else:
                print("No vulnerabilities found.")

            print("Scan complete.")
        else:
            print(f"Failed to retrieve {url}. Status code: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"Error occurred while scanning {url}: {str(e)}")

# Prompt the user to enter the target site
target_site = input("Enter the target site URL: ")

# Perform the scan
scan_website(target_site)
