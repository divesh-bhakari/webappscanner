from flask import Flask, render_template, request
import requests
from datetime import datetime
import csv
import os
import re

app = Flask(__name__)
app.secret_key = 'supersecretkey'

CSV_FOLDER = "csv_reports"
os.makedirs(CSV_FOLDER, exist_ok=True)

# --------------------------
# URL Validation
# --------------------------
def is_valid_url(url):
    pattern = re.compile(
        r'^(https?:\/\/)?'       # http:// or https:// (optional)
        r'([a-zA-Z0-9-]+\.)+'    # domain/subdomain
        r'(com|in|org|net|edu|gov|io|info)$'  # valid TLDs
    )
    return re.match(pattern, url.strip()) is not None

# --------------------------
# Vulnerability Scanners with multiple payloads
# --------------------------
def sql_injection_scan(url):
    payloads = ["' OR '1'='1", "'; DROP TABLE users--", "\" OR \"1\"=\"1"]
    try:
        for payload in payloads:
            r = requests.get(url + payload, timeout=5)
            if any(err in r.text.lower() for err in [
                "sql syntax", "mysql", "native client", "odbc", "sql error"
            ]):
                return "Possible SQL Injection"
    except:
        pass
    return "No SQL Injection found"

def xss_scan(url):
    payloads = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "<svg/onload=alert(1)>"]
    try:
        for payload in payloads:
            r = requests.get(url + payload, timeout=5)
            if payload in r.text:
                return "Possible XSS vulnerability"
    except:
        pass
    return "No XSS found"

def dir_traversal_scan(url):
    payloads = ["/../", "/../../../../etc/passwd", "/..%2F..%2F..%2Fetc/passwd"]
    try:
        for payload in payloads:
            r = requests.get(url + payload, timeout=5)
            if "root:" in r.text or r.status_code == 200:
                return "Possible Directory Traversal"
    except:
        pass
    return "No Directory Traversal found"

def open_redirect_scan(url):
    try:
        r = requests.get(url + "?next=http://malicious.com", allow_redirects=False, timeout=5)
        if r.status_code in [301, 302] and "malicious.com" in r.headers.get("Location", ""):
            return "Possible Open Redirect"
    except:
        pass
    return "No Open Redirect found"

def clickjacking_scan(url):
    try:
        r = requests.get(url, timeout=5)
        if 'X-Frame-Options' not in r.headers:
            return "Possible Clickjacking vulnerability"
    except:
        pass
    return "No Clickjacking found"

def insecure_headers_scan(url):
    missing_headers = []
    try:
        r = requests.get(url, timeout=5)
        headers = r.headers
        for h in ['Content-Security-Policy','Strict-Transport-Security','X-Content-Type-Options']:
            if h not in headers:
                missing_headers.append(h)
        if missing_headers:
            return f"Missing security headers: {', '.join(missing_headers)}"
    except:
        pass
    return "All important headers present"

def http_method_scan(url):
    try:
        r = requests.options(url, timeout=5)
        allowed = r.headers.get('Allow','')
        if 'PUT' in allowed or 'DELETE' in allowed:
            return f"Unsafe HTTP Methods Allowed: {allowed}"
    except:
        pass
    return "HTTP Methods safe"

def robots_scan(url):
    try:
        r = requests.get(url + "/robots.txt", timeout=5)
        if r.status_code == 200 and "Disallow" in r.text:
            return "robots.txt found (check for sensitive paths)"
    except:
        pass
    return "No robots.txt found"

# --------------------------
# Flask Routes
# --------------------------
@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    url = request.form.get('url').strip()
    if not url.startswith("http"):
        url = "http://" + url

    # Validate URL before scanning
    if not is_valid_url(url.replace("http://","").replace("https://","")):
        return render_template("result.html", 
                               url=url,
                               vulnerabilities={}, 
                               detailed_info={},
                               total_detected=0,
                               total_safe=0,
                               high_risk_count=0,
                               overall_score=0,
                               scan_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                               scan_duration="0 sec",
                               invalid=True)

    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    results = {}
    detailed_info = {}
    risk_weights = {
        "SQL Injection": 3,
        "XSS": 3,
        "Directory Traversal": 3,
        "Open Redirect": 2,
        "Clickjacking": 2,
        "Insecure HTTP Headers": 2,
        "Unsafe HTTP Methods": 1,
        "Robots.txt Check": 1
    }

    # Run scans
    results['SQL Injection'] = sql_injection_scan(url)
    detailed_info['SQL Injection'] = "Injecting malicious SQL queries can bypass authentication or expose data."

    results['XSS'] = xss_scan(url)
    detailed_info['XSS'] = "Cross-Site Scripting can steal cookies, session tokens, or perform unwanted actions."

    results['Directory Traversal'] = dir_traversal_scan(url)
    detailed_info['Directory Traversal'] = "Allows attackers to access files outside webroot."

    results['Open Redirect'] = open_redirect_scan(url)
    detailed_info['Open Redirect'] = "Can redirect users to malicious sites."

    results['Clickjacking'] = clickjacking_scan(url)
    detailed_info['Clickjacking'] = "Embedding site in iframe without protections can trick users into actions."

    results['Insecure HTTP Headers'] = insecure_headers_scan(url)
    detailed_info['Insecure HTTP Headers'] = "Missing security headers increases attack surface."

    results['Unsafe HTTP Methods'] = http_method_scan(url)
    detailed_info['Unsafe HTTP Methods'] = "PUT or DELETE methods may allow modification of resources."

    results['Robots.txt Check'] = robots_scan(url)
    detailed_info['Robots.txt Check'] = "Sensitive paths in robots.txt may leak information."

    # Summary metrics
    total_detected = sum(1 for v in results.values() if "No" not in v and "safe" not in v)
    total_safe = len(results) - total_detected
    high_risk_count = sum(1 for k,v in results.items() if risk_weights[k] >= 3 and "No" not in v and "safe" not in v)

    # Weighted security score
    total_risk = sum(risk_weights.values())
    detected_risk = sum(risk_weights[k] for k,v in results.items() if "No" not in v and "safe" not in v)
    overall_score = round(((total_risk - detected_risk) / total_risk) * 100, 2)

    # Save CSV
    csv_filename = os.path.join(CSV_FOLDER, "scan_results.csv")
    with open(csv_filename, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Vulnerability","Status"])
        for k,v in results.items():
            writer.writerow([k,v])

    return render_template('result.html',
                       url=url,
                       vulnerabilities=results,
                       detailed_info=detailed_info,
                       total_detected=total_detected,
                       total_safe=total_safe,
                       high_risk_count=high_risk_count,
                       overall_score=overall_score,
                       scan_time=scan_time,
                       scan_duration="~5 sec",
                       csv_file=csv_filename,
                       invalid=False)

if __name__ == '__main__':
    app.run(debug=True)
