from flask import Flask, render_template, request, flash, redirect, url_for
import requests
from urllib.parse import urlparse
from datetime import datetime
import csv
import os
import re
import time

app = Flask(__name__)
app.secret_key = 'supersecretkey'

CSV_FOLDER = "csv_reports"
os.makedirs(CSV_FOLDER, exist_ok=True)

# --------------------------
# Allowed testing URLs
# --------------------------
ALLOWED_SITES = [
    "http://testphp.vulnweb.com",
    "http://demo.testfire.net",
    "http://zero.webappsecurity.com",
    "https://juice-shop.herokuapp.com",
    "http://hackazon.webscantest.com"
]

# --------------------------
# URL Validation
# --------------------------
def validate_url(url):
    # Step 1: Normalize scheme
    if not url.startswith(("http://", "https://")):
        url = "http://" + url   # default to http if missing

    # Step 2: Parse and check domain
    parsed = urlparse(url)
    if not parsed.netloc:   # No domain found
        return None, "Invalid URL format"

    # Step 3: Try connecting
    try:
        r = requests.get(url, timeout=5, allow_redirects=True)
        if r.status_code < 400:   # Accepts 2xx and 3xx responses
            return url, None
        else:
            return None, f"Website returned status code {r.status_code}"
    except requests.exceptions.ConnectionError:
        return None, "Website not reachable"
    except requests.exceptions.Timeout:
        return None, "Connection timed out"
    except Exception as e:
        return None, f"Error: {str(e)}"

# --------------------------
# SQL Injection Scanner
# --------------------------
def sql_injection_scan(url):
    payloads = [
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
        "' OR '1'='1' -- ",
        "' OR '1'='1' /*",
        "'; DROP TABLE users--",
        "' OR SLEEP(5)--"
    ]
    try:
        for payload in payloads:
            r = requests.get(url + payload, timeout=5)
            if any(err in r.text.lower() for err in [
                "sql syntax", "mysql", "native client", "odbc", "sql error"
            ]):
                return "Possible SQL Injection"
            if "SLEEP" in payload:
                start = time.time()
                requests.get(url + payload, timeout=10)
                end = time.time()
                if end - start >= 5:
                    return "Possible Time-Based SQL Injection"
    except:
        pass
    return "No SQL Injection found"

# --------------------------
# XSS Scanner
# --------------------------
def xss_scan(url, post_data=None, check_stored=False, stored_url=None):
    payloads = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>",
        "'\"><iframe src=javascript:alert(1)>",
        "<body onload=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<math><maction xlink:href=javascript:alert(1) type=mouseover></maction></math>"
    ]

    encodings = [
        lambda p: p,
        lambda p: p.replace("<", "&lt;").replace(">", "&gt;"),
        lambda p: p.replace("<", "%3C").replace(">", "%3E")
    ]

    try:
        for payload in payloads:
            for encode in encodings:
                test_payload = encode(payload)

                # Reflected GET
                r = requests.get(url + test_payload, timeout=5)
                if payload in r.text or test_payload in r.text:
                    return "Reflected XSS detected"

                # POST-based XSS
                if post_data:
                    data = {k: test_payload for k in post_data.keys()}
                    r_post = requests.post(url, data=data, timeout=5)
                    if payload in r_post.text or test_payload in r_post.text:
                        return "POST-based XSS detected"

                # Stored XSS
                if check_stored and stored_url:
                    if post_data:
                        data = {k: test_payload for k in post_data.keys()}
                        requests.post(url, data=data, timeout=5)
                    r_stored = requests.get(stored_url, timeout=5)
                    if payload in r_stored.text or test_payload in r_stored.text:
                        return "Stored XSS detected"

    except:
        pass

    return "No XSS found"

# --------------------------
# Directory Traversal
# --------------------------
def dir_traversal_scan(url):
    import urllib.parse
    import time

    payloads = [
        "/../", "/../../../../etc/passwd", "/..%2F..%2F..%2Fetc/passwd",
        "/../../../../boot.ini", "/..%2F..%2F..%2Fboot.ini",
        "/etc/passwd", "/boot.ini",
        "/../"*5, "/..%2F"*5
    ]
    indicators = ["root:", "[boot loader]", "[operating systems]"]
    max_retries = 2

    parsed = urllib.parse.urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    query_params = urllib.parse.parse_qs(parsed.query)

    for payload in payloads:
        try:
            for attempt in range(max_retries):
                r = requests.get(base_url + payload, timeout=5)
                if r.status_code in [200, 403, 401]:
                    if any(ind in r.text for ind in indicators):
                        return "Possible Directory Traversal (Path Scan)"
                time.sleep(0.5)

            if query_params:
                for param in query_params:
                    for attempt in range(max_retries):
                        modified_params = query_params.copy()
                        modified_params[param] = payload
                        full_url = f"{base_url}?{urllib.parse.urlencode(modified_params, doseq=True)}"
                        r = requests.get(full_url, timeout=5)
                        if r.status_code in [200, 403, 401]:
                            if any(ind in r.text for ind in indicators):
                                return f"Possible Directory Traversal (Parameter: {param})"
                        time.sleep(0.5)

        except requests.exceptions.Timeout:
            continue
        except Exception as e:
            print(f"[Directory Traversal Scanner] Error: {e}")
            continue

    return "No Directory Traversal found"

# --------------------------
# Open Redirect
# --------------------------
def open_redirect_scan(url):
    import urllib.parse
    redirect_params = ["url", "next", "redirect", "dest", "goto", "return", "page"]
    test_payloads = [
        "http://malicious.com",
        "https://malicious.com",
        "//malicious.com",
        "/malicious"
    ]

    try:
        parsed = urllib.parse.urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        for param in redirect_params:
            for payload in test_payloads:
                query_dict = {param: payload}
                full_url = f"{base_url}?{urllib.parse.urlencode(query_dict)}"

                try:
                    r = requests.get(full_url, allow_redirects=False, timeout=5)
                    location = r.headers.get("Location", "")
                    if any(test_payload in location for test_payload in test_payloads):
                        return f"Possible Open Redirect via parameter '{param}' -> {location}"

                    r2 = requests.get(full_url, timeout=5)
                    final_url = r2.url
                    if any(test_payload in final_url for test_payload in test_payloads):
                        return f"Possible Open Redirect via parameter '{param}' -> {final_url}"

                except requests.exceptions.RequestException:
                    continue

    except Exception as e:
        print(f"[Open Redirect Scanner] Error: {e}")

    return "No Open Redirect found"

# --------------------------
# Clickjacking 
# --------------------------
def clickjacking_scan(url):
    try:
        r = requests.get(url, timeout=5)
        headers = {k.lower(): v for k, v in r.headers.items()}

        x_frame = headers.get('x-frame-options', None)
        csp = headers.get('content-security-policy', '')

        vulnerable = False
        reasons = []

        if not x_frame:
            vulnerable = True
            reasons.append("Missing X-Frame-Options header")
        elif x_frame.lower() not in ["deny", "sameorigin"]:
            vulnerable = True
            reasons.append(f"X-Frame-Options is set to '{x_frame}', which may allow framing")

        if "frame-ancestors" not in csp.lower():
            vulnerable = True
            reasons.append("Missing CSP frame-ancestors directive")

        if vulnerable:
            return "Possible Clickjacking vulnerability: " + "; ".join(reasons)

    except requests.exceptions.RequestException as e:
        print(f"[Clickjacking Scanner] Error: {e}")
    except Exception as e:
        print(f"[Clickjacking Scanner] Unexpected Error: {e}")

    return "No Clickjacking found"

# --------------------------
# Insecure Headers (Improved)
# --------------------------
important_headers = {
    "Content-Security-Policy": "Helps prevent XSS",
    "Strict-Transport-Security": "Forces HTTPS",
    "X-Content-Type-Options": "Prevents MIME sniffing",
    "X-Frame-Options": "Protects against clickjacking",
    "Referrer-Policy": "Controls referrer leakage",
    "Permissions-Policy": "Restricts browser features",
    "Cache-Control": "Prevents caching sensitive data"
}

def insecure_headers_scan(url):
    result = {"missing": [], "misconfigured": [], "present": []}
    try:
        session = requests.Session()
        r = session.get(url, timeout=5)
        headers = {k.lower(): v for k, v in r.headers.items()}

        for h in important_headers:
            if h.lower() not in headers:
                result["missing"].append(h)
            else:
                value = headers[h.lower()]
                result["present"].append(f"{h}: {value}")

                if h == "X-Frame-Options" and value.lower() not in ["deny", "sameorigin"]:
                    result["misconfigured"].append(f"{h}: {value}")
                if h == "Content-Security-Policy" and "*" in value:
                    result["misconfigured"].append(f"{h}: {value}")

        if result["missing"] or result["misconfigured"]:
            return f"Missing: {result['missing']} | Misconfigured: {result['misconfigured']}"
        else:
            return "All important headers present"

    except requests.exceptions.RequestException as e:
        return f"[Error] {str(e)}"

# --------------------------
# HTTP Methods
# --------------------------
def improved_http_method_scan(url):
    risky_methods = ["PUT", "DELETE", "TRACE", "CONNECT", "PATCH"]
    results = []

    # Step 1: Check Allow header
    try:
        r = requests.options(url, timeout=5)
        allowed = r.headers.get("Allow", "")
        if allowed:
            for method in risky_methods:
                if method in allowed:
                    results.append(f"{method} listed in Allow header")
    except:
        results.append("Could not retrieve Allow header")

    # Step 2: Actively test methods
    for method in risky_methods:
        try:
            test = requests.request(method, url, timeout=5)
            if test.status_code not in [405, 501]:  # 405 = Method Not Allowed
                results.append(f"{method} appears to be supported (Status {test.status_code})")
        except:
            continue

    if results:
        return "⚠️ Unsafe HTTP Methods Detected:\n" + "\n".join(results)
    return "✅ HTTP Methods are safe"


# --------------------------
# Robots.txt
# --------------------------
def robots_scan(url):
    sensitive_keywords = ["admin", "backup", "config", "test", "private", "secret"]

    try:
        r = requests.get(url.rstrip("/") + "/robots.txt", timeout=5)
        if r.status_code == 200:
            disallowed = re.findall(r"Disallow:\s*(\S+)", r.text, re.IGNORECASE)
            
            if disallowed:
                flagged = [path for path in disallowed if any(key in path.lower() for key in sensitive_keywords)]
                
                if flagged:
                    return f"robots.txt found 🚨 Sensitive paths exposed: {', '.join(flagged)}"
                else:
                    return f"robots.txt found ✅ Disallowed paths: {', '.join(disallowed)}"
            else:
                return "robots.txt found but no Disallow rules"
    except requests.exceptions.RequestException:
        return "Error fetching robots.txt"

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

    # ✅ Validate URL first
    if not url.startswith("http"):
        url = "http://" + url  # auto-add scheme if missing

    valid_url, error = validate_url(url)
    if not valid_url:
        flash(f"⚠️ {error}")
        return redirect(url_for('index'))

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
    detailed_info['Insecure HTTP Headers'] = "Missing/misconfigured security headers increase attack surface."

    results['Unsafe HTTP Methods'] = http_method_scan(url)
    detailed_info['Unsafe HTTP Methods'] = "PUT or DELETE methods may allow modification of resources."

    results['Robots.txt Check'] = robots_scan(url)
    detailed_info['Robots.txt Check'] = "Sensitive paths in robots.txt may leak information."

    total_detected = sum(1 for v in results.values() if "No" not in v and "safe" not in v)
    total_safe = len(results) - total_detected
    high_risk_count = sum(1 for k,v in results.items() if risk_weights[k] >= 3 and "No" not in v and "safe" not in v)

    total_risk = sum(risk_weights.values())
    detected_risk = sum(risk_weights[k] for k,v in results.items() if "No" not in v and "safe" not in v)
    overall_score = round(((total_risk - detected_risk) / total_risk) * 100, 2)

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
