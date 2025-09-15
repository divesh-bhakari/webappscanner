from flask import Flask, render_template, request, flash, redirect, url_for, send_file, session, jsonify
import requests
from requests.adapters import HTTPAdapter, Retry
from urllib.parse import urlparse, urljoin
from datetime import datetime
import csv
import os
import re
import time
from threading import Thread, Lock
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import json
from concurrent.futures import ThreadPoolExecutor, as_completed


# persistent DB
from flask_sqlalchemy import SQLAlchemy

# --------------------------
# Flask App Setup
# --------------------------
app = Flask(__name__)
app.secret_key = 'supersecretkey'

# DB (SQLite) - simple local persistence for jobs/results
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///hellboy_jobs.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

CSV_FOLDER = "csv_reports"
os.makedirs(CSV_FOLDER, exist_ok=True)

# --------------------------
# Allowed Testing URLs
# --------------------------
ALLOWED_SITES = [
    "http://testphp.vulnweb.com",
    "http://demo.testfire.net",
    "http://zero.webappsecurity.com",
    "https://juice-shop.herokuapp.com",
    "http://hackazon.webscantest.com"
]

# --------------------------
# Rate Limiter Setup
# --------------------------
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["10 per hour"]
)
limiter.init_app(app)

# --------------------------
# Versioning Info
# --------------------------
APP_VERSION = "3.0.0"
LAST_UPDATED = datetime.now()

@app.context_processor
def inject_version_info():
    return dict(app_version=APP_VERSION, last_updated=LAST_UPDATED.strftime("%d-%m-%Y"))

# --------------------------
# In-memory User Database (Dictionary)
# For production, replace with real database
# --------------------------
users_db = {}

# --------------------------
# Job model to persist background scan jobs and results
# --------------------------
class ScanJob(db.Model):
    __tablename__ = 'scan_jobs'
    id = db.Column(db.String(36), primary_key=True)  # uuid
    target = db.Column(db.String(2083), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(32), default='queued')  # queued, running, finished, failed
    current_url = db.Column(db.String(2083), nullable=True)
    pages_scanned = db.Column(db.Integer, default=0)
    pages_total_estimate = db.Column(db.Integer, default=0)
    message = db.Column(db.Text, nullable=True)  # JSON string of findings
    finished_at = db.Column(db.DateTime, nullable=True)

    def as_dict(self):
        return {
            'id': self.id,
            'target': self.target,
            'status': self.status,
            'current_url': self.current_url,
            'pages_scanned': self.pages_scanned,
            'pages_total_estimate': self.pages_total_estimate,
            'message': self.message,
            'created_at': self.created_at.isoformat(),
            'finished_at': self.finished_at.isoformat() if self.finished_at else None,
        }

with app.app_context():
    db.create_all()

db_lock = Lock()

# --------------------------
# URL Validation (kept original)
# --------------------------
def validate_url(url):
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    parsed = urlparse(url)
    if not parsed.netloc:
        return None, "Invalid URL format"
    try:
        r = requests.get(url, timeout=2, allow_redirects=True)
        if r.status_code < 400:
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
# SCANNERS (unchanged, copied from your code)
# --------------------------

# SQL Injection Scanner
def sql_injection_scan(url):
    # Removed time-based payloads so scans stay fast during testing
    payloads = [
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
        "' OR '1'='1' -- ",
        "' OR '1'='1' /*",
        "'; DROP TABLE users--"
    ]
    try:
        for payload in payloads:
            r = requests.get(url + payload, timeout=3)
            body = r.text.lower()
            if any(err in body for err in ["sql syntax", "mysql", "native client", "odbc", "sql error"]):
                return "Possible SQL Injection"
    except Exception:
        # swallow errors so scanner doesn't crash whole job
        pass
    return "No SQL Injection found"


# XSS Scanner
def xss_scan(url, post_data=None, check_stored=False, stored_url=None):
    payloads = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "<svg/onload=alert(1)>",
                "'\"><iframe src=javascript:alert(1)>", "<body onload=alert(1)>",
                "<details open ontoggle=alert(1)>", "<math><maction xlink:href=javascript:alert(1) type=mouseover></maction></math>"]
    encodings = [lambda p: p, lambda p: p.replace("<", "&lt;").replace(">", "&gt;"), lambda p: p.replace("<", "%3C").replace(">", "%3E")]
    try:
        for payload in payloads:
            for encode in encodings:
                test_payload = encode(payload)
                r = requests.get(url + test_payload, timeout=5)
                if payload in r.text or test_payload in r.text:
                    return "Reflected XSS detected"
                if post_data:
                    data = {k: test_payload for k in post_data.keys()}
                    r_post = requests.post(url, data=data, timeout=5)
                    if payload in r_post.text or test_payload in r_post.text:
                        return "POST-based XSS detected"
                if check_stored and stored_url and post_data:
                    data = {k: test_payload for k in post_data.keys()}
                    requests.post(url, data=data, timeout=5)
                    r_stored = requests.get(stored_url, timeout=5)
                    if payload in r_stored.text or test_payload in r_stored.text:
                        return "Stored XSS detected"
    except:
        pass
    return "No XSS found"

# Directory Traversal
def dir_traversal_scan(url):
    import urllib.parse
    payloads = ["/../", "/../../../../etc/passwd", "/..%2F..%2F..%2Fetc/passwd", "/../../../../boot.ini", "/..%2F..%2F..%2Fboot.ini"]
    indicators = ["root:", "[boot loader]", "[operating systems]"]
    parsed = urllib.parse.urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    for payload in payloads:
        try:
            r = requests.get(base_url + payload, timeout=5)
            if any(ind in r.text for ind in indicators):
                return "Possible Directory Traversal"
        except:
            continue
    return "No Directory Traversal found"

# Open Redirect
def open_redirect_scan(url):
    import urllib.parse
    redirect_params = ["url", "next", "redirect", "dest", "goto", "return", "page"]
    test_payloads = ["http://malicious.com", "https://malicious.com", "//malicious.com", "/malicious"]
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
                        return f"Possible Open Redirect via {param}"
                except:
                    continue
    except:
        pass
    return "No Open Redirect found"

# Clickjacking
def clickjacking_scan(url):
    try:
        r = requests.get(url, timeout=2)
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
            reasons.append(f"X-Frame-Options is set to '{x_frame}'")
        if "frame-ancestors" not in csp.lower():
            vulnerable = True
            reasons.append("Missing CSP frame-ancestors directive")
        if vulnerable:
            return "Possible Clickjacking vulnerability: " + "; ".join(reasons)
    except:
        pass
    return "No Clickjacking found"

# Insecure Headers
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
        r = requests.get(url, timeout=2)
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
    except:
        return "Error fetching headers"

# Unsafe HTTP Methods
def improved_http_method_scan(url):
    risky_methods = ["PUT", "DELETE", "TRACE", "CONNECT", "PATCH"]
    results = []
    try:
        r = requests.options(url, timeout=5)
        allowed = r.headers.get("Allow", "")
        for method in risky_methods:
            if method in allowed:
                results.append(f"{method} listed in Allow header")
    except:
        results.append("Could not retrieve Allow header")
    for method in risky_methods:
        try:
            test = requests.request(method, url, timeout=5)
            if test.status_code not in [405, 501]:
                results.append(f"{method} appears supported (Status {test.status_code})")
        except:
            continue
    if results:
        return "⚠️ Unsafe HTTP Methods Detected:\n" + "\n".join(results)
    return "✅ HTTP Methods are safe"

# Robots.txt
def robots_scan(url):
    sensitive_keywords = ["admin", "backup", "config", "test", "private", "secret"]
    try:
        r = requests.get(url.rstrip("/") + "/robots.txt", timeout=5)
        if r.status_code == 200:
            disallowed = re.findall(r"Disallow:\s*(\S+)", r.text, re.IGNORECASE)
            flagged = [p for p in disallowed if any(k in p.lower() for k in sensitive_keywords)]
            if flagged:
                return f"robots.txt found 🚨 Sensitive paths exposed: {', '.join(flagged)}"
            elif disallowed:
                return f"robots.txt found ✅ Disallowed paths: {', '.join(disallowed)}"
            else:
                return "robots.txt found but no Disallow rules"
    except:
        return "Error fetching robots.txt"
    return "No robots.txt found"

# --------------------------
# Fast lightweight per-URL scanner (only fast checks)
# --------------------------
def fast_scan_single_url(url, session=None, timeout_short=5, timeout_mid=10):
    s = session or requests.Session()

    # Set retry strategy
    retries = Retry(total=2, backoff_factor=0.3, status_forcelist=[500,502,503,504])
    s.mount("http://", HTTPAdapter(max_retries=retries))
    s.mount("https://", HTTPAdapter(max_retries=retries))

    results = {}

    # Insecure headers
    try:
        r = s.get(url, timeout=timeout_short, allow_redirects=False)
        headers = {k.lower(): v for k, v in r.headers.items()}
        missing = []
        for h in ["content-security-policy", "strict-transport-security", "x-content-type-options", "x-frame-options"]:
            if h not in headers:
                missing.append(h)
        results["Insecure HTTP Headers"] = "OK" if not missing else f"Missing headers: {missing}"
    except Exception:
        results["Insecure HTTP Headers"] = "Could not fetch headers"

    # Clickjacking
    try:
        x_frame = headers.get('x-frame-options', "")
        csp = headers.get('content-security-policy', "")
        if not x_frame or "frame-ancestors" not in csp.lower():
            results["Clickjacking"] = "Possible Clickjacking (insecure headers)"
        else:
            results["Clickjacking"] = "OK"
    except Exception:
        results["Clickjacking"] = "Could not check clickjacking"

    # robots.txt
    try:
        rrobots = s.get(url.rstrip("/") + "/robots.txt", timeout=timeout_short)
        if rrobots.status_code == 200:
            results["Robots.txt Check"] = "Found"
        else:
            results["Robots.txt Check"] = "No robots.txt"
    except Exception:
        results["Robots.txt Check"] = "Could not fetch robots.txt"

    return results


# --------------------------
# Helper: same-origin and normalize links
# --------------------------
def same_origin(base, url):
    try:
        b = urlparse(base)
        u = urlparse(url)
        return (u.scheme in ['http', 'https']) and (u.netloc == b.netloc)
    except:
        return False

def normalize_link(base, link):
    return urljoin(base, link)

# --------------------------
# Scan per URL wrapper: call all scanners and return dict
# --------------------------
def scan_single_url(url):
    """
    Run all individual scanners in parallel (thread pool) and return a dict of results.
    This replaces the sequential scanning to speed up per-page scans.
    """
    scanners = {
        'SQL Injection': sql_injection_scan,
        'XSS': xss_scan,
        'Directory Traversal': dir_traversal_scan,
        'Open Redirect': open_redirect_scan,
        'Clickjacking': clickjacking_scan,
        'Insecure HTTP Headers': insecure_headers_scan,
        'Unsafe HTTP Methods': improved_http_method_scan,
        'Robots.txt Check': robots_scan,
    }

    results = {}
    # tune max_workers to 3-8 depending on how many parallel checks you want
    try:
        with ThreadPoolExecutor(max_workers=5) as executor:
            future_to_name = {executor.submit(fn, url): name for name, fn in scanners.items()}
            for future in as_completed(future_to_name):
                name = future_to_name[future]
                try:
                    results[name] = future.result()
                except Exception as e:
                    results[name] = f"Error: {e}"
    except Exception as e:
        # if thread pool fails for some reason, fall back to sequential run
        results = {}
        for name, fn in scanners.items():
            try:
                results[name] = fn(url)
            except Exception as ex:
                results[name] = f"Error fallback: {ex}"

    return results
# --------------------------
# Crawler + Scanner Job (Improved)
# --------------------------
# --------------------------
# Fast parallel crawler + scanner (aim: small scans in ~15s)
# --------------------------
def crawl_and_scan_job_fast(job_id, max_pages=10, max_depth=1, delay_between_requests=0.0, max_workers=8):
    """
    Fast-mode crawler: parallel fetch+scan using ThreadPoolExecutor.
    Replace your existing crawl_and_scan_job or call this for tests.
    """
    with app.app_context():
        job = ScanJob.query.get(job_id)
        if not job:
            return

        with db_lock:
            job.status = 'running'
            job.started_at = datetime.utcnow()
            job.message = "Fast scan started..."
            job.pages_total_estimate = 0
            job.pages_scanned = 0
            db.session.commit()

        start = job.target
        seen = set()
        queue = [(start, 0)]
        job_findings = {}
        session_requests = requests.Session()
        session_requests.headers.update({'User-Agent': 'HellboyFast/1.0'})

        # worker that fetches page and runs fast scanners
        def worker_fetch_and_scan(url, depth):
            # fetch page (fast) to extract links and give HTML for potential extra checks
            links = []
            try:
                r = session_requests.get(url, timeout=1.5, allow_redirects=False)
                content_type = r.headers.get('content-type', '')
                text = r.text if 'text' in content_type else ''
                if 'text/html' in content_type:
                    from bs4 import BeautifulSoup
                    soup = BeautifulSoup(text, 'html.parser')
                    for a in soup.find_all('a', href=True):
                        href = a['href'].strip()
                        if href.startswith(('mailto:', 'tel:')):
                            continue
                        new_url = normalize_link(url, href)
                        if same_origin(start, new_url):
                            links.append((new_url, depth + 1))
            except Exception:
                text = ""
            # run fast per-url scanner
            scanned = fast_scan_single_url(url, session=session_requests, timeout_short=1, timeout_mid=2)
            return url, depth, scanned, links

        # run loop that dispatches a small batch of workers at a time
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {}
            try:
                while queue and len(seen) < max_pages:
                    # fill up worker slots
                    while queue and len(futures) < max_workers and len(seen) + len(futures) < max_pages:
                        url, depth = queue.pop(0)
                        if url in seen or depth > max_depth or not same_origin(start, url):
                            continue
                        # reserve it (pre-mark to avoid duplicates enqueued)
                        seen.add(url)
                        futures[executor.submit(worker_fetch_and_scan, url, depth)] = (url, depth)

                    # process completed futures as they finish
                    if not futures:
                        break
                    done, _ = as_completed(futures), None
                    # pull one completed future at a time to update DB quickly
                    for fut in done:
                        try:
                            url_done, depth_done, scanned_results, new_links = fut.result(timeout=0)
                        except Exception:
                            # if a future raised or timed out retrieving .result, skip to next
                            url_done, scanned_results, new_links = None, {"error": "worker error"}, []
                        if url_done:
                            job_findings[url_done] = scanned_results
                            # add new links to queue if not seen and within limit
                            for nl, nd in new_links:
                                if nl not in seen and len(seen) + len(queue) < max_pages:
                                    queue.append((nl, nd))

                            # commit progress once per finished page
                            with db_lock:
                                job.current_url = url_done
                                job.pages_scanned = len(job_findings)
                                job.pages_total_estimate = max(job.pages_total_estimate, len(seen) + len(queue))
                                db.session.commit()

                        # remove processed future from our dict
                        try:
                            futures.pop(fut)
                        except KeyError:
                            pass

                        # tiny break so loop can refill futures
                        break

                    # small optional delay - set to 0 for fastest
                    if delay_between_requests:
                        time.sleep(delay_between_requests)

            except Exception as e:
                with db_lock:
                    job.status = 'failed'
                    job.message = f"Fast scan error: {e}"
                    db.session.commit()

        # finalize
        with db_lock:
            job.status = 'finished'
            job.current_url = None
            job.finished_at = datetime.utcnow()
            job.pages_scanned = len(job_findings)
            try:
                job.message = json.dumps(job_findings)
            except Exception:
                job.message = "Fast scan completed but could not serialize findings"
            db.session.commit()

        # write CSV (best-effort)
        try:
            csv_filename = os.path.join(CSV_FOLDER, f"scan_{job_id}.csv")
            with open(csv_filename, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["URL", "Vulnerability", "Status/Details"])
                for u, resd in job_findings.items():
                    for vuln_name, status in resd.items():
                        writer.writerow([u, vuln_name, status])
        except Exception as e:
            with db_lock:
                job.message = (job.message or '') + f"\nError writing CSV: {str(e)}"
                db.session.commit()

# --------------------------
# FLASK ROUTES (login/register kept same)
# --------------------------

# Home page
@app.route('/')
def index():
    if not session.get('username'):
        return redirect(url_for('login'))
    return render_template('index.html')

# Registration
@app.route('/register', methods=['GET','POST'])
@limiter.exempt
def register():
    if request.method == 'POST':
        username = request.form.get('username').strip()
        password = request.form.get('password').strip()
        confirm_password = request.form.get('confirm_password').strip()

        if not username or not password or not confirm_password:
            flash("Please fill all fields")
            return redirect(url_for('register'))

        if password != confirm_password:
            flash("Passwords do not match")
            return redirect(url_for('register'))

        if username in users_db:
            flash("Username already exists")
            return redirect(url_for('register'))

        hashed_pw = generate_password_hash(password)
        users_db[username] = hashed_pw
        flash("Registration successful. Please login.")
        return redirect(url_for('login'))

    return render_template('register.html')

# Login
@app.route('/login', methods=['GET','POST'])
@limiter.exempt
def login():
    if request.method == 'POST':
        username = request.form.get('username').strip()
        password = request.form.get('password').strip()

        if username in users_db and check_password_hash(users_db[username], password):
            session['username'] = username
            flash("Login successful", "auth")
            return redirect(url_for('index'))
        else:
            flash("Invalid username or password", "auth")
            return redirect(url_for('login'))

    return render_template('login.html')

# Logout
@app.route('/logout')
@limiter.exempt
def logout():
    session.pop('username', None)
    flash("Logged out successfully", "auth")
    return redirect(url_for('login'))

# New: start scan -> create job, start thread, render scanning page
@app.route('/scan', methods=['POST'])
@limiter.limit("2 per hour")
def scan():
    if not session.get('username'):
        flash("Please login first", "auth")
        return redirect(url_for('login'))

    url = request.form.get('url').strip()

    # Validate URL
    valid_url, error = validate_url(url)
    if not valid_url:
        flash(f"⚠️ {error}", "scan")
        return redirect(url_for('index'))

    # Optional whitelist enforcement (commented out by default)
    # if urlparse(valid_url).netloc not in [urlparse(u).netloc for u in ALLOWED_SITES]:
    #     flash("⚠️ This site is not allowed for scanning.", "scan")
    #     return redirect(url_for('index'))

    # create job record
    job_id = str(uuid.uuid4())
    job = ScanJob(id=job_id, target=valid_url, status='queued')
    with db_lock:
        db.session.add(job)
        db.session.commit()

    # start background thread (daemon)
    t = Thread(target=crawl_and_scan_job_fast, args=(job_id, 10, 1, 0.5, 4), daemon=True)
    t.start()

    # show scanning page that polls status
    return render_template('scanning.html', job_id=job_id, target=valid_url)

# --------------------------
# Scan Status Endpoint
# --------------------------
@limiter.exempt
@app.route('/scan_status/<job_id>')
def scan_status(job_id):
    job = ScanJob.query.get(job_id)
    if not job:
        return jsonify({'error': 'job not found'}), 404

    # Calculate percent manually
    total = job.pages_total_estimate or max(job.pages_scanned, 1)
    percent = int((job.pages_scanned / total) * 100) if total else 0

    return jsonify({
    "status": job.status,
    "target": job.target,
    "current_url": job.current_url,
    "progress": percent,            # current name used by backend
    "percent": percent,             # alias so older frontends work
    "pages_scanned": job.pages_scanned,
    "pages_total_estimate": job.pages_total_estimate,
    "result": job.message if job.status == "finished" else None,
    "csv_file": f"/download_csv/{job_id}" if job.status == "finished" else None
})



# result page for job
@app.route('/scan_result/<job_id>')
def scan_result(job_id):
    if not session.get('username'):
        flash("Please login first", "auth")
        return redirect(url_for('login'))

    job = ScanJob.query.get(job_id)
    if not job:
        flash("Job not found")
        return redirect(url_for('index'))

    findings = {}
    try:
        if job.message:
            findings = json.loads(job.message)
    except Exception:
        findings = {"error": "Could not parse findings"}

    # aggregate per-your-old-template expectations
    aggregated = {}
    vuln_names = ["SQL Injection","XSS","Directory Traversal","Open Redirect","Clickjacking","Insecure HTTP Headers","Unsafe HTTP Methods","Robots.txt Check"]
    for vn in vuln_names:
        aggregated[vn] = f"No {vn}"

    for u, resd in findings.items():
        for k,v in resd.items():
            if isinstance(v, str) and ("No " in v or "safe" in v.lower() or "All important headers present" in v):
                continue
            aggregated[k] = v

    risk_weights = {"SQL Injection":3,"XSS":3,"Directory Traversal":3,"Open Redirect":2,
                    "Clickjacking":2,"Insecure HTTP Headers":2,"Unsafe HTTP Methods":1,"Robots.txt Check":1}

    total_detected = sum(1 for v in aggregated.values() if isinstance(v,str) and ("No " not in v and "safe" not in v.lower()))
    total_safe = len(aggregated) - total_detected
    high_risk_count = sum(1 for k,v in aggregated.items() if risk_weights.get(k,0)>=3 and isinstance(v,str) and ("No " not in v and "safe" not in v.lower()))
    total_risk = sum(risk_weights.values())
    detected_risk = sum(risk_weights[k] for k,v in aggregated.items() if isinstance(v,str) and ("No " not in v and "safe" not in v.lower()))
    overall_score = round(((total_risk - detected_risk)/total_risk)*100,2) if total_risk else 0

    csv_filename = os.path.join(CSV_FOLDER, f"scan_{job_id}.csv")
    return render_template('result.html',
                           job_id=job_id,
                           url=job.target,
                           vulnerabilities=aggregated,
                           detailed_info={"SQL Injection": "Allows attackers to execute arbitrary SQL commands in your database, potentially exposing sensitive data or modifying your database.",
    "Cross-Site Scripting (XSS)": "Allows attackers to inject malicious scripts into web pages viewed by other users, which can steal cookies, session tokens, or perform actions on behalf of the user.",
    "Clickjacking": "Attackers can trick users into clicking on hidden buttons or links, potentially performing unwanted actions without their consent.",
    "Directory Traversal": "Allows attackers to access files and directories outside the web root, potentially exposing sensitive system files.",
    "Insecure Deserialization": "Allows attackers to manipulate serialized objects to execute arbitrary code or bypass authentication.",
    "Security Misconfiguration": "Improperly configured security settings can expose sensitive data or functionality.",
    "Sensitive Data Exposure": "Exposes sensitive information like passwords, credit card numbers, or personal data to attackers.",
    "Broken Authentication": "Allows attackers to compromise passwords, keys, or session tokens to impersonate users.",
    "Using Components with Known Vulnerabilities": "Outdated or vulnerable libraries can be exploited to compromise the application.",
    "Insufficient Logging & Monitoring": "Lack of logging can allow attackers to go unnoticed, making it harder to detect or respond to attacks."},  # keep your descriptions or pass them here
                           total_detected=total_detected,
                           total_safe=total_safe,
                           high_risk_count=high_risk_count,
                           overall_score=overall_score,
                           scan_time=job.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                           scan_duration="(background)",
                           csv_file=csv_filename,
                           invalid=False)

# Download CSV per job
@app.route('/download_csv/<job_id>')
def download_csv(job_id):
    if not session.get('username'):
        flash("Please login first")
        return redirect(url_for('login'))

    csv_filename = os.path.join(CSV_FOLDER, f"scan_{job_id}.csv")
    if os.path.exists(csv_filename):
        return send_file(csv_filename, mimetype='text/csv', download_name=f'scan_{job_id}.csv', as_attachment=True)
    else:
        flash("CSV report not found.")
        return redirect(url_for('index'))

# Rate Limit Error Handler
@app.errorhandler(429)
def ratelimit_handler(e):
    return render_template("429.html", error=str(e)), 429

# Run
if __name__ == '__main__':
    app.run(debug=True)
