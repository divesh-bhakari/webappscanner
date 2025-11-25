# Web Application Vulnerability Scanner  
*A Lightweight Flask-Based Scanner for Detecting OWASP Top Vulnerabilities*

---

## 🚀 Overview  
This Web Application Vulnerability Scanner is a modular security testing tool built using **Flask**, designed to detect **7/10 OWASP vulnerabilities** with **93% accuracy**.  
The system includes a multi-page crawler, background task processing, and real-time scan tracking — providing a fast and developer-friendly way to assess the security posture of web applications.

---

## 🔥 Key Features  

### 🛡️ OWASP Vulnerability Detection  
- Detects **SQL Injection, XSS, CSRF indicators, Clickjacking**, and other critical flaws  
- Automated payload injection and response analysis  
- 93% detection accuracy across tested targets  

### 🌐 Multi-Page Web Crawler  
- Crawls **100+ URLs per scan**  
- Follows links, analyzes forms, and enumerates inputs  
- Automatically filters duplicate or irrelevant pages  

### ⚙️ Async Scanning with Progress Tracking  
- Background processing using **Celery + Redis**  
- Real-time progress bar and task state updates  
- Ideal for long-running security scans  

---

## 🛠️ Tech Stack  
**Backend:** Python (Flask, Requests, BeautifulSoup)  
**Async Tasks:** Celery, Redis  
**Database:** SQLAlchemy  
**Frontend:** HTML, CSS, JavaScript  
**Security:** Custom payload engine & signature-based detection  
