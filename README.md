# SecuriScan

[![Python](https://img.shields.io/badge/Python-3.11-blue.svg)](https://www.python.org/)  
[![Flask](https://img.shields.io/badge/Flask-2.3-green.svg)](https://flask.palletsprojects.com/)

---

## Project Description

The **Web Application Vulnerability Scanner** is a professional tool built using Python (Flask).  
It allows users to scan websites for common vulnerabilities, view results in a browser-based interface, and generate reports.

> ⚠️ **Legal Warning**: This tool is intended for educational and ethical testing purposes only.  
> Only scan websites you own or have explicit permission to test. Unauthorized scanning is illegal.

---

##  Features

- **SQL Injection (SQLi)** – Detects injectable fields in web forms.  
- **Cross-Site Scripting (XSS)** – Detects reflected and stored XSS vulnerabilities.  
- **Directory Traversal** – Checks if sensitive files can be accessed from the web.  
- **Clickjacking** – Detects if a website is vulnerable to UI redress attacks.  
- **Open Redirect** – Checks for redirect vulnerabilities.  
- **Custom Report Generation** – Saves scan results in a readable format (CSV/HTML).  
- **User-Friendly Interface** – Built with Flask templates for easy interaction.  

---

##  Requirements

- Python 3.10+  
- pip (Python package manager)  
- Git  
- *(Optional)* Virtual Environment (venv)  

### Python Dependencies

Listed in `requirements.txt`:

- Flask  
- Flask-Cors  
- requests  
- beautifulsoup4  
- gunicorn  

---
## Check out the live web app

https://webappscanner-yz1r.onrender.com/

## Cloning the Repository

Open a terminal or command prompt and run:
git clone https://github.com/divesh-bhakari/webappscanner.git
