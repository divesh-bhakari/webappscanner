# HELLBOY – Web Application Vulnerability Scanner

[![Python](https://img.shields.io/badge/Python-3.11-blue.svg)](https://www.python.org/)  
[![Flask](https://img.shields.io/badge/Flask-2.3-green.svg)](https://flask.palletsprojects.com/)

---

## 📖 Project Description

**wen application vulnurablity scanner** is a professional web application vulnerability scanner built using Python (Flask).  
It allows users to scan websites for common vulnerabilities, view results in a web interface, and generate reports.  

> ⚠️ Legal Warning: This tool is intended for educational and ethical testing purposes only.  
> Only scan websites you own or have explicit permission to test. Unauthorized scanning is illegal.

---

## ⚡ Features

- SQL Injection (SQLi) – Detects injectable fields in web forms.  
- Cross-Site Scripting (XSS) – Detects reflected and stored XSS vulnerabilities.  
- Directory Traversal – Checks if sensitive files can be accessed from the web.  
- Clickjacking – Detects if a website is vulnerable to UI redress attacks.  
- Open Redirect – Checks for redirect vulnerabilities.  
- Custom Report Generation – Saves scan results in a readable format.  
- Friendly Web Interface – Uses Flask templates for easy scanning.

---

## ⚙️ Requirements

- Python 3.10+  
- pip (Python package manager)  
- Git  
- Optional: Virtual Environment (venv)  

### Required packages:

- Flask  
- requests  
- BeautifulSoup4  

---

## 💾 Cloning the Repository

Open terminal or command prompt.  

Clone the repo:https://github.com/divesh-bhakari/webappscanner.git

```bash
git clone https://github.com/divesh-bhakari/webappscanner.git

Go into the project folder:

cd webappscanner
🛠 Setup Instructions
1️⃣ Optional: Create a Virtual Environment
python -m venv venv
Activate it:

Windows: venv\Scripts\activate

Linux/Mac: source venv/bin/activate
2️⃣ Install Dependencies
pip install -r requirements.txt
3️⃣ Running the Application
python app.py
Open your browser at http://127.0.0.1:5000/

4️⃣ Scanning a Website

Enter the target URL in the input box.

Click Scan.

Wait for results to appear.

Save the report if required.
