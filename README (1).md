# Automated Web Scanner

A Python tool that audits websites for **secure HTTP headers**, **cookie flags** and **CORS misconfigurations**, then gives a security score (0-100), a letter grade and fix recommendations.

> **Legal notice:** Only scan websites you own or have written permission to test. The scanner performs passive, read-only checks, but unauthorised scanning may still be illegal.

## Features

- Checks 7 important security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP)
- Detects weak values, such as short HSTS max-age or `unsafe-inline` in CSP
- Detects information leakage (`Server` version, `X-Powered-By`)
- Audits cookies for `Secure`, `HttpOnly` and `SameSite`
- Tests CORS: reflected origins, `null` origin, wildcard with credentials, unsafe preflight methods
- Severity levels: Critical, High, Medium, Low, Info
- Web interface and command-line mode
- Built-in protection that blocks scans of private/internal IP addresses (SSRF safety)

## Project structure

```
app.py                                   Flask app + scanner logic
automated-web-scanner-project-report.html   Project report (open in a browser)
README.md                                This file
requirements.txt                         Python dependencies
```

## Installation

```bash
# 1. (Optional) create a virtual environment
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # Linux / macOS

# 2. Install dependencies
pip install -r requirements.txt
```

## Usage

### Web interface

```bash
python app.py
```

Open http://127.0.0.1:5000, enter a URL and click **Scan**.

### Command line

```bash
python app.py --url https://example.com
```

To test your own local server:

```bash
python app.py --url http://127.0.0.1:8000 --allow-private
```

## How scoring works

The score starts at 100 and points are deducted per finding:

| Severity | Deduction |
|----------|-----------|
| Critical | 25 |
| High     | 15 |
| Medium   | 8  |
| Low      | 3  |
| Info     | 0  |

Grades: **A** 90+, **B** 80+, **C** 65+, **D** 50+, **F** below 50.

## Technologies used

- Python 3
- Flask (web interface and API)
- Requests (HTTP client)
- HTML, CSS, JavaScript (front end)

## Limitations

- Checks only the single URL given (no crawling)
- Does not test for injection, XSS or authentication flaws
- Results depend on the headers the server sends to this scanner's request

## Future scope

- Crawl multiple pages and subdomains
- TLS/SSL certificate and cipher analysis
- Export reports as PDF/JSON
- Scan history with a database
