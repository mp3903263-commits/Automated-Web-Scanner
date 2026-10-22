"""
Automated Web Scanner
---------------------
A defensive, passive auditing tool that checks a website for:
  1. Missing / weak HTTP security headers
  2. Insecure cookie flags
  3. Information-leaking headers
  4. CORS misconfigurations

Use ONLY on websites you own or have written permission to test.

Run the web UI :  python app.py
Run from the CLI:  python app.py --url https://example.com
"""

import argparse
import ipaddress
import json
import re
import socket
from urllib.parse import urljoin, urlparse

import requests
from flask import Flask, Response, jsonify, request

app = Flask(__name__)

TIMEOUT = 8
MAX_REDIRECTS = 5
USER_AGENT = "AutomatedWebScanner/1.0 (defensive security audit)"
SEVERITY_WEIGHT = {"Critical": 25, "High": 15, "Medium": 8, "Low": 3, "Info": 0}

# Header name -> (severity if missing, advice)
SECURITY_HEADERS = {
    "Strict-Transport-Security": (
        "High",
        "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to force HTTPS.",
    ),
    "Content-Security-Policy": (
        "High",
        "Define a Content-Security-Policy to restrict where scripts, styles and frames load from.",
    ),
    "X-Frame-Options": (
        "Medium",
        "Add 'X-Frame-Options: DENY' (or CSP frame-ancestors) to prevent clickjacking.",
    ),
    "X-Content-Type-Options": (
        "Medium",
        "Add 'X-Content-Type-Options: nosniff' to stop MIME-type sniffing.",
    ),
    "Referrer-Policy": (
        "Low",
        "Add 'Referrer-Policy: strict-origin-when-cross-origin' to limit referrer leakage.",
    ),
    "Permissions-Policy": (
        "Low",
        "Add a Permissions-Policy to disable unused browser features (camera, mic, geolocation).",
    ),
    "Cross-Origin-Opener-Policy": (
        "Low",
        "Add 'Cross-Origin-Opener-Policy: same-origin' to isolate the browsing context.",
    ),
}


# --------------------------------------------------------------------------
# Target validation (basic SSRF protection)
# --------------------------------------------------------------------------
def normalize_url(raw):
    raw = (raw or "").strip()
    if not raw:
        raise ValueError("Please enter a URL.")
    if not re.match(r"^https?://", raw, re.I):
        raw = "https://" + raw
    parsed = urlparse(raw)
    if not parsed.hostname:
        raise ValueError("Invalid URL.")
    return raw


def assert_public_host(url, allow_private=False):
    """Refuse to scan loopback / private / link-local addresses unless allowed."""
    if allow_private:
        return
    host = urlparse(url).hostname
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        raise ValueError(f"Could not resolve host: {host}")
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
        ):
            raise ValueError(
                "Scanning private or internal addresses is blocked for safety."
            )


def safe_request(method, url, headers=None, allow_private=False):
    """HTTP request that follows redirects manually, validating every hop."""
    hdrs = {"User-Agent": USER_AGENT}
    if headers:
        hdrs.update(headers)
    for _ in range(MAX_REDIRECTS + 1):
        assert_public_host(url, allow_private)
        resp = requests.request(
            method, url, headers=hdrs, timeout=TIMEOUT, allow_redirects=False
        )
        if resp.status_code in (301, 302, 303, 307, 308) and resp.headers.get("Location"):
            url = urljoin(url, resp.headers["Location"])
            continue
        return resp, url
    raise ValueError("Too many redirects.")


# --------------------------------------------------------------------------
# Checks
# --------------------------------------------------------------------------
def finding(category, title, severity, detail, fix=""):
    return {
        "category": category,
        "title": title,
        "severity": severity,
        "detail": detail,
        "fix": fix,
    }


def check_headers(resp):
    results = []
    h = resp.headers
    for name, (severity, advice) in SECURITY_HEADERS.items():
        value = h.get(name)
        if name == "X-Frame-Options" and not value:
            csp = h.get("Content-Security-Policy", "")
            if "frame-ancestors" in csp.lower():
                continue
        if not value:
            results.append(finding("Security Headers", f"Missing {name}", severity,
                                   f"The response does not include the {name} header.", advice))
            continue

        # Quality checks for present headers
        if name == "Strict-Transport-Security":
            m = re.search(r"max-age=(\d+)", value, re.I)
            if not m or int(m.group(1)) < 15552000:
                results.append(finding("Security Headers", "Weak HSTS max-age", "Medium",
                                       f"Value is '{value}'. max-age should be at least 15552000 (180 days).",
                                       "Increase max-age to 31536000."))
                continue
        if name == "Content-Security-Policy":
            weak = [t for t in ("'unsafe-inline'", "'unsafe-eval'") if t in value]
            if weak or re.search(r"(^|[\s;])\*([\s;]|$)", value):
                results.append(finding("Security Headers", "Weak Content-Security-Policy", "Medium",
                                       "Policy allows " + (", ".join(weak) or "wildcard sources") + ".",
                                       "Remove unsafe directives and wildcard sources; use nonces or hashes."))
                continue
        if name == "X-Content-Type-Options" and value.strip().lower() != "nosniff":
            results.append(finding("Security Headers", "Incorrect X-Content-Type-Options", "Low",
                                   f"Value is '{value}', expected 'nosniff'.", "Set it to 'nosniff'."))
            continue
        results.append(finding("Security Headers", f"{name} present", "Info", f"Value: {value[:160]}"))

    # Information leakage
    server = h.get("Server", "")
    if re.search(r"\d", server):
        results.append(finding("Information Leakage", "Server header reveals version", "Low",
                               f"Server: {server}", "Hide the server version string."))
    if h.get("X-Powered-By"):
        results.append(finding("Information Leakage", "X-Powered-By header exposed", "Low",
                               f"X-Powered-By: {h['X-Powered-By']}", "Remove the X-Powered-By header."))
    return results


def check_cookies(resp, final_url):
    results = []
    try:
        raw_cookies = resp.raw.headers.getlist("Set-Cookie")
    except Exception:
        raw_cookies = []
    https = final_url.lower().startswith("https://")
    for c in raw_cookies:
        name = c.split("=", 1)[0].strip()
        low = c.lower()
        problems = []
        if https and "secure" not in low:
            problems.append("Secure")
        if "httponly" not in low:
            problems.append("HttpOnly")
        if "samesite" not in low:
            problems.append("SameSite")
        if problems:
            results.append(finding("Cookies", f"Cookie '{name}' missing flags", "Medium",
                                   "Missing: " + ", ".join(problems),
                                   "Set Secure, HttpOnly and SameSite=Lax/Strict on cookies."))
    if raw_cookies and not any(r["category"] == "Cookies" for r in results):
        results.append(finding("Cookies", "Cookie flags look good", "Info",
                               f"{len(raw_cookies)} cookie(s) checked."))
    return results


def check_cors(url, allow_private=False):
    results = []
    host = urlparse(url).hostname
    tests = [
        ("arbitrary origin", "https://evil.example"),
        ("null origin", "null"),
        ("look-alike origin", f"https://{host}.evil.example"),
    ]
    reflected_any = False
    for label, origin in tests:
        try:
            r, _ = safe_request("GET", url, {"Origin": origin}, allow_private)
        except Exception as exc:
            results.append(finding("CORS", f"CORS test failed ({label})", "Info", str(exc)))
            continue
        acao = r.headers.get("Access-Control-Allow-Origin")
        acac = (r.headers.get("Access-Control-Allow-Credentials") or "").lower() == "true"
        if not acao:
            continue
        if acao == origin:
            reflected_any = True
            if acac:
                results.append(finding("CORS", f"Reflects {label} WITH credentials", "Critical",
                                       f"Origin '{origin}' is echoed back and credentials are allowed.",
                                       "Use a strict allow-list of trusted origins; never reflect the Origin header."))
            else:
                results.append(finding("CORS", f"Reflects {label}", "Medium",
                                       f"Origin '{origin}' is echoed back in Access-Control-Allow-Origin.",
                                       "Validate origins against an explicit allow-list."))
        elif acao == "*":
            if acac:
                results.append(finding("CORS", "Wildcard origin with credentials flag", "High",
                                       "Access-Control-Allow-Origin: * combined with Allow-Credentials: true.",
                                       "Do not combine wildcard origins with credentials."))
            else:
                results.append(finding("CORS", "Wildcard CORS policy", "Low",
                                       "Access-Control-Allow-Origin: * lets any site read responses.",
                                       "Restrict to specific trusted origins if the data is not public."))
                break

    # Preflight check
    try:
        r, _ = safe_request(
            "OPTIONS", url,
            {"Origin": "https://evil.example",
             "Access-Control-Request-Method": "PUT"},
            allow_private,
        )
        methods = r.headers.get("Access-Control-Allow-Methods", "")
        if r.headers.get("Access-Control-Allow-Origin") in ("*", "https://evil.example") and \
                re.search(r"\b(PUT|DELETE|PATCH)\b", methods, re.I):
            results.append(finding("CORS", "Preflight allows unsafe methods", "Medium",
                                   f"Access-Control-Allow-Methods: {methods}",
                                   "Limit allowed methods to what the API really needs."))
    except Exception:
        pass

    if not results:
        results.append(finding("CORS", "No CORS misconfiguration detected", "Info",
                               "No permissive Access-Control-Allow-Origin behaviour was observed."))
    return results


# --------------------------------------------------------------------------
# Scan driver
# --------------------------------------------------------------------------
def grade(score):
    for limit, letter in ((90, "A"), (80, "B"), (65, "C"), (50, "D")):
        if score >= limit:
            return letter
    return "F"


def run_scan(raw_url, allow_private=False):
    url = normalize_url(raw_url)
    resp, final_url = safe_request("GET", url, allow_private=allow_private)

    findings = []
    findings += check_headers(resp)
    findings += check_cookies(resp, final_url)
    findings += check_cors(final_url, allow_private)

    if not final_url.lower().startswith("https://"):
        findings.append(finding("Transport", "Site is not served over HTTPS", "High",
                                "The final URL uses plain HTTP.", "Enable HTTPS with a valid TLS certificate."))

    score = max(0, 100 - sum(SEVERITY_WEIGHT[f["severity"]] for f in findings))
    summary = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITY_WEIGHT}
    return {
        "target": url,
        "final_url": final_url,
        "status_code": resp.status_code,
        "score": score,
        "grade": grade(score),
        "summary": summary,
        "findings": findings,
    }


# --------------------------------------------------------------------------
# Web UI
# --------------------------------------------------------------------------
INDEX_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Automated Web Scanner</title>
<style>
  :root { --bg:#0b1020; --card:#131a33; --line:#25305c; --text:#e6ebff; --muted:#93a0c9; --accent:#38bdf8; }
  * { box-sizing:border-box; }
  body { margin:0; font-family:'Segoe UI',system-ui,sans-serif; background:var(--bg); color:var(--text); }
  header { padding:32px 20px 10px; text-align:center; }
  h1 { margin:0; font-size:2rem; }
  h1 span { color:var(--accent); }
  p.sub { color:var(--muted); margin:8px 0 0; }
  main { max-width:900px; margin:0 auto; padding:20px; }
  form { display:flex; gap:10px; margin:20px 0; }
  input { flex:1; padding:14px; border-radius:10px; border:1px solid var(--line); background:var(--card); color:var(--text); font-size:1rem; }
  button { padding:14px 26px; border:0; border-radius:10px; background:var(--accent); color:#06212e; font-weight:700; cursor:pointer; font-size:1rem; }
  button:disabled { opacity:.6; cursor:wait; }
  .notice { font-size:.85rem; color:var(--muted); background:var(--card); border:1px solid var(--line); border-radius:10px; padding:10px 14px; }
  .card { background:var(--card); border:1px solid var(--line); border-radius:14px; padding:20px; margin-top:20px; }
  .score { display:flex; align-items:center; gap:20px; flex-wrap:wrap; }
  .grade { font-size:3.2rem; font-weight:800; width:90px; height:90px; border-radius:50%; display:grid; place-items:center; border:4px solid var(--accent); }
  .chips span { display:inline-block; margin:4px 6px 0 0; padding:4px 10px; border-radius:999px; font-size:.8rem; background:#0e1530; border:1px solid var(--line); }
  .f { border-left:5px solid var(--line); background:#0e1530; border-radius:8px; padding:12px 14px; margin-top:10px; }
  .f h3 { margin:0 0 4px; font-size:1rem; }
  .f small { color:var(--muted); }
  .f .fix { margin-top:6px; color:#a7f3d0; font-size:.9rem; }
  .Critical { border-color:#ef4444; } .High { border-color:#f97316; }
  .Medium { border-color:#eab308; } .Low { border-color:#38bdf8; } .Info { border-color:#22c55e; }
  .err { color:#fca5a5; }
</style>
</head>
<body>
<header>
  <h1>Automated <span>Web Scanner</span></h1>
  <p class="sub">Audit a website for secure headers, cookie flags and CORS flaws</p>
</header>
<main>
  <form id="f">
    <input id="url" placeholder="https://example.com" required>
    <button id="go">Scan</button>
  </form>
  <div class="notice">Only scan sites you own or have written permission to test. This tool performs passive, read-only checks.</div>
  <div id="out"></div>
</main>
<script>
const out = document.getElementById('out');
function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}
document.getElementById('f').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const btn = document.getElementById('go');
  btn.disabled = true; btn.textContent = 'Scanning...';
  out.replaceChildren();
  try {
    const r = await fetch('/api/scan', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({url: document.getElementById('url').value})
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || 'Scan failed');
    render(d);
  } catch (e) {
    out.appendChild(el('div', 'card err', e.message));
  } finally {
    btn.disabled = false; btn.textContent = 'Scan';
  }
});
function render(d) {
  const card = el('div', 'card');
  const row = el('div', 'score');
  row.appendChild(el('div', 'grade', d.grade));
  const info = el('div');
  info.appendChild(el('h2', '', 'Security score: ' + d.score + '/100'));
  info.appendChild(el('small', '', d.final_url + '  (HTTP ' + d.status_code + ')'));
  const chips = el('div', 'chips');
  for (const [k, v] of Object.entries(d.summary)) chips.appendChild(el('span', '', k + ': ' + v));
  info.appendChild(chips);
  row.appendChild(info);
  card.appendChild(row);
  out.appendChild(card);

  const order = ['Critical', 'High', 'Medium', 'Low', 'Info'];
  const sorted = d.findings.slice().sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity));
  const list = el('div', 'card');
  list.appendChild(el('h2', '', 'Findings (' + sorted.length + ')'));
  for (const f of sorted) {
    const box = el('div', 'f ' + f.severity);
    box.appendChild(el('h3', '', '[' + f.severity + '] ' + f.title));
    box.appendChild(el('small', '', f.category + ' - ' + f.detail));
    if (f.fix) box.appendChild(el('div', 'fix', 'Fix: ' + f.fix));
    list.appendChild(box);
  }
  out.appendChild(list);
}
</script>
</body>
</html>
"""


@app.route("/")
def index():
    return Response(INDEX_HTML, mimetype="text/html")


@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json(silent=True) or {}
    try:
        return jsonify(run_scan(data.get("url", "")))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except requests.RequestException as exc:
        return jsonify({"error": f"Could not reach the target: {exc.__class__.__name__}"}), 502


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Automated Web Scanner")
    parser.add_argument("--url", help="Scan this URL from the command line and exit")
    parser.add_argument("--allow-private", action="store_true",
                        help="Allow scanning localhost/private IPs (for your own test servers)")
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args()

    if args.url:
        try:
            print(json.dumps(run_scan(args.url, args.allow_private), indent=2))
        except Exception as exc:
            print("Error:", exc)
        return
    app.run(host="127.0.0.1", port=args.port, debug=False)


if __name__ == "__main__":
    main()
