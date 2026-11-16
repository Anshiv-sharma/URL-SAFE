from __future__ import annotations

import hashlib
import json
import mimetypes
import os
import re
import sqlite3
import threading
import webbrowser
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent
DB_PATH = ROOT / "url_safe.db"
PORT = int(os.environ.get("URL_SAFE_PORT", "8765"))


class SecurityFinding:
    def __init__(self, title: str, detail: str, severity: str, points: int):
        self.title, self.detail, self.severity, self.points = title, detail, severity, points

    def to_dict(self):
        return vars(self)


class SecurityReport:
    def __init__(self, target: str, scan_type: str, findings: list[SecurityFinding], notes: list[str] | None = None):
        self.target, self.scan_type = target, scan_type
        self.findings, self.notes = findings, notes or []
        self.created_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

    @property
    def score(self):
        return min(100, sum(f.points for f in self.findings))

    @property
    def level(self):
        if self.score >= 70: return "Critical"
        if self.score >= 45: return "High"
        if self.score >= 25: return "Medium"
        return "Low"

    @property
    def recommendation(self):
        return {"Critical": "Stop and verify the source through a separate, trusted channel.",
                "High": "Avoid opening or sharing this item until the warning signs are resolved.",
                "Medium": "Pause and verify the context before interacting with this item.",
                "Low": "No major warning signs were found by these local checks."}[self.level]

    def to_dict(self):
        return {"target": self.target, "scan_type": self.scan_type, "score": self.score,
                "level": self.level, "recommendation": self.recommendation,
                "findings": [f.to_dict() for f in self.findings], "notes": self.notes,
                "created_at": self.created_at}


class SecurityScanner:
    scan_type = "text"
    def scan(self, target: str) -> SecurityReport:
        raise NotImplementedError


class URLScanner(SecurityScanner):
    scan_type = "url"
    def scan(self, target):
        findings, notes = [], []
        raw = target.strip()
        if not raw: return SecurityReport("(empty)", self.scan_type, [SecurityFinding("No URL entered", "Paste a URL to begin the local check.", "info", 0)])
        normalized = raw if "://" in raw else "https://" + raw
        parsed = urlparse(normalized)
        host = (parsed.hostname or "").lower()
        if parsed.scheme != "https": findings.append(SecurityFinding("Connection is not HTTPS", "The address does not use an encrypted HTTPS connection.", "medium", 25))
        if parsed.username or parsed.password: findings.append(SecurityFinding("Credentials embedded in URL", "A username or password appears before the host name.", "high", 45))
        if host.startswith("xn--") or ".xn--" in host: findings.append(SecurityFinding("Punycode domain", "Internationalized domain encoding can make lookalike names harder to spot.", "high", 35))
        if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", host): findings.append(SecurityFinding("IP address used as host", "A raw IP address can hide the identity normally shown by a domain name.", "medium", 25))
        if len(host.split(".")) > 4: findings.append(SecurityFinding("Unusually deep subdomain", "Many subdomain layers can obscure the registered domain.", "medium", 20))
        if len(raw) > 120: findings.append(SecurityFinding("Unusually long address", "Long URLs can bury the real destination or add confusing tracking parameters.", "low", 10))
        if host.count("-") >= 3: findings.append(SecurityFinding("Hyphen-heavy domain", "Several hyphens can be used to imitate a familiar brand name.", "low", 12))
        if re.search(r"(login|verify|secure|account|update|password|wallet|invoice|gift|urgent)", raw, re.I):
            findings.append(SecurityFinding("High-pressure or account language", "The address contains terms often used in credential or payment lures.", "medium", 18))
        if re.search(r"%[0-9a-f]{2}|@|\\\\", raw, re.I): findings.append(SecurityFinding("Obfuscated URL characters", "Encoded or misleading characters can disguise where a link leads.", "medium", 20))
        if not findings: findings.append(SecurityFinding("No common URL warning signs", "This local heuristic scan did not match its configured risk patterns.", "info", 0))
        notes.append("This check examines the text of the URL only. It does not visit the site or verify reputation, ownership, or page content.")
        return SecurityReport(raw[:180], self.scan_type, findings, notes)


class PasswordScanner(SecurityScanner):
    scan_type = "password"
    def scan(self, target):
        p = target
        if not p: return SecurityReport("(empty)", self.scan_type, [SecurityFinding("No password entered", "Enter a sample password to see local guidance.", "info", 0)])
        findings = []
        if len(p) < 12: findings.append(SecurityFinding("Short length", f"Use at least 12 characters; this sample has {len(p)}.", "high", 35))
        if len(p) < 16: findings.append(SecurityFinding("Room to increase length", "A longer unique passphrase is usually easier to remember and harder to guess.", "low", 12))
        groups = sum(bool(re.search(pattern, p)) for pattern in [r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]"])
        if groups < 3: findings.append(SecurityFinding("Limited character variety", "This sample uses fewer than three character groups.", "medium", 18))
        if re.search(r"password|qwerty|letmein|admin|welcome|123456|iloveyou", p, re.I): findings.append(SecurityFinding("Common password pattern", "A widely guessed word or sequence appears in the sample.", "critical", 55))
        if re.search(r"(.)\1{2,}|0123|1234|abcd|qwer", p, re.I): findings.append(SecurityFinding("Repeated or sequential characters", "Repeated characters and simple sequences are easier to guess.", "medium", 20))
        if not findings: findings.append(SecurityFinding("Good baseline structure", "No common weak patterns were detected. Use a unique password for every account.", "info", 0))
        return SecurityReport("Password sample (not stored)", self.scan_type, findings,
            ["Password checks run locally. The sample is not saved to scan history or included in reports."])


class TextScanner(SecurityScanner):
    scan_type = "text"
    patterns = [(r"\b(urgent|immediately|within 24 hours|act now|final warning)\b", "Urgency or pressure language", 15),
                (r"\b(verify your account|confirm your password|reset your credentials|suspended account)\b", "Credential or account verification request", 28),
                (r"\b(gift card|wire transfer|crypto(?:currency)?|payment required|bank details)\b", "Unusual payment request", 25),
                (r"https?://\S+|www\.\S+", "Link included in message", 12),
                (r"\b(you have won|claim your prize|too good to be true|guaranteed return)\b", "Prize or unrealistic offer", 24),
                (r"\b(do not tell|keep this secret|don't contact)\b", "Request for secrecy", 22)]
    def scan(self, target):
        if not target.strip(): return SecurityReport("(empty)", self.scan_type, [SecurityFinding("No text entered", "Paste a message or text snippet to begin.", "info", 0)])
        findings = [SecurityFinding(title, "This phrase can appear in social-engineering attempts. Check the sender and request independently.", "medium", points)
                    for pattern, title, points in self.patterns if re.search(pattern, target, re.I)]
        if not findings: findings.append(SecurityFinding("No configured phrases matched", "A clean heuristic result cannot establish that a message is trustworthy.", "info", 0))
        return SecurityReport(target[:120].replace("\n", " "), self.scan_type, findings,
            ["Text is analyzed in memory and is not retained in history. Heuristics can miss new or subtle scams."])


class FileScanner(SecurityScanner):
    scan_type = "file"
    risky = {".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".js", ".vbs", ".hta", ".jar", ".msi", ".lnk"}
    def scan(self, target):
        name = Path(target).name or "(unnamed file)"
        findings = []
        suffix = Path(name).suffix.lower()
        if suffix in self.risky: findings.append(SecurityFinding("Executable or script file", f"The .{suffix.lstrip('.')} file type can run code on your device.", "high", 42))
        if re.search(r"\.(pdf|docx?|xlsx?|jpg|png|txt)\.(exe|scr|bat|cmd|js|vbs)$", name, re.I): findings.append(SecurityFinding("Double file extension", "The visible document or image extension may conceal an executable type.", "critical", 58))
        if name.startswith(".") or name.startswith("~$"): findings.append(SecurityFinding("Hidden or temporary filename", "This name uses a hidden or temporary-file convention.", "low", 10))
        if len(name) > 100: findings.append(SecurityFinding("Unusually long filename", "A long name can make the true extension harder to notice.", "low", 10))
        if not findings: findings.append(SecurityFinding("No filename warning signs", "No configured risky extension or naming pattern was found.", "info", 0))
        return SecurityReport(name[:160], self.scan_type, findings,
            ["Only the filename and extension were checked. File contents were not opened, uploaded, or executed."])


class ScanHistory:
    def __init__(self, path=DB_PATH):
        self.path = path
        with sqlite3.connect(self.path) as db:
            db.execute("CREATE TABLE IF NOT EXISTS scans (id INTEGER PRIMARY KEY, created_at TEXT, scan_type TEXT, target TEXT, score INTEGER, level TEXT, result TEXT)")
    def save(self, report):
        if report.scan_type in ("password", "text"): return None
        data = report.to_dict()
        with sqlite3.connect(self.path) as db:
            cur = db.execute("INSERT INTO scans(created_at,scan_type,target,score,level,result) VALUES(?,?,?,?,?,?)", (data["created_at"], data["scan_type"], data["target"], data["score"], data["level"], json.dumps(data)))
            return cur.lastrowid
    def list(self, limit=50):
        with sqlite3.connect(self.path) as db:
            db.row_factory = sqlite3.Row
            return [dict(r) for r in db.execute("SELECT id,created_at,scan_type,target,score,level FROM scans ORDER BY id DESC LIMIT ?", (limit,))]
    def get(self, scan_id):
        with sqlite3.connect(self.path) as db:
            row = db.execute("SELECT result FROM scans WHERE id=?", (scan_id,)).fetchone()
            return json.loads(row[0]) if row else None


SCANNERS = {"url": URLScanner(), "password": PasswordScanner(), "text": TextScanner(), "file": FileScanner()}
HISTORY = ScanHistory()

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_): pass
    def send_json(self, data, status=200):
        payload = json.dumps(data).encode()
        self.send_response(status); self.send_header("Content-Type", "application/json; charset=utf-8"); self.send_header("Content-Length", str(len(payload))); self.send_header("Cache-Control", "no-store"); self.end_headers(); self.wfile.write(payload)
    def do_GET(self):
        route = urlparse(self.path).path
        if route == "/api/history": return self.send_json(HISTORY.list())
        if route.startswith("/api/report/"):
            try: report = HISTORY.get(int(route.rsplit("/", 1)[1]))
            except ValueError: report = None
            return self.send_json(report or {"error": "Report not found"}, 200 if report else 404)
        if route == "/api/health": return self.send_json({"ok": True})
        file = ROOT / ("index.html" if route == "/" else route.lstrip("/"))
        if not file.is_file() or file.parent != ROOT: self.send_error(404); return
        mime = mimetypes.guess_type(file.name)[0] or "application/octet-stream"
        data = file.read_bytes(); self.send_response(200); self.send_header("Content-Type", mime + ("; charset=utf-8" if mime.startswith("text/") or "javascript" in mime else "")); self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)
    def do_POST(self):
        if self.path != "/api/scan": self.send_error(404); return
        try:
            req = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
            kind, target = req.get("type"), str(req.get("target", ""))
            scanner = SCANNERS.get(kind)
            if not scanner: return self.send_json({"error": "Unknown scan type"}, 400)
            if len(target) > 12000: return self.send_json({"error": "Input is too long"}, 413)
            report = scanner.scan(target)
            saved_id = HISTORY.save(report)
            result = report.to_dict(); result["id"] = saved_id
            return self.send_json(result)
        except (json.JSONDecodeError, TypeError): return self.send_json({"error": "Invalid request"}, 400)

if __name__ == "__main__":
    server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    url = f"http://127.0.0.1:{PORT}"
    print(f"URL-SAFE is running at {url}  (Ctrl+C to stop)")
    threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try: server.serve_forever()
    except KeyboardInterrupt: print("\nURL-SAFE stopped.")
    finally: server.server_close()
