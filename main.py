#!/usr/bin/env python3
"""
Telegram Bot for MailDiggerPro with integrated FastAPI viewer
"""

import logging
import threading
import uvicorn
import socket
import urllib.request
import os
import time
from .bot import run_bot

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO
)
logger = logging.getLogger(__name__)

def get_ip_info():
    local_ip = "127.0.0.1"
    public_ip = "Unknown"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except Exception:
        pass
    try:
        req = urllib.request.Request("https://api.ipify.org")
        with urllib.request.urlopen(req, timeout=3) as response:
            public_ip = response.read().decode('utf-8')
    except Exception:
        pass
    return local_ip, public_ip

def get_free_port(start_port=3000, max_port=3020):
    for port in range(start_port, max_port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(('0.0.0.0', port)) != 0:
                return port
    return start_port

def start_viewer(port):
    uvicorn.run(
        "bot_telegram_maildiggerpro.viewer_app:app",
        host="0.0.0.0",
        port=port,
        log_level="info",
        reload=False,
    )

import shutil
import subprocess
import re
import atexit

cloudflared_proc = None

def find_cloudflared():
    candidates = [
        "cloudflared",
        "cloudflared.exe",
        os.path.join(os.path.dirname(__file__), "cloudflared.exe"),
        os.path.join(os.path.dirname(__file__), "cloudflared-windows-amd64.exe"),
        os.path.expanduser(r"~\Downloads\cloudflared.exe"),
        os.path.expanduser(r"~\Downloads\cloudflared-windows-amd64.exe"),
    ]
    for c in candidates:
        if shutil.which(c):
            return shutil.which(c)
        if os.path.exists(c):
            return c
    return None

def start_cloudflared_tunnel(port):
    global cloudflared_proc
    exe = find_cloudflared()
    if not exe:
        logger.warning("cloudflared executable not found automatically.")
        return None
    try:
        logger.info(f"Starting Cloudflare Tunnel automatically using {exe} on port {port}...")
        cloudflared_proc = subprocess.Popen(
            [exe, "tunnel", "--url", f"http://localhost:{port}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
        )
        atexit.register(stop_cloudflared_tunnel)
        
        # Read lines to find trycloudflare.com URL
        url_pattern = re.compile(r"https://[a-zA-Z0-9-]+\.trycloudflare\.com")
        start_time = time.time()
        while time.time() - start_time < 20:
            line = cloudflared_proc.stdout.readline()
            if not line:
                if cloudflared_proc.poll() is not None:
                    break
                time.sleep(0.1)
                continue
            match = url_pattern.search(line)
            if match:
                url = match.group(0)
                logger.info(f" Cloudflare Tunnel established at: {url}")
                return url
    except Exception as e:
        logger.error(f"Failed to start Cloudflare Tunnel: {e}")
    return None

def stop_cloudflared_tunnel():
    global cloudflared_proc
    if cloudflared_proc and cloudflared_proc.poll() is None:
        try:
            cloudflared_proc.terminate()
            logger.info("Cloudflare tunnel terminated.")
        except Exception:
            pass

def main():
    try:
        local_ip, public_ip = get_ip_info()
        port = get_free_port(3000)
        
        os.environ["VIEWER_LOCAL_IP"] = local_ip
        os.environ["VIEWER_PUBLIC_IP"] = public_ip
        os.environ["VIEWER_PORT"] = str(port)
        
        logger.info(f"Detected IPs - Local: {local_ip}, Public: {public_ip}")
        logger.info(f"Starting Mobile Viewer on port {port} in background thread...")
        
        t = threading.Thread(target=start_viewer, args=(port,), daemon=True)
        t.start()
        
        # 1. Try starting Cloudflare Tunnel automatically
        cf_url = start_cloudflared_tunnel(port)
        if cf_url:
            os.environ["VIEWER_PUBLIC_URL"] = cf_url
        else:
            # 2. Check config.yaml
            import yaml
            try:
                config_path = os.path.join(os.path.dirname(__file__), "config.yaml")
                with open(config_path, "r", encoding="utf-8") as f:
                    config = yaml.safe_load(f) or {}
            except Exception:
                config = {}
            if config.get("public_url"):
                public_url = config["public_url"]
                os.environ["VIEWER_PUBLIC_URL"] = public_url
                logger.info(f"Using configured public URL: {public_url}")
            
        logger.info("Starting Telegram Bot (blocking main thread)...")
        run_bot()
    except KeyboardInterrupt:
        logger.info("Services stopped by user.")
    finally:
        stop_cloudflared_tunnel()

if __name__ == "__main__":
    main()
