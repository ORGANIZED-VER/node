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
        else:
            try:
                from pyngrok import ngrok
                logger.info("Setting up ngrok tunnel...")
                auth_token = config.get("ngrok_auth_token", "YOUR_DEFAULT_TOKEN_HERE")
                ngrok.set_auth_token(auth_token)
                public_url = ngrok.connect(port).public_url
                os.environ["VIEWER_PUBLIC_URL"] = public_url
                logger.info(f"ngrok tunnel created at {public_url}")
            except Exception as e:
                logger.error(f"Failed to setup ngrok tunnel: {e}")
            
        logger.info("Starting Telegram Bot (blocking main thread)...")
        run_bot()
    except KeyboardInterrupt:
        logger.info("Services stopped by user.")

if __name__ == "__main__":
    main()
