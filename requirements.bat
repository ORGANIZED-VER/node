@echo off
echo ============================================
echo Telegram Bot - Installing Dependencies
echo ============================================
echo.

echo Installing dependencies...
pip install python-telegram-bot>=20.0
pip install requests
pip install fastapi
pip install "uvicorn[standard]"
pip install PyYAML

echo.
echo ============================================
echo Installation Complete!
echo ============================================
pause
