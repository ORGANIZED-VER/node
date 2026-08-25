@echo off
echo Starting MailDiggerPro Telegram Bot...
cd /d "%~dp0.."
python -m bot_telegram_maildiggerpro.main
pause
