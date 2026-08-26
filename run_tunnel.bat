@echo off
title Cloudflare Tunnel for MailDiggerPro
echo ========================================================
echo   Starting Cloudflare Tunnel for Mini App (Port 3000)...
echo ========================================================
echo.

where cloudflared >nul 2>&1
if %errorlevel% equ 0 (
    cloudflared tunnel --url http://localhost:3000
    goto end
)

if exist "cloudflared.exe" (
    cloudflared.exe tunnel --url http://localhost:3000
    goto end
)

if exist "cloudflared-windows-amd64.exe" (
    cloudflared-windows-amd64.exe tunnel --url http://localhost:3000
    goto end
)

if exist "%USERPROFILE%\Downloads\cloudflared.exe" (
    "%USERPROFILE%\Downloads\cloudflared.exe" tunnel --url http://localhost:3000
    goto end
)

if exist "%USERPROFILE%\Downloads\cloudflared-windows-amd64.exe" (
    "%USERPROFILE%\Downloads\cloudflared-windows-amd64.exe" tunnel --url http://localhost:3000
    goto end
)

echo [ERROR] cloudflared.exe not found!
echo Please make sure cloudflared.exe or cloudflared-windows-amd64.exe is in this folder or in Downloads.
echo.
pause

:end
pause
