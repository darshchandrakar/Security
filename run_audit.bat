@echo off
echo =====================================
echo Starting Level 4 Security Audit
echo =====================================

echo Checking PowerShell execution policy...
powershell -Command "Set-ExecutionPolicy Bypass -Scope Process -Force"

echo Running audit script...
powershell -ExecutionPolicy Bypass -File "%~dp0audit_L4.ps1"

echo.
echo =====================================
echo Audit finished.
echo Check the logs folder for results.
echo =====================================

pause