@echo off
rem Установка smartdns службой Windows.
rem Запускать от администратора: install-windows.bat

set DIR=%~dp0
set DEST=C:\Program Files\smartdns

if not exist "%DEST%" mkdir "%DEST%"
copy /Y "%DIR%smartdns.exe" "%DEST%\" >nul
if not exist "%DEST%\smartdns.yaml" copy /Y "%DIR%smartdns.yaml" "%DEST%\" >nul

"%DEST%\smartdns.exe" -service remove >nul 2>&1
"%DEST%\smartdns.exe" -config "%DEST%\smartdns.yaml" -service install
"%DEST%\smartdns.exe" -service start

echo.
echo Готово. Проверка:
echo   nslookup claude.ai 127.0.0.1
echo   type "%DEST%\smartdns.log"
echo.
echo Остановить:  "%DEST%\smartdns.exe" -service stop
echo Удалить:     "%DEST%\smartdns.exe" -service remove
pause
