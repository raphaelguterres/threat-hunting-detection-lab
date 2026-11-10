@echo off
setlocal
echo Preflight H03: consulta de volume, servico e ACL por SID.
echo A copia local do verificador sera preservada. Nenhuma mudanca H03 sera aplicada.
set "h03_source=%~dp0..\M1_H03_PREFLIGHT_READONLY.ps1"
set "h03_local=%LOCALAPPDATA%\WazuhH03Preflight-%RANDOM%-%RANDOM%"
if not exist "%h03_source%" goto failed
if exist "%h03_local%" goto failed
mkdir "%h03_local%"
if errorlevel 1 goto failed
copy /b "%h03_source%" "%h03_local%\preflight.ps1"
if errorlevel 1 goto failed
fc /b "%h03_source%" "%h03_local%\preflight.ps1" >nul
if errorlevel 1 goto failed
powershell.exe -NoProfile -File "%h03_local%\preflight.ps1"
set "h03_exit=%ERRORLEVEL%"
goto finish
:failed
echo Falha de preparacao. Preflight cancelado.
set "h03_exit=2"
:finish
echo Codigo de saida: %h03_exit%
pause
exit /b %h03_exit%
