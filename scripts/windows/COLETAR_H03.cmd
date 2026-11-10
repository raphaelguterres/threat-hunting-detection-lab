@echo off
setlocal
echo H03: apenas coleta dos eventos Sysmon existentes. Nao executa probes.
set "h03_source=%~dp0..\M1_H03_COLLECT_NATIVE_READONLY.ps1"
set "h03_run=%~dp0..\..\.lab\h03-live-20261110e"
set "h03_local=%LOCALAPPDATA%\WazuhH03Collect-%RANDOM%-%RANDOM%"
if not exist "%h03_source%" goto failed
if exist "%h03_local%" goto failed
mkdir "%h03_local%"
if errorlevel 1 goto failed
copy /b "%h03_source%" "%h03_local%\collect.ps1"
if errorlevel 1 goto failed
fc /b "%h03_source%" "%h03_local%\collect.ps1" >nul
if errorlevel 1 goto failed
powershell.exe -NoProfile -File "%h03_local%\collect.ps1" -RunDirectory "%h03_run%"
set "h03_exit=%ERRORLEVEL%"
goto finish
:failed
set "h03_exit=2"
:finish
echo Codigo de saida: %h03_exit%
pause
exit /b %h03_exit%
