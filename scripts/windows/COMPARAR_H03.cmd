@echo off
setlocal
echo Comparacao H03 SOMENTE LEITURA. Valores privados nao serao impressos.
set "h03_source=%~dp0..\M1_H03_COMPARE_READONLY.ps1"
set "h03_local=%LOCALAPPDATA%\WazuhH03Compare-%RANDOM%-%RANDOM%"
if not exist "%h03_source%" goto failed
if exist "%h03_local%" goto failed
mkdir "%h03_local%"
if errorlevel 1 goto failed
copy /b "%h03_source%" "%h03_local%\compare.ps1"
if errorlevel 1 goto failed
fc /b "%h03_source%" "%h03_local%\compare.ps1" >nul
if errorlevel 1 goto failed
powershell.exe -NoProfile -File "%h03_local%\compare.ps1"
set "h03_exit=%ERRORLEVEL%"
goto finish
:failed
echo Falha na preparacao. Comparacao cancelada.
set "h03_exit=2"
:finish
echo Codigo de saida: %h03_exit%
pause
exit /b %h03_exit%
