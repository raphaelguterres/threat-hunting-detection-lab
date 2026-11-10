@echo off
setlocal
echo CHANGE C: aplicar UMA diretiva FIM no agente 004 e reiniciar WazuhSvc.
echo Janela termina em 10/11/2026 18:01 BRT. Ha verificacao e recuperacao em falha.
set "h03_source=%~dp0scripts\M1_H03_CHANGE_C_APPLY.ps1"
set "h03_local=%LOCALAPPDATA%\WazuhH03Apply-%RANDOM%-%RANDOM%"
if not exist "%h03_source%" goto failed
if exist "%h03_local%" goto failed
mkdir "%h03_local%"
if errorlevel 1 goto failed
copy /b "%h03_source%" "%h03_local%\apply.ps1"
if errorlevel 1 goto failed
fc /b "%h03_source%" "%h03_local%\apply.ps1" >nul
if errorlevel 1 goto failed
powershell.exe -NoProfile -File "%h03_local%\apply.ps1"
set "h03_exit=%ERRORLEVEL%"
goto finish
:failed
echo Falha de preparacao. Nenhuma ativacao iniciada.
set "h03_exit=2"
:finish
echo Codigo de saida: %h03_exit%
pause
exit /b %h03_exit%
