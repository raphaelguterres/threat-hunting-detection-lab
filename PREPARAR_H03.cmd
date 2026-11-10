@echo off
setlocal
echo CHANGE C AUTORIZADA: criar pastas protegidas e preparar proposta FIM.
echo Este passo NAO altera ossec.conf ativo e NAO reinicia o servico.
set "h03_source=%~dp0scripts\M1_H03_CHANGE_C_PREPARE.ps1"
set "h03_local=%LOCALAPPDATA%\WazuhH03Prepare-%RANDOM%-%RANDOM%"
if not exist "%h03_source%" goto failed
if exist "%h03_local%" goto failed
mkdir "%h03_local%"
if errorlevel 1 goto failed
copy /b "%h03_source%" "%h03_local%\prepare.ps1"
if errorlevel 1 goto failed
fc /b "%h03_source%" "%h03_local%\prepare.ps1" >nul
if errorlevel 1 goto failed
powershell.exe -NoProfile -File "%h03_local%\prepare.ps1"
set "h03_exit=%ERRORLEVEL%"
goto finish
:failed
echo Falha ao preparar executor. Operacao cancelada.
set "h03_exit=2"
:finish
echo Codigo de saida: %h03_exit%
pause
exit /b %h03_exit%
