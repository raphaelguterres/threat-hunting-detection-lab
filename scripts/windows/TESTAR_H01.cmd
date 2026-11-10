@echo off
setlocal
echo H01: uma chamada PowerShell codificada e uma tarefa desabilitada, sem gatilhos.
echo Exige preflight e nova aprovacao. A acao da tarefa nunca sera executada.
set "h01_source=%~dp0..\M1_H01_ENCODED_CONTROLLER.ps1"
set "h01_run=%~dp0..\..\.lab\h01-live-20261110"
set "h01_local=%LOCALAPPDATA%\WazuhH01Controller-%RANDOM%-%RANDOM%"
if not exist "%h01_source%" goto failed
if not exist "%h01_run%\manifest.json" goto failed
if exist "%h01_local%" goto failed
mkdir "%h01_local%"
if errorlevel 1 goto failed
copy /b "%h01_source%" "%h01_local%\controller.ps1"
if errorlevel 1 goto failed
fc /b "%h01_source%" "%h01_local%\controller.ps1" >nul
if errorlevel 1 goto failed
powershell.exe -NoProfile -File "%h01_local%\controller.ps1" -RunDirectory "%h01_run%" -SourceDirectory "%~dp0.."
set "h01_exit=%ERRORLEVEL%"
goto finish
:failed
set "h01_exit=2"
:finish
echo Codigo de saida: %h01_exit%
pause
exit /b %h01_exit%
