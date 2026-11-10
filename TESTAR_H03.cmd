@echo off
setlocal
echo H03: teste autorizado de dois programas benignos, com coleta Sysmon e limpeza.
echo Aguarda comprovacao Manager/Indexer antes de modificar e executar.
set "h03_source=%~dp0scripts\M1_H03_CONTROLLED_BINARY_TEST.ps1"
set "h03_run=%~dp0.lab\h03-live-20261110"
set "h03_local=%LOCALAPPDATA%\WazuhH03Binary-%RANDOM%-%RANDOM%"
if not exist "%h03_source%" goto failed
if not exist "%h03_run%\manifest.json" goto failed
if exist "%h03_local%" goto failed
mkdir "%h03_local%"
if errorlevel 1 goto failed
copy /b "%h03_source%" "%h03_local%\test.ps1"
if errorlevel 1 goto failed
fc /b "%h03_source%" "%h03_local%\test.ps1" >nul
if errorlevel 1 goto failed
powershell.exe -NoProfile -File "%h03_local%\test.ps1" -RunDirectory "%h03_run%"
set "h03_exit=%ERRORLEVEL%"
goto finish
:failed
echo Falha de preparacao. Nada sera executado.
set "h03_exit=2"
:finish
echo Codigo de saida: %h03_exit%
pause
exit /b %h03_exit%
