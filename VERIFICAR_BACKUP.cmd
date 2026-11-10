@echo off
setlocal
echo Verificacao de backup Wazuh - recuperacao apenas em memoria.
echo Nenhum arquivo ativo sera restaurado e nenhum servico sera reiniciado.
echo Uma copia local do verificador sera criada. A politica PowerShell sera preservada.
set "backup_check_source=%~dp0.lab\m1-change-prep\M1_CHANGE_C_BACKUP_VERIFY_ONLY.ps1"
if not exist "%backup_check_source%" goto source_missing
set "backup_check_dir=%LOCALAPPDATA%\WazuhM1Verify-%RANDOM%-%RANDOM%"
if exist "%backup_check_dir%" goto target_exists
mkdir "%backup_check_dir%"
if errorlevel 1 goto copy_failed
copy /b "%backup_check_source%" "%backup_check_dir%\verify.ps1"
if errorlevel 1 goto copy_failed
fc /b "%backup_check_source%" "%backup_check_dir%\verify.ps1" >nul
if errorlevel 1 goto copy_failed
powershell.exe -NoProfile -File "%backup_check_dir%\verify.ps1" -BackupFolder "%LOCALAPPDATA%\WazuhM1ChangeC-20261104T201324Z"
set "backup_check_exit=%ERRORLEVEL%"
goto finish
:source_missing
echo ERRO: verificador de origem ausente.
set "backup_check_exit=2"
goto finish
:target_exists
echo ERRO: pasta de destino ja existe. Nenhum arquivo foi sobrescrito.
set "backup_check_exit=2"
goto finish
:copy_failed
echo ERRO: falha ao preparar ou conferir a copia local. Verificacao cancelada.
set "backup_check_exit=2"
:finish
echo.
echo Codigo de saida: %backup_check_exit%
pause
exit /b %backup_check_exit%
