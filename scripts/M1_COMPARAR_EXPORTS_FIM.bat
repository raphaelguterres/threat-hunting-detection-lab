@echo off
setlocal EnableExtensions
cd /d "%~dp0.."
if errorlevel 1 exit /b 2
echo [M1] Offline, somente leitura. Nao coleta dados do Manager/Indexer.
python scripts\m1_fim_offline_source_match.py --manager .lab\m1-manager-authorized-export.jsonl --indexer .lab\m1-indexer-authorized-export.jsonl --scope .lab\m1-probe-scope-private.json
set "EXITCODE=%ERRORLEVEL%"
if not "%EXITCODE%"=="0" (
 echo [M1] Comparacao nao concluida. Use apenas exportacoes autorizadas reais.
 exit /b %EXITCODE%
)
echo [M1] Fontes fornecidas correspondem. Nao e aprovacao independente do Manager ou de deploy.
exit /b 0
