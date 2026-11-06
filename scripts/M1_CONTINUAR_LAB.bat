@echo off
setlocal EnableExtensions
cd /d "%~dp0.."
if errorlevel 1 exit /b 2
echo [M1] Validando excecao privada e pre-requisitos para continuidade...
python scripts\m1_evidence_gate.py --manifest .lab\m1-evidence.json --stage postchange --owner-continuation .lab\m1-owner-scoped-continuation-20261105-private.json
set "RC=%ERRORLEVEL%"
if not "%RC%"=="0" (
  echo [M1] Continuacao NAO liberada. Corrija pendencias ou renove autorizacao.
  exit /b %RC%
)
echo [M1] GO de continuidade local autorizado. Nao e autorizacao de alteracao ativa.
exit /b 0
