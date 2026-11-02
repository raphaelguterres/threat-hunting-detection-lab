@echo off
setlocal EnableExtensions DisableDelayedExpansion
title M1 - Threat Hunting Offline - Laboratorio Blue Team
cd /d "%~dp0.."
echo.
echo =====================================================
echo  M1 - THREAT HUNTING / CORRELACAO OFFLINE
echo =====================================================
echo  Nenhuma conexao com VMs, credenciais ou servico Wazuh.
echo  As saidas mostram so quantidades agregadas.
echo  Resultados sinteticos NAO sao incidentes reais.
echo.
where python >nul 2>&1
if errorlevel 1 (
 echo ERRO: Python nao encontrado no PATH do Windows.
 pause
 exit /b 2
)
:menu
echo.
echo  [1] Executar 20 testes e demonstracao SINTETICA
echo  [2] Analisar arquivo PRIVADO .lab\m1-normalized-events.jsonl
echo  [3] Sair
echo.
set "CHOICE="
set /p "CHOICE=Escolha uma opcao: "
if "%CHOICE%"=="1" goto synthetic
if "%CHOICE%"=="2" goto private
if "%CHOICE%"=="3" exit /b 0
echo Opcao invalida.
goto menu

:synthetic
echo.
echo MODO: SINTETICO, 12 eventos artificiais, nenhuma telemetria real.
python -m unittest discover -s tests -p test_hunt_correlations.py -q
if errorlevel 1 (
 echo FALHA: testes unitarios nao passaram.
 pause
 exit /b 3
)
python scripts\hunt_correlations.py --input tests\fixtures\m1-synthetic.jsonl --fixture
if errorlevel 1 (
 echo FALHA: fixture sintética invalida.
 pause
 exit /b 4
)
echo.
echo SINTETICO_OK: o programa funcionou; M1 real permanece pendente.
pause
exit /b 0

:private
echo.
echo MODO: SOMENTE LEITURA DO ARQUIVO NORMALIZADO PRIVADO.
echo O analista deve confirmar previamente a origem de cada evento.
if not exist ".lab\m1-normalized-events.jsonl" (
 echo PENDENTE: nao existe .lab\m1-normalized-events.jsonl.
 echo Nao copie registros sintéticos e nao invente dados da VM.
 pause
 exit /b 5
)
python scripts\hunt_correlations.py
if errorlevel 1 (
 echo FALHA: entrada privada invalida ou nao autorizada pelo contrato.
 pause
 exit /b 6
)
echo.
echo Os pares sao CANDIDATOS de triagem, nunca incidentes confirmados.
pause
exit /b 0
