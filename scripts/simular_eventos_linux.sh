#!/usr/bin/env bash
# Simulação segura para um agente Linux do laboratório Wazuh.
# Executar com sudo: sudo bash simular_eventos_linux.sh
set -euo pipefail

LOG_DIR="/var/log/wazuh-lab"
LOG_FILE="$LOG_DIR/events.log"
FIM_DIR="/opt/wazuh-lab/monitorado"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Execute como root: sudo bash simular_eventos_linux.sh" >&2
  exit 1
fi

install -d -m 0755 "$LOG_DIR" "$FIM_DIR"
touch "$LOG_FILE"
chmod 0644 "$LOG_FILE"

emit() {
  printf '%s %s wazuh-lab: %s\n' "$(date '+%b %e %T')" "$(hostname -s)" "$1" >> "$LOG_FILE"
}

echo "[1/5] Gravando falhas de autenticação simuladas..."
emit 'LAB_BRUTE_FORCE user=analista origem=TEST-NET-24 tentativas=8 janela=60s'

echo "[2/5] Gravando execução suspeita simulada..."
emit 'LAB_SUSPICIOUS_COMMAND user=analista comando="curl -I https://example.invalid" processo=bash'

echo "[3/5] Criando alteração para File Integrity Monitoring..."
printf 'baseline=ativa\nultima_alteracao=%s\n' "$(date -Is)" > "$FIM_DIR/configuracao.conf"
# A segunda escrita garante uma mudança após a criação inicial em execuções repetidas.
printf 'revisado_por=simulador-lab\n' >> "$FIM_DIR/configuracao.conf"

echo "[4/5] Gravando possível exfiltração simulada..."
emit 'LAB_DATA_EXFIL destino=TEST-NET-80 volume=350MB protocolo=HTTPS classificacao=simulada'

echo "[5/5] Gravando elevação de privilégio simulada..."
emit 'LAB_PRIVILEGE_ESCALATION usuario=analista acao=sudo contexto=simulacao_autorizada'

echo "Concluído. Aguarde alguns segundos e filtre o Dashboard por rule.groups: lab."
