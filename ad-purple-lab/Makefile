# ============================================================
# AD Purple Lab - Makefile
# Uso: make <target>
# ============================================================

.PHONY: init up down restart logs ps shell audit export health \
        build pull clean neo4j-shell validate \
        detect wazuh dashboards lab-health \
        panel panel-build panel-up panel-down

COMPOSE := docker compose
KALI_CONTAINER := kali-audit

# ── Colores ───────────────────────────────────────────────────
GREEN  := \033[0;32m
YELLOW := \033[1;33m
BLUE   := \033[0;34m
NC     := \033[0m

## init: Inicializar proyecto (crear .env, directorios, verificar dependencias)
init:
	@echo "$(GREEN)Inicializando AD Purple Lab...$(NC)"
	@bash scripts/init.sh

## up: Levantar todos los servicios
up:
	@echo "$(GREEN)Levantando servicios...$(NC)"
	@$(COMPOSE) up -d
	@echo ""
	@echo "$(GREEN)Servicios disponibles:$(NC)"
	@echo "  Neo4j Browser:         http://localhost:7474"
	@echo "  OpenSearch Dashboards: http://localhost:5601"
	@echo "  Grafana:               http://localhost:3000"
	@echo "  OpenSearch API:        http://localhost:9200"

## down: Detener todos los servicios (preserva volúmenes)
down:
	@echo "$(YELLOW)Deteniendo servicios...$(NC)"
	@$(COMPOSE) down

## restart: Reiniciar todos los servicios
restart:
	@echo "$(YELLOW)Reiniciando servicios...$(NC)"
	@$(COMPOSE) restart

## logs: Ver logs en tiempo real de todos los servicios
logs:
	@$(COMPOSE) logs -f --tail=50

## logs-kali: Ver logs del contenedor kali-audit
logs-kali:
	@$(COMPOSE) logs -f --tail=100 kali-audit

## logs-neo4j: Ver logs de Neo4j
logs-neo4j:
	@$(COMPOSE) logs -f --tail=50 neo4j

## ps: Estado de los contenedores
ps:
	@$(COMPOSE) ps

## build: Construir imágenes locales (kali, zeek)
build:
	@echo "$(GREEN)Construyendo imágenes...$(NC)"
	@$(COMPOSE) build --no-cache

## pull: Descargar imágenes remotas
pull:
	@$(COMPOSE) pull

## shell: Abrir shell interactivo en el contenedor kali-audit
shell:
	@echo "$(GREEN)Abriendo shell en $(KALI_CONTAINER)...$(NC)"
	@docker exec -it $(KALI_CONTAINER) /bin/bash

## audit: Ejecutar auditoría segura completa desde kali-audit
audit:
	@echo "$(GREEN)Iniciando auditoría segura...$(NC)"
	@docker exec -it $(KALI_CONTAINER) bash /workspace/scripts/safe-audit.sh

## validate: Validar variables de entorno
validate:
	@docker exec -it $(KALI_CONTAINER) bash /workspace/scripts/validate-env.sh

## dns-check: Ejecutar solo verificación DNS
dns-check:
	@docker exec -it $(KALI_CONTAINER) bash /workspace/scripts/dns-check.sh

## ldap-check: Ejecutar solo verificación LDAP
ldap-check:
	@docker exec -it $(KALI_CONTAINER) bash /workspace/scripts/ldap-check.sh

## bloodhound: Ejecutar solo colección BloodHound
bloodhound:
	@docker exec -it $(KALI_CONTAINER) bash /workspace/scripts/bloodhound-collect.sh

## export: Empaquetar logs y reportes en tar.gz
export:
	@echo "$(GREEN)Exportando logs y reportes...$(NC)"
	@bash scripts/export-logs.sh

## health: Mostrar resumen de salud del stack
health:
	@bash scripts/health-summary.sh

## neo4j-shell: Abrir cypher-shell en Neo4j
neo4j-shell:
	@docker exec -it neo4j cypher-shell -u neo4j

## clean: Detener servicios y eliminar volúmenes (DESTRUCTIVO)
clean:
	@echo "$(YELLOW)ADVERTENCIA: Esto eliminará todos los volúmenes de datos.$(NC)"
	@read -p "¿Confirmar? [y/N]: " confirm && [ "$$confirm" = "y" ]
	@$(COMPOSE) down -v
	@echo "Volúmenes eliminados."

## clean-reports: Limpiar directorio de reportes
clean-reports:
	@echo "$(YELLOW)Eliminando reportes...$(NC)"
	@find ./reports -type f -delete 2>/dev/null || true
	@echo "Reportes eliminados."

## detect: Mostrar últimas alertas de Suricata y notices de Zeek
detect:
	@echo "$(BLUE)── Suricata fast.log (últimas 20) ──$(NC)"
	@tail -20 ./logs/suricata/fast.log 2>/dev/null || echo "  (sin alertas aún)"
	@echo ""
	@echo "$(BLUE)── Zeek notice.log (últimas 10) ──$(NC)"
	@tail -10 ./logs/zeek/notice.log 2>/dev/null || echo "  (sin notices aún)"
	@echo ""
	@echo "$(BLUE)── Zeek ad_activity.log (últimas 10) ──$(NC)"
	@tail -10 ./logs/zeek/ad_activity.log 2>/dev/null || echo "  (sin eventos AD aún)"

## wazuh: Levantar Wazuh Manager (requiere wazuh/docker-compose.override.yml)
wazuh:
	@echo "$(GREEN)Levantando Wazuh Manager...$(NC)"
	@$(COMPOSE) -f docker-compose.yml -f wazuh/docker-compose.override.yml up -d wazuh-manager
	@echo "$(GREEN)Wazuh Manager iniciado.$(NC)"
	@echo "  API:              http://localhost:55000"
	@echo "  Puerto agentes:   1514/tcp+udp"
	@echo "  Puerto enrollment: 1515/tcp"
	@echo "  Ver wazuh/README.md para instalar agente en el DC"

## wazuh-status: Estado de Wazuh y agentes conectados
wazuh-status:
	@echo "$(BLUE)Estado de Wazuh Manager:$(NC)"
	@docker exec wazuh-manager /var/ossec/bin/wazuh-control status 2>/dev/null || echo "  (wazuh-manager no está corriendo)"
	@echo ""
	@echo "$(BLUE)Agentes conectados:$(NC)"
	@docker exec wazuh-manager /var/ossec/bin/agent_control -lc 2>/dev/null || echo "  (sin agentes)"

## dashboards: Abrir todas las UIs en el navegador (Linux/macOS)
dashboards:
	@echo "$(GREEN)Abriendo dashboards...$(NC)"
	@command -v xdg-open &>/dev/null && xdg-open http://localhost:3000 || true
	@command -v open &>/dev/null && open http://localhost:3000 || true
	@echo "  Grafana:               http://localhost:3000  (admin/admin)"
	@echo "  OpenSearch Dashboards: http://localhost:5601"
	@echo "  Neo4j Browser:         http://localhost:7474"

## lab-health: Dashboard completo de salud del laboratorio
lab-health:
	@bash scripts/lab-health.sh

## panel: Levantar el SOC Admin Panel (panel-api + panel-ui)
panel: panel-up

## panel-build: Construir imágenes del panel (backend + frontend)
panel-build:
	@echo "$(GREEN)Construyendo imágenes del panel...$(NC)"
	@$(COMPOSE) build panel-api panel-ui

## panel-up: Iniciar panel-api y panel-ui en background
panel-up:
	@echo "$(GREEN)Iniciando SOC Admin Panel...$(NC)"
	@$(COMPOSE) up -d panel-api panel-ui
	@echo ""
	@echo "$(GREEN)Panel disponible:$(NC)"
	@echo "  SOC Panel UI:  http://localhost:3002"
	@echo "  Panel API:     http://localhost:8080"
	@echo "  API Health:    http://localhost:8080/health"

## panel-down: Detener panel-api y panel-ui
panel-down:
	@echo "$(YELLOW)Deteniendo SOC Admin Panel...$(NC)"
	@$(COMPOSE) stop panel-api panel-ui

## panel-logs: Ver logs del panel en tiempo real
panel-logs:
	@$(COMPOSE) logs -f --tail=50 panel-api panel-ui

## help: Mostrar esta ayuda
help:
	@echo "AD Purple Lab - Targets disponibles:"
	@echo ""
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## /  make /' | column -t -s ':'
