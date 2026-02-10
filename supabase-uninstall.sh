#!/usr/bin/env bash
###############################################################################
#  uninstall-supabase.sh – Remoção completa do Supabase Self-Hosted
#
#  Remove: containers, imagens, volumes Docker, dados do banco,
#          arquivos de configuração e o diretório de instalação.
#
#  Uso: sudo ./uninstall-supabase.sh
#       sudo ./uninstall-supabase.sh --force    (sem confirmações)
###############################################################################

set -euo pipefail

# ─── Cores ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

log()   { echo -e "${GREEN}[✓]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
err()   { echo -e "${RED}[✗]${NC} $*" >&2; }
info()  { echo -e "${BLUE}[i]${NC} $*"; }
header(){ echo -e "\n${CYAN}══════════════════════════════════════════════════════${NC}"; echo -e "${CYAN}  $*${NC}"; echo -e "${CYAN}══════════════════════════════════════════════════════${NC}\n"; }

INSTALL_DIR="${SUPABASE_INSTALL_DIR:-/opt/supabase}"
FORCE=false
REMOVE_IMAGES=false
KEEP_BACKUP=false
BACKUP_DIR=""

# ─── Parsear argumentos ─────────────────────────────────────────────────────
for arg in "$@"; do
    case "$arg" in
        --force|-f)      FORCE=true ;;
        --images|-i)     REMOVE_IMAGES=true ;;
        --backup|-b)     KEEP_BACKUP=true ;;
        --help|-h)
            echo "Uso: $0 [opções]"
            echo ""
            echo "Opções:"
            echo "  --force, -f     Não pedir confirmação"
            echo "  --images, -i    Remover também as imagens Docker do Supabase"
            echo "  --backup, -b    Fazer backup do banco antes de apagar"
            echo "  --help, -h      Mostrar esta ajuda"
            exit 0
            ;;
        *) err "Argumento desconhecido: $arg"; exit 1 ;;
    esac
done

# ─── Verificações ────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    err "Este script precisa ser executado como root (sudo)."
    exit 1
fi

if ! command -v docker &>/dev/null; then
    err "Docker não encontrado."
    exit 1
fi

# Detectar Docker Compose
if docker compose version &>/dev/null 2>&1; then
    COMPOSE_CMD="docker compose"
elif command -v docker-compose &>/dev/null; then
    COMPOSE_CMD="docker-compose"
else
    COMPOSE_CMD=""
fi

# ─── Aviso ───────────────────────────────────────────────────────────────────
header "☢  SUPABASE NUKE – Remoção Completa"

echo -e "${RED}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${RED}║                                                              ║${NC}"
echo -e "${RED}║   ⚠  ATENÇÃO: ESTA AÇÃO É IRREVERSÍVEL!                    ║${NC}"
echo -e "${RED}║                                                              ║${NC}"
echo -e "${RED}║   Serão removidos:                                           ║${NC}"
echo -e "${RED}║   • Todos os containers do Supabase                         ║${NC}"
echo -e "${RED}║   • Todos os dados do PostgreSQL                            ║${NC}"
echo -e "${RED}║   • Todos os arquivos de Storage                            ║${NC}"
echo -e "${RED}║   • Todas as Edge Functions                                  ║${NC}"
echo -e "${RED}║   • Configurações, chaves e credenciais                     ║${NC}"
echo -e "${RED}║   • Diretório: ${INSTALL_DIR}$(printf '%*s' $((35 - ${#INSTALL_DIR})) '')║${NC}"
if [[ "$REMOVE_IMAGES" == true ]]; then
echo -e "${RED}║   • Imagens Docker do Supabase (~5GB)                       ║${NC}"
fi
echo -e "${RED}║                                                              ║${NC}"
echo -e "${RED}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# ─── Mostrar o que existe ────────────────────────────────────────────────────
if [[ -d "$INSTALL_DIR" ]]; then
    info "Diretório encontrado: $INSTALL_DIR"
    DISK_USAGE=$(du -sh "$INSTALL_DIR" 2>/dev/null | awk '{print $1}' || echo "N/A")
    info "Espaço em disco: $DISK_USAGE"
else
    warn "Diretório $INSTALL_DIR não encontrado."
fi

# Contar containers Supabase rodando
RUNNING_CONTAINERS=$(docker ps --filter "name=supabase-" --filter "name=realtime-dev" -q 2>/dev/null | wc -l || echo "0")
info "Containers Supabase rodando: $RUNNING_CONTAINERS"

# ─── Confirmação ─────────────────────────────────────────────────────────────
if [[ "$FORCE" != true ]]; then
    echo ""
    echo -e "${RED}Tem certeza que deseja APAGAR TUDO?${NC}"
    echo ""
    read -rp "$(echo -e "${RED}Digite 'NUKE' para confirmar: ${NC}")" CONFIRM
    if [[ "$CONFIRM" != "NUKE" ]]; then
        info "Operação cancelada."
        exit 0
    fi
    echo ""
fi

# ─── Backup opcional ─────────────────────────────────────────────────────────
if [[ "$KEEP_BACKUP" == true ]]; then
    header "Backup do Banco de Dados"
    BACKUP_DIR="/tmp/supabase-backup-$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$BACKUP_DIR"

    if docker ps -q --filter "name=supabase-db" | grep -q .; then
        info "Fazendo dump do banco de dados..."
        if docker exec supabase-db pg_dumpall -U supabase_admin > "$BACKUP_DIR/full_dump.sql" 2>/dev/null; then
            log "Backup salvo em: $BACKUP_DIR/full_dump.sql"
            DUMP_SIZE=$(du -sh "$BACKUP_DIR/full_dump.sql" | awk '{print $1}')
            info "Tamanho do dump: $DUMP_SIZE"
        else
            warn "Não foi possível fazer backup do banco (container pode não estar saudável)"
        fi
    else
        warn "Container supabase-db não está rodando. Backup ignorado."
    fi

    # Copiar .env e credenciais
    if [[ -f "$INSTALL_DIR/.env" ]]; then
        cp "$INSTALL_DIR/.env" "$BACKUP_DIR/.env"
        log "Arquivo .env copiado para backup"
    fi
    if [[ -f "$INSTALL_DIR/CREDENCIAIS.txt" ]]; then
        cp "$INSTALL_DIR/CREDENCIAIS.txt" "$BACKUP_DIR/CREDENCIAIS.txt"
        log "Arquivo CREDENCIAIS.txt copiado para backup"
    fi

    echo ""
    log "Backup completo em: ${CYAN}${BACKUP_DIR}${NC}"
    echo ""
fi

# ─── FASE 1: Parar e remover containers ─────────────────────────────────────
header "Fase 1/4 – Parando Containers"

if [[ -n "$COMPOSE_CMD" && -f "$INSTALL_DIR/docker-compose.yml" ]]; then
    cd "$INSTALL_DIR"
    info "Parando todos os serviços via Docker Compose..."
    $COMPOSE_CMD down -v --remove-orphans 2>&1 || true
    log "Docker Compose down executado"
else
    info "Docker Compose não disponível ou docker-compose.yml não encontrado."
    info "Removendo containers individualmente..."
fi

# Garantir que todos os containers Supabase foram removidos
SUPABASE_CONTAINERS=$(docker ps -a --filter "name=supabase-" --filter "name=realtime-dev" -q 2>/dev/null || true)
if [[ -n "$SUPABASE_CONTAINERS" ]]; then
    info "Removendo containers restantes..."
    echo "$SUPABASE_CONTAINERS" | xargs -r docker rm -f 2>/dev/null || true
    log "Containers removidos"
else
    log "Nenhum container Supabase restante"
fi

# ─── FASE 2: Remover volumes Docker ─────────────────────────────────────────
header "Fase 2/4 – Removendo Volumes Docker"

# Volumes nomeados do Supabase (criados pelo compose)
SUPABASE_VOLUMES=$(docker volume ls -q --filter "name=supabase" 2>/dev/null || true)
if [[ -n "$SUPABASE_VOLUMES" ]]; then
    info "Removendo volumes Docker nomeados..."
    echo "$SUPABASE_VOLUMES" | xargs -r docker volume rm -f 2>/dev/null || true
    log "Volumes Docker removidos"
else
    log "Nenhum volume Docker nomeado do Supabase encontrado"
fi

# ─── FASE 3: Remover diretório de instalação ────────────────────────────────
header "Fase 3/4 – Removendo Arquivos"

if [[ -d "$INSTALL_DIR" ]]; then
    info "Removendo diretório: $INSTALL_DIR"

    # Listar o que vai ser removido
    ITEMS=$(find "$INSTALL_DIR" -maxdepth 1 -mindepth 1 | wc -l)
    info "Itens no diretório: $ITEMS"

    # Remover tudo
    rm -rf "$INSTALL_DIR"

    if [[ ! -d "$INSTALL_DIR" ]]; then
        log "Diretório $INSTALL_DIR removido com sucesso"
    else
        err "Falha ao remover $INSTALL_DIR (verifique permissões)"
    fi
else
    log "Diretório $INSTALL_DIR já não existe"
fi

# ─── FASE 4: Remover imagens Docker (opcional) ──────────────────────────────
header "Fase 4/4 – Limpeza de Imagens"

if [[ "$REMOVE_IMAGES" == true ]]; then
    info "Removendo imagens Docker do Supabase..."

    SUPABASE_IMAGES=$(docker images --format '{{.Repository}}:{{.Tag}} {{.ID}}' 2>/dev/null | \
        grep -E "supabase/|postgrest/|kong:|timberio/vector|darthsim/imgproxy" | \
        awk '{print $2}' | sort -u || true)

    if [[ -n "$SUPABASE_IMAGES" ]]; then
        COUNT=$(echo "$SUPABASE_IMAGES" | wc -l)
        info "Encontradas $COUNT imagens para remover..."
        echo "$SUPABASE_IMAGES" | xargs -r docker rmi -f 2>/dev/null || true
        log "$COUNT imagens removidas"
    else
        log "Nenhuma imagem do Supabase encontrada"
    fi
else
    SUPABASE_IMAGES=$(docker images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | \
        grep -E "supabase/|postgrest/|kong:|timberio/vector|darthsim/imgproxy" | wc -l || echo "0")
    if [[ "$SUPABASE_IMAGES" -gt 0 ]]; then
        info "$SUPABASE_IMAGES imagens Docker do Supabase mantidas (use --images para remover)"
    fi
fi

# ─── Remover rede Docker ────────────────────────────────────────────────────
SUPABASE_NETWORKS=$(docker network ls -q --filter "name=supabase" 2>/dev/null || true)
if [[ -n "$SUPABASE_NETWORKS" ]]; then
    info "Removendo redes Docker do Supabase..."
    echo "$SUPABASE_NETWORKS" | xargs -r docker network rm 2>/dev/null || true
    log "Redes removidas"
fi

# ─── Limpar Docker (dangling) ───────────────────────────────────────────────
info "Limpando recursos Docker órfãos..."
docker system prune -f --volumes 2>/dev/null | tail -2 || true

# ─── Resumo Final ────────────────────────────────────────────────────────────
header "Remoção Concluída"

echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║          Supabase removido completamente! 🗑️              ║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║${NC}                                                            ${GREEN}║${NC}"
echo -e "${GREEN}║${NC}  ${CYAN}Removidos:${NC}                                               ${GREEN}║${NC}"
echo -e "${GREEN}║${NC}    ✓ Containers e serviços                                 ${GREEN}║${NC}"
echo -e "${GREEN}║${NC}    ✓ Dados do PostgreSQL                                   ${GREEN}║${NC}"
echo -e "${GREEN}║${NC}    ✓ Arquivos de Storage                                   ${GREEN}║${NC}"
echo -e "${GREEN}║${NC}    ✓ Configurações e credenciais                           ${GREEN}║${NC}"
echo -e "${GREEN}║${NC}    ✓ Volumes Docker                                        ${GREEN}║${NC}"
if [[ "$REMOVE_IMAGES" == true ]]; then
echo -e "${GREEN}║${NC}    ✓ Imagens Docker                                        ${GREEN}║${NC}"
else
echo -e "${GREEN}║${NC}    ○ Imagens Docker mantidas                               ${GREEN}║${NC}"
fi
echo -e "${GREEN}║${NC}                                                            ${GREEN}║${NC}"
if [[ -n "$BACKUP_DIR" && -d "$BACKUP_DIR" ]]; then
echo -e "${GREEN}║${NC}  ${YELLOW}Backup salvo em:${NC}                                         ${GREEN}║${NC}"
echo -e "${GREEN}║${NC}  ${CYAN}${BACKUP_DIR}${NC}"
echo -e "${GREEN}║${NC}                                                            ${GREEN}║${NC}"
fi
echo -e "${GREEN}║${NC}  Para reinstalar:                                          ${GREEN}║${NC}"
echo -e "${GREEN}║${NC}  ${CYAN}sudo ./install-supabase.sh${NC}                                ${GREEN}║${NC}"
echo -e "${GREEN}║${NC}                                                            ${GREEN}║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
