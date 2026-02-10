#!/usr/bin/env bash
###############################################################################
#  install-supabase.sh – Instalação completa e automatizada do Supabase
#  Self-Hosted com Docker Compose (Ubuntu)
#
#  • Gera TODAS as chaves/secrets automaticamente (JWT, ANON, SERVICE_ROLE, etc.)
#  • Permite escolher modo de acesso: localhost, rede interna, IP externo, domínio ou proxy reverso
#  • Resultado: Supabase rodando e pronto para uso
#
#  Requisitos: Ubuntu com Docker e Docker Compose já instalados
#  Uso: chmod +x install-supabase.sh && sudo ./install-supabase.sh
#
#  Variáveis de ambiente para automação (sem interação):
#    SUPABASE_ACCESS_MODE=1|2|3|4|5
#    SUPABASE_DOMAIN=meudominio.com         (modo 4)
#    SUPABASE_PUBLIC_DOMAIN=supa.empresa.com (modo 5 - proxy reverso)
#    SUPABASE_PUBLIC_PROTOCOL=https          (modo 5)
#    SUPABASE_PUBLIC_API_PORT=               (modo 5, vazio=padrão do protocolo)
#    SUPABASE_PUBLIC_STUDIO_PORT=            (modo 5, vazio=padrão)
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

# ─── Configurações ───────────────────────────────────────────────────────────
INSTALL_DIR="${SUPABASE_INSTALL_DIR:-/opt/supabase}"
STUDIO_PORT="${SUPABASE_STUDIO_PORT:-3000}"
API_PORT="${SUPABASE_API_PORT:-8000}"
DASHBOARD_USERNAME="${SUPABASE_DASHBOARD_USER:-supabase}"
DASHBOARD_PASSWORD="${SUPABASE_DASHBOARD_PASS:-}"
# Modo de acesso pode ser pré-definido via variável de ambiente:
#   SUPABASE_ACCESS_MODE=1  (interno/localhost)
#   SUPABASE_ACCESS_MODE=2  (rede interna/IP privado)
#   SUPABASE_ACCESS_MODE=3  (externo/IP público)
#   SUPABASE_ACCESS_MODE=4  (domínio customizado)
#   SUPABASE_ACCESS_MODE=5  (proxy reverso / load balancer)
ACCESS_MODE="${SUPABASE_ACCESS_MODE:-}"
CUSTOM_DOMAIN="${SUPABASE_DOMAIN:-}"

# ─── Verificações ────────────────────────────────────────────────────────────
header "Supabase Self-Hosted – Instalação Automatizada"

# Verificar se é root ou tem sudo
if [[ $EUID -ne 0 ]]; then
    err "Este script precisa ser executado como root (sudo)."
    exit 1
fi

# Verificar Ubuntu
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    if [[ "$ID" != "ubuntu" ]]; then
        warn "Este script foi projetado para Ubuntu. Distro detectada: $ID"
        warn "Prosseguindo mesmo assim..."
    fi
    info "Sistema: $PRETTY_NAME"
else
    warn "Não foi possível detectar o sistema operacional."
fi

# Verificar Docker
if ! command -v docker &>/dev/null; then
    err "Docker não encontrado. Instale o Docker antes de executar este script."
    err "  curl -fsSL https://get.docker.com | sh"
    exit 1
fi
log "Docker encontrado: $(docker --version)"

# Verificar Docker Compose
if docker compose version &>/dev/null 2>&1; then
    COMPOSE_CMD="docker compose"
    log "Docker Compose (plugin): $(docker compose version --short)"
elif command -v docker-compose &>/dev/null; then
    COMPOSE_CMD="docker-compose"
    log "Docker Compose (standalone): $(docker-compose --version)"
else
    err "Docker Compose não encontrado. Instale com:"
    err "  sudo apt install -y docker-compose-plugin"
    exit 1
fi

# Verificar se Docker está rodando
if ! docker info &>/dev/null 2>&1; then
    warn "Docker daemon não está rodando. Iniciando..."
    systemctl start docker
    systemctl enable docker
    sleep 2
fi

# Instalar dependências necessárias
info "Verificando dependências..."
apt-get update -qq
apt-get install -y -qq git openssl jq curl > /dev/null 2>&1
log "Dependências instaladas (git, openssl, jq, curl)"

# ─── Funções de Geração de Secrets ──────────────────────────────────────────

generate_password() {
    # Gera senha alfanumérica segura de N caracteres (padrão 32)
    local length="${1:-32}"
    openssl rand -base64 "$((length * 3 / 4 + 1))" | tr -dc 'A-Za-z0-9' | head -c "$length"
}

generate_hex() {
    # Gera string hexadecimal de N bytes (padrão 32)
    local bytes="${1:-32}"
    openssl rand -hex "$bytes"
}

generate_jwt() {
    # Gera JWT assinado com HS256 (compatível com Supabase)
    local secret="$1"
    local role="$2"
    local iss="${3:-supabase}"

    # Header: {"alg":"HS256","typ":"JWT"}
    local header
    header=$(echo -n '{"alg":"HS256","typ":"JWT"}' | openssl base64 -e -A | tr '+/' '-_' | tr -d '=')

    # Payload com expiração em 5 anos
    local exp
    exp=$(date -d "+5 years" +%s 2>/dev/null || date -v+5y +%s 2>/dev/null || echo $(($(date +%s) + 157680000)))

    local iat
    iat=$(date +%s)

    local payload_json="{\"role\":\"${role}\",\"iss\":\"${iss}\",\"iat\":${iat},\"exp\":${exp}}"
    local payload
    payload=$(echo -n "$payload_json" | openssl base64 -e -A | tr '+/' '-_' | tr -d '=')

    # Signature
    local signature
    signature=$(echo -n "${header}.${payload}" | openssl dgst -sha256 -hmac "$secret" -binary | openssl base64 -e -A | tr '+/' '-_' | tr -d '=')

    echo "${header}.${payload}.${signature}"
}

# ─── Gerar todos os secrets ──────────────────────────────────────────────────
header "Gerando Secrets e Chaves"

# Secrets principais
POSTGRES_PASSWORD=$(generate_password 40)
JWT_SECRET=$(generate_hex 32)
SECRET_KEY_BASE=$(openssl rand -base64 48)
VAULT_ENC_KEY=$(openssl rand -hex 16)

# Dashboard
if [[ -z "$DASHBOARD_PASSWORD" ]]; then
    DASHBOARD_PASSWORD=$(generate_password 24)
fi

# JWT keys
ANON_KEY=$(generate_jwt "$JWT_SECRET" "anon" "supabase")
SERVICE_ROLE_KEY=$(generate_jwt "$JWT_SECRET" "service_role" "supabase")

# Logflare / Analytics
LOGFLARE_API_KEY=$(generate_password 48)
LOGFLARE_PUBLIC_ACCESS_TOKEN=$(generate_password 48)
LOGFLARE_PRIVATE_ACCESS_TOKEN=$(generate_password 48)

# Postgres Meta
PG_META_CRYPTO_KEY=$(openssl rand -base64 24)

# Pooler tenant
POOLER_TENANT_ID="supabase-$(generate_password 8 | tr '[:upper:]' '[:lower:]')"

log "POSTGRES_PASSWORD gerado"
log "JWT_SECRET gerado"
log "ANON_KEY (JWT) gerado"
log "SERVICE_ROLE_KEY (JWT) gerado"
log "SECRET_KEY_BASE gerado"
log "VAULT_ENC_KEY gerado"
log "LOGFLARE tokens gerados"
log "PG_META_CRYPTO_KEY gerado"
log "DASHBOARD_PASSWORD gerado"

# ─── Clonar repositório do Supabase ─────────────────────────────────────────
header "Baixando Supabase"

if [[ -d "$INSTALL_DIR" ]]; then
    warn "Diretório $INSTALL_DIR já existe."
    if [[ -f "$INSTALL_DIR/docker-compose.yml" ]]; then
        warn "Parando containers existentes..."
        cd "$INSTALL_DIR"
        $COMPOSE_CMD down 2>/dev/null || true
    fi
    # Backup do .env existente
    if [[ -f "$INSTALL_DIR/.env" ]]; then
        cp "$INSTALL_DIR/.env" "$INSTALL_DIR/.env.backup.$(date +%Y%m%d%H%M%S)"
        log "Backup do .env existente criado"
    fi
fi

# Clonar ou atualizar
TEMP_DIR=$(mktemp -d)
info "Clonando repositório oficial do Supabase..."
git clone --depth 1 https://github.com/supabase/supabase "$TEMP_DIR/supabase" 2>/dev/null

# Criar diretório de instalação e copiar arquivos do docker
mkdir -p "$INSTALL_DIR"
cp -rf "$TEMP_DIR/supabase/docker/"* "$INSTALL_DIR/"
# Copiar arquivos ocultos (como .env.example)
cp -rf "$TEMP_DIR/supabase/docker/".* "$INSTALL_DIR/" 2>/dev/null || true

# Limpar temp
rm -rf "$TEMP_DIR"
log "Arquivos do Supabase copiados para $INSTALL_DIR"

cd "$INSTALL_DIR"

# ─── Criar arquivo .env ─────────────────────────────────────────────────────
header "Configurando Variáveis de Ambiente"

# ─── Detecção de Rede ────────────────────────────────────────────────────────
header "Configuração de Rede"

# Detectar IPs disponíveis
info "Detectando interfaces de rede..."

# IP privado (rede interna)
INTERNAL_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "")
if [[ -n "$INTERNAL_IP" ]]; then
    log "IP interno (rede local): ${CYAN}${INTERNAL_IP}${NC}"
else
    warn "Não foi possível detectar IP interno"
    INTERNAL_IP="127.0.0.1"
fi

# IP público (externo)
EXTERNAL_IP=$(curl -s -4 --max-time 5 ifconfig.me 2>/dev/null || curl -s -4 --max-time 5 icanhazip.com 2>/dev/null || echo "")
if [[ -n "$EXTERNAL_IP" ]]; then
    log "IP externo (internet):   ${CYAN}${EXTERNAL_IP}${NC}"
else
    warn "Não foi possível detectar IP externo (sem acesso à internet?)"
fi

echo ""

# Variáveis que serão definidas pela escolha:
#   SUPABASE_BIND_HOST  = IP onde o Docker faz bind (onde os containers escutam)
#   SUPABASE_PUBLIC_HOST = hostname/IP/domínio que o usuário final acessa
#   PUBLIC_PROTOCOL      = http ou https
#   PUBLIC_API_PORT      = porta da API na URL pública (pode ser diferente da interna)
#   PUBLIC_STUDIO_PORT   = porta do Studio na URL pública
#   IS_BEHIND_PROXY      = true/false
SUPABASE_BIND_HOST=""
SUPABASE_PUBLIC_HOST=""
PUBLIC_PROTOCOL="http"
PUBLIC_API_PORT="$API_PORT"
PUBLIC_STUDIO_PORT="$STUDIO_PORT"
IS_BEHIND_PROXY=false

# Se o modo não foi pré-definido via env e também não foi passado domínio customizado
if [[ -z "$ACCESS_MODE" && -z "$CUSTOM_DOMAIN" ]]; then
    echo -e "${CYAN}Como o Supabase será acessado?${NC}"
    echo ""
    echo -e "  ${GREEN}1)${NC} ${YELLOW}Localhost${NC}           – Apenas nesta máquina (127.0.0.1)"
    if [[ -n "$INTERNAL_IP" && "$INTERNAL_IP" != "127.0.0.1" ]]; then
        echo -e "  ${GREEN}2)${NC} ${YELLOW}Rede Interna${NC}       – Acessível na LAN via ${CYAN}${INTERNAL_IP}${NC}"
    fi
    if [[ -n "$EXTERNAL_IP" ]]; then
        echo -e "  ${GREEN}3)${NC} ${YELLOW}IP Externo${NC}         – Acessível pela internet via ${CYAN}${EXTERNAL_IP}${NC}"
    fi
    echo -e "  ${GREEN}4)${NC} ${YELLOW}Domínio/IP${NC}         – Informar manualmente um domínio ou IP"
    echo -e "  ${GREEN}5)${NC} ${YELLOW}Proxy Reverso / LB${NC} – Atrás de Nginx, Caddy, HAProxy, Traefik, etc."
    echo ""
    
    while true; do
        read -rp "$(echo -e "${BLUE}Escolha [1-5]:${NC} ")" ACCESS_MODE
        case "$ACCESS_MODE" in
            1) break ;;
            2) 
                if [[ -n "$INTERNAL_IP" && "$INTERNAL_IP" != "127.0.0.1" ]]; then
                    break
                else
                    err "Opção indisponível (IP interno não detectado)"
                fi
                ;;
            3)
                if [[ -n "$EXTERNAL_IP" ]]; then
                    break
                else
                    err "Opção indisponível (IP externo não detectado)"
                fi
                ;;
            4|5) break ;;
            *) err "Opção inválida. Digite 1, 2, 3, 4 ou 5." ;;
        esac
    done
fi

# ─── Configuração do Proxy Reverso (Modo 5) ─────────────────────────────────
configure_proxy_mode() {
    IS_BEHIND_PROXY=true

    echo ""
    echo -e "${CYAN}┌─────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│  Configuração para Proxy Reverso / Load Balancer           │${NC}"
    echo -e "${CYAN}│                                                             │${NC}"
    echo -e "${CYAN}│  O proxy/LB recebe as requisições externas e encaminha     │${NC}"
    echo -e "${CYAN}│  para esta máquina. O Supabase vai escutar internamente    │${NC}"
    echo -e "${CYAN}│  e as URLs públicas serão as do proxy.                     │${NC}"
    echo -e "${CYAN}│                                                             │${NC}"
    echo -e "${CYAN}│  Exemplo:                                                   │${NC}"
    echo -e "${CYAN}│   Usuário → https://supa.empresa.com → Proxy → :8000      │${NC}"
    echo -e "${CYAN}└─────────────────────────────────────────────────────────────┘${NC}"
    echo ""

    # URL pública (domínio ou IP do proxy/LB)
    if [[ -z "${SUPABASE_PUBLIC_DOMAIN:-}" ]]; then
        read -rp "$(echo -e "${BLUE}Domínio ou IP público (ex: supa.empresa.com):${NC} ")" SUPABASE_PUBLIC_DOMAIN
    fi
    SUPABASE_PUBLIC_HOST="$SUPABASE_PUBLIC_DOMAIN"

    # Protocolo
    if [[ -z "${SUPABASE_PUBLIC_PROTOCOL:-}" ]]; then
        echo ""
        echo -e "  ${GREEN}1)${NC} ${YELLOW}https${NC} (recomendado para produção)"
        echo -e "  ${GREEN}2)${NC} ${YELLOW}http${NC}"
        read -rp "$(echo -e "${BLUE}Protocolo [1-2] (padrão: 1):${NC} ")" proto_choice
        case "${proto_choice:-1}" in
            2) PUBLIC_PROTOCOL="http" ;;
            *) PUBLIC_PROTOCOL="https" ;;
        esac
    else
        PUBLIC_PROTOCOL="$SUPABASE_PUBLIC_PROTOCOL"
    fi

    # Porta pública da API (o proxy pode mapear 443→8000, então externamente não tem porta)
    if [[ -z "${SUPABASE_PUBLIC_API_PORT:-}" ]]; then
        echo ""
        if [[ "$PUBLIC_PROTOCOL" == "https" ]]; then
            info "Com HTTPS, geralmente a porta padrão (443) é usada e não precisa aparecer na URL."
        fi
        read -rp "$(echo -e "${BLUE}Porta pública da API (vazio = porta padrão do protocolo):${NC} ")" pub_api_port
        if [[ -n "$pub_api_port" ]]; then
            PUBLIC_API_PORT="$pub_api_port"
        else
            PUBLIC_API_PORT=""
        fi
    else
        PUBLIC_API_PORT="$SUPABASE_PUBLIC_API_PORT"
    fi

    # Porta pública do Studio
    if [[ -z "${SUPABASE_PUBLIC_STUDIO_PORT:-}" ]]; then
        read -rp "$(echo -e "${BLUE}Porta pública do Studio (vazio = mesma da API / porta padrão):${NC} ")" pub_studio_port
        if [[ -n "$pub_studio_port" ]]; then
            PUBLIC_STUDIO_PORT="$pub_studio_port"
        else
            PUBLIC_STUDIO_PORT=""
        fi
    else
        PUBLIC_STUDIO_PORT="$SUPABASE_PUBLIC_STUDIO_PORT"
    fi

    # Bind: onde o Docker escuta nesta máquina
    echo ""
    echo -e "${CYAN}Onde o Docker deve escutar (bind) nesta máquina?${NC}"
    echo -e "  ${GREEN}1)${NC} ${YELLOW}127.0.0.1${NC}        – Somente localhost (proxy na mesma máquina)"
    echo -e "  ${GREEN}2)${NC} ${YELLOW}${INTERNAL_IP}${NC}  – IP interno (proxy em outra máquina na LAN)"
    echo -e "  ${GREEN}3)${NC} ${YELLOW}0.0.0.0${NC}          – Todas as interfaces"
    read -rp "$(echo -e "${BLUE}Bind [1-3] (padrão: 2):${NC} ")" bind_choice
    case "${bind_choice:-2}" in
        1) SUPABASE_BIND_HOST="127.0.0.1" ;;
        3) SUPABASE_BIND_HOST="0.0.0.0" ;;
        *) SUPABASE_BIND_HOST="$INTERNAL_IP" ;;
    esac
}

# ─── Resolver hostname/IP baseado na escolha ────────────────────────────────
case "$ACCESS_MODE" in
    1)
        SUPABASE_BIND_HOST="127.0.0.1"
        SUPABASE_PUBLIC_HOST="localhost"
        BIND_DESCRIPTION="Localhost (apenas local)"
        ;;
    2)
        SUPABASE_BIND_HOST="$INTERNAL_IP"
        SUPABASE_PUBLIC_HOST="$INTERNAL_IP"
        BIND_DESCRIPTION="Rede Interna ($INTERNAL_IP)"
        ;;
    3)
        SUPABASE_BIND_HOST="0.0.0.0"
        SUPABASE_PUBLIC_HOST="$EXTERNAL_IP"
        BIND_DESCRIPTION="IP Externo ($EXTERNAL_IP)"
        ;;
    4)
        if [[ -z "$CUSTOM_DOMAIN" ]]; then
            read -rp "$(echo -e "${BLUE}Informe o domínio ou IP:${NC} ")" CUSTOM_DOMAIN
        fi
        SUPABASE_BIND_HOST="0.0.0.0"
        SUPABASE_PUBLIC_HOST="$CUSTOM_DOMAIN"
        BIND_DESCRIPTION="Customizado ($CUSTOM_DOMAIN)"
        ;;
    5)
        configure_proxy_mode
        BIND_DESCRIPTION="Proxy Reverso → ${PUBLIC_PROTOCOL}://${SUPABASE_PUBLIC_HOST}"
        ;;
    *)
        if [[ -n "$CUSTOM_DOMAIN" ]]; then
            SUPABASE_BIND_HOST="0.0.0.0"
            SUPABASE_PUBLIC_HOST="$CUSTOM_DOMAIN"
            BIND_DESCRIPTION="Customizado ($CUSTOM_DOMAIN)"
        else
            SUPABASE_BIND_HOST="127.0.0.1"
            SUPABASE_PUBLIC_HOST="localhost"
            BIND_DESCRIPTION="Localhost (padrão)"
        fi
        ;;
esac

# Montar URLs públicas
# Para proxy reverso, a porta pode ser omitida se for padrão do protocolo
build_url() {
    local protocol="$1"
    local host="$2"
    local port="$3"
    if [[ -z "$port" ]] || \
       { [[ "$protocol" == "https" ]] && [[ "$port" == "443" ]]; } || \
       { [[ "$protocol" == "http" ]] && [[ "$port" == "80" ]]; }; then
        echo "${protocol}://${host}"
    else
        echo "${protocol}://${host}:${port}"
    fi
}

API_EXTERNAL_URL=$(build_url "$PUBLIC_PROTOCOL" "$SUPABASE_PUBLIC_HOST" "$PUBLIC_API_PORT")
SUPABASE_PUBLIC_URL=$(build_url "$PUBLIC_PROTOCOL" "$SUPABASE_PUBLIC_HOST" "$PUBLIC_API_PORT")

# Studio URL: se for proxy, pode ter porta separada ou ser path-based
if [[ -n "$PUBLIC_STUDIO_PORT" ]]; then
    SITE_URL=$(build_url "$PUBLIC_PROTOCOL" "$SUPABASE_PUBLIC_HOST" "$PUBLIC_STUDIO_PORT")
else
    # Sem porta específica, usa a mesma base do API (proxy pode rotear por path/subdomínio)
    SITE_URL=$(build_url "$PUBLIC_PROTOCOL" "$SUPABASE_PUBLIC_HOST" "$PUBLIC_API_PORT")
fi

# Para compatibilidade com o resto do script, SUPABASE_HOST aponta para o host público
SUPABASE_HOST="$SUPABASE_PUBLIC_HOST"

echo ""
log "Modo selecionado: ${CYAN}${BIND_DESCRIPTION}${NC}"
if [[ "$IS_BEHIND_PROXY" == true ]]; then
    info "Bind:    ${CYAN}${SUPABASE_BIND_HOST}:${API_PORT}${NC} (interno)"
    info "API:     ${CYAN}${API_EXTERNAL_URL}${NC} (público)"
    info "Studio:  ${CYAN}${SITE_URL}${NC} (público)"
else
    info "Studio:  ${CYAN}${SITE_URL}${NC}"
    info "API:     ${CYAN}${API_EXTERNAL_URL}${NC}"
fi
echo ""

# Detectar Docker socket
DOCKER_SOCKET="/var/run/docker.sock"
if [[ ! -S "$DOCKER_SOCKET" ]]; then
    # Rootless docker
    DOCKER_SOCKET="/run/user/$(id -u)/docker.sock"
fi

cat > "$INSTALL_DIR/.env" << ENVFILE
############
# Secrets
# GERADO AUTOMATICAMENTE em $(date '+%Y-%m-%d %H:%M:%S')
# MODO: ${BIND_DESCRIPTION}
# GUARDE ESTAS INFORMAÇÕES EM LOCAL SEGURO!
############

POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
JWT_SECRET=${JWT_SECRET}
ANON_KEY=${ANON_KEY}
SERVICE_ROLE_KEY=${SERVICE_ROLE_KEY}
DASHBOARD_USERNAME=${DASHBOARD_USERNAME}
DASHBOARD_PASSWORD=${DASHBOARD_PASSWORD}
SECRET_KEY_BASE=${SECRET_KEY_BASE}
VAULT_ENC_KEY=${VAULT_ENC_KEY}

############
# Rede
# BIND_HOST: onde o Docker escuta (interno)
# URLs: como o mundo externo acessa (público)
############
# BIND_HOST=${SUPABASE_BIND_HOST}
# PUBLIC_HOST=${SUPABASE_PUBLIC_HOST}
# IS_BEHIND_PROXY=${IS_BEHIND_PROXY}

############
# Database - Supavisor (Pooler)
############
POSTGRES_HOST=db
POSTGRES_DB=postgres
POSTGRES_PORT=5432
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
# default pool size is 20
POOL_SIZE=20
POOLER_PROXY_PORT_TRANSACTION=6543
POOLER_DEFAULT_POOL_SIZE=20
POOLER_MAX_CLIENT_CONN=100
POOLER_TENANT_ID=${POOLER_TENANT_ID}
POOLER_DB_POOL_SIZE=10

############
# Postgres Meta
############
PG_META_CRYPTO_KEY=${PG_META_CRYPTO_KEY}

############
# API Proxy - Kong
############
KONG_HTTP_PORT=${API_PORT}
KONG_HTTPS_PORT=8443

############
# API - PostgREST
############
PGRST_DB_SCHEMAS=public,storage,graphql_public

############
# Auth - GoTrue
############
SITE_URL=${SITE_URL}
ADDITIONAL_REDIRECT_URLS=
JWT_EXPIRY=3600
DISABLE_SIGNUP=false
API_EXTERNAL_URL=${API_EXTERNAL_URL}

## Mailer Config
MAILER_URLPATHS_CONFIRMATION="/auth/v1/verify"
MAILER_URLPATHS_INVITE="/auth/v1/verify"
MAILER_URLPATHS_RECOVERY="/auth/v1/verify"
MAILER_URLPATHS_EMAIL_CHANGE="/auth/v1/verify"

## Email auth
ENABLE_EMAIL_SIGNUP=true
ENABLE_EMAIL_AUTOCONFIRM=true
SMTP_ADMIN_EMAIL=admin@example.com
SMTP_HOST=supabase-mail
SMTP_PORT=2500
SMTP_USER=fake_mail_user
SMTP_PASS=fake_mail_password
SMTP_SENDER_NAME=fake_sender
ENABLE_ANONYMOUS_USERS=false

## Phone auth
ENABLE_PHONE_SIGNUP=true
ENABLE_PHONE_AUTOCONFIRM=true

############
# Studio
############
STUDIO_DEFAULT_ORGANIZATION=Default Organization
STUDIO_DEFAULT_PROJECT=Default Project
STUDIO_PORT=${STUDIO_PORT}
SUPABASE_PUBLIC_URL=${SUPABASE_PUBLIC_URL}
IMGPROXY_ENABLE_WEBP_DETECTION=true

############
# Functions - Edge Runtime
############
FUNCTIONS_VERIFY_JWT=false

############
# Logs - Analytics
############
LOGFLARE_LOGGER_BACKEND_API_KEY=${LOGFLARE_API_KEY}
LOGFLARE_API_KEY=${LOGFLARE_API_KEY}

# Please refer to https://supabase.com/docs/reference/self-hosting-analytics/introduction
############
# Change vector.toml sinks to reflect this change
# these cannot be the same value
LOGFLARE_PUBLIC_ACCESS_TOKEN=${LOGFLARE_PUBLIC_ACCESS_TOKEN}
LOGFLARE_PRIVATE_ACCESS_TOKEN=${LOGFLARE_PRIVATE_ACCESS_TOKEN}

# Docker socket location
DOCKER_SOCKET_LOCATION=${DOCKER_SOCKET}

# Google Cloud Project details (não utilizado se não configurado)
GOOGLE_PROJECT_ID=GOOGLE_PROJECT_ID
GOOGLE_PROJECT_NUMBER=GOOGLE_PROJECT_NUMBER
ENVFILE

log "Arquivo .env criado com todas as variáveis"

# ─── Ajustar permissões dos volumes (PERSISTÊNCIA) ──────────────────────────
header "Preparando Volumes (Dados Persistentes)"

# Estes diretórios armazenam TODOS os dados permanentes do Supabase:
#   volumes/db/data      → Dados do PostgreSQL (tabelas, schemas, etc.)
#   volumes/storage      → Arquivos enviados via Storage API
#   volumes/functions    → Edge Functions customizadas
#   volumes/db/*.sql     → Scripts de inicialização do banco (vêm do repo)
#   volumes/api/         → Configuração do Kong
#   volumes/logs/        → Configuração do Vector (logs)
#   volumes/pooler/      → Configuração do Supavisor

mkdir -p "$INSTALL_DIR/volumes/storage"
mkdir -p "$INSTALL_DIR/volumes/db/data"
mkdir -p "$INSTALL_DIR/volumes/functions"

# Garantir permissões corretas
chmod -R 755 "$INSTALL_DIR/volumes"

log "Diretórios de volumes criados em: $INSTALL_DIR/volumes/"
info "Os dados do banco serão persistidos em: ${CYAN}$INSTALL_DIR/volumes/db/data/${NC}"
info "Os arquivos de storage serão persistidos em: ${CYAN}$INSTALL_DIR/volumes/storage/${NC}"
warn "NUNCA use 'docker compose down -v' (o -v apaga os volumes!)"

# ─── Iniciar Supabase ───────────────────────────────────────────────────────
header "Iniciando Supabase"

cd "$INSTALL_DIR"

info "Baixando imagens Docker (isso pode demorar alguns minutos)..."
$COMPOSE_CMD pull 2>&1 | tail -5

info "Iniciando todos os serviços..."
$COMPOSE_CMD up -d 2>&1

# ─── Aguardar serviços ficarem saudáveis ─────────────────────────────────────
header "Aguardando Serviços"

MAX_WAIT=180
ELAPSED=0
INTERVAL=5

check_service() {
    local service_name="$1"
    local container_name="$2"
    local status
    status=$(docker inspect --format='{{.State.Health.Status}}' "$container_name" 2>/dev/null || echo "not_found")
    case "$status" in
        healthy) echo "healthy" ;;
        unhealthy) echo "unhealthy" ;;
        starting) echo "starting" ;;
        *) echo "waiting" ;;
    esac
}

SERVICES=(
    "Studio:supabase-studio"
    "Kong:supabase-kong"
    "Auth:supabase-auth"
    "Rest:supabase-rest"
    "Realtime:realtime-dev.supabase-realtime"
    "Storage:supabase-storage"
    "Database:supabase-db"
    "Analytics:supabase-analytics"
)

info "Aguardando serviços ficarem saudáveis (timeout: ${MAX_WAIT}s)..."

while [[ $ELAPSED -lt $MAX_WAIT ]]; do
    ALL_HEALTHY=true
    STATUS_LINE=""

    for svc in "${SERVICES[@]}"; do
        IFS=':' read -r name container <<< "$svc"
        status=$(check_service "$name" "$container")
        if [[ "$status" != "healthy" ]]; then
            ALL_HEALTHY=false
        fi
        case "$status" in
            healthy)   STATUS_LINE+=" ${GREEN}${name}✓${NC}" ;;
            unhealthy) STATUS_LINE+=" ${RED}${name}✗${NC}" ;;
            *)         STATUS_LINE+=" ${YELLOW}${name}…${NC}" ;;
        esac
    done

    echo -ne "\r  [${ELAPSED}s]${STATUS_LINE}   "

    if $ALL_HEALTHY; then
        echo ""
        break
    fi

    sleep "$INTERVAL"
    ELAPSED=$((ELAPSED + INTERVAL))
done

echo ""

if $ALL_HEALTHY; then
    log "Todos os serviços estão saudáveis!"
else
    warn "Nem todos os serviços estão saudáveis ainda, mas podem precisar de mais tempo."
    warn "Verifique com: cd $INSTALL_DIR && $COMPOSE_CMD ps"
fi

# ─── Verificar se a API responde ─────────────────────────────────────────────
info "Testando API..."
sleep 3

# Testar localmente usando o bind host (não o público, que pode depender de proxy)
TEST_HOST="$SUPABASE_BIND_HOST"
if [[ "$TEST_HOST" == "0.0.0.0" ]]; then
    TEST_HOST="127.0.0.1"
fi

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://${TEST_HOST}:${API_PORT}/rest/v1/" \
    -H "apikey: ${ANON_KEY}" \
    -H "Authorization: Bearer ${ANON_KEY}" 2>/dev/null || echo "000")

if [[ "$HTTP_CODE" == "200" ]]; then
    log "API REST respondendo corretamente (HTTP 200) em http://${TEST_HOST}:${API_PORT}"
elif [[ "$HTTP_CODE" != "000" ]]; then
    warn "API respondeu com HTTP $HTTP_CODE (pode ser esperado se não há tabelas)"
else
    warn "API ainda não respondeu. Pode precisar de mais alguns segundos."
fi

# ─── Salvar credenciais ─────────────────────────────────────────────────────
CREDENTIALS_FILE="$INSTALL_DIR/CREDENCIAIS.txt"
cat > "$CREDENTIALS_FILE" << CREDS
╔══════════════════════════════════════════════════════════════════════════════╗
║                    SUPABASE – CREDENCIAIS DE ACESSO                        ║
║            Gerado em: $(date '+%Y-%m-%d %H:%M:%S')                            ║
║            Modo:     ${BIND_DESCRIPTION}
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                            ║
║  ⚠ GUARDE ESTE ARQUIVO EM LOCAL SEGURO E DEPOIS REMOVA DO SERVIDOR!       ║
║                                                                            ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                            ║
║  STUDIO (Dashboard Web)                                                    ║
║  ─────────────────────                                                     ║
║  URL:      ${SITE_URL}
║  Usuário:  ${DASHBOARD_USERNAME}
║  Senha:    ${DASHBOARD_PASSWORD}
║                                                                            ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                            ║
║  API (Kong Gateway)                                                        ║
║  ─────────────────                                                         ║
║  URL Pública: ${API_EXTERNAL_URL}
║  Bind:        ${SUPABASE_BIND_HOST}:${API_PORT}
║                                                                            ║
║  REDE E ACESSO                                                             ║
║  ─────────────                                                             ║
║  Modo:        ${BIND_DESCRIPTION}
║  Bind Host:   ${SUPABASE_BIND_HOST}
║  Host Público: ${SUPABASE_PUBLIC_HOST}
║  Protocolo:   ${PUBLIC_PROTOCOL}
║  IP Interno:  ${INTERNAL_IP:-N/A}
║  IP Externo:  ${EXTERNAL_IP:-N/A}
║  Proxy:       ${IS_BEHIND_PROXY}
║                                                                            ║
║  Portas internas (Docker bind):                                            ║
║    ${STUDIO_PORT}/tcp  - Studio (Dashboard)
║    ${API_PORT}/tcp  - API Gateway (Kong)
║    5432/tcp  - PostgreSQL (via Supavisor session mode)
║    6543/tcp  - PostgreSQL (via Supavisor transaction mode)
║                                                                            ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                            ║
║  BANCO DE DADOS (PostgreSQL via Supavisor)                                 ║
║  ─────────────────────────────────────────                                 ║
║  Host:     ${SUPABASE_BIND_HOST}  (usar IP interno, não expor externamente)
║  Porta:    5432 (session) / 6543 (transaction pooling)                     ║
║  Database: postgres                                                        ║
║  User:     postgres.${POOLER_TENANT_ID}
║  Password: ${POSTGRES_PASSWORD}
║                                                                            ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                            ║
║  CHAVES DE API                                                             ║
║  ─────────────                                                             ║
║                                                                            ║
║  JWT_SECRET:                                                               ║
║  ${JWT_SECRET}
║                                                                            ║
║  ANON_KEY (usar no frontend):                                              ║
║  ${ANON_KEY}
║                                                                            ║
║  SERVICE_ROLE_KEY (NUNCA expor no frontend!):                              ║
║  ${SERVICE_ROLE_KEY}
║                                                                            ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                            ║
║  EXEMPLOS DE USO                                                           ║
║  ───────────────                                                           ║
║                                                                            ║
║  # JavaScript/TypeScript:                                                  ║
║  import { createClient } from '@supabase/supabase-js'                      ║
║  const supabase = createClient(                                            ║
║    '${API_EXTERNAL_URL}',
║    '<ANON_KEY>'                                                            ║
║  )                                                                         ║
║                                                                            ║
║  # curl (listar tabelas):                                                  ║
║  curl ${API_EXTERNAL_URL}/rest/v1/ \\
║    -H "apikey: <ANON_KEY>"                                                 ║
║                                                                            ║
║  # psql (conexão direta – usar IP interno):                                ║
║  psql "postgresql://postgres.${POOLER_TENANT_ID}:<PASS>@${SUPABASE_BIND_HOST}:5432/postgres"
║                                                                            ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                            ║
║  COMANDOS ÚTEIS                                                            ║
║  ──────────────                                                            ║
║  cd ${INSTALL_DIR}
║  $COMPOSE_CMD ps                  # Status dos serviços
║  $COMPOSE_CMD logs -f             # Logs em tempo real
║  $COMPOSE_CMD down                # Parar tudo
║  $COMPOSE_CMD up -d               # Iniciar tudo
║  $COMPOSE_CMD restart             # Reiniciar tudo
║                                                                            ║
╚══════════════════════════════════════════════════════════════════════════════╝
CREDS

chmod 600 "$CREDENTIALS_FILE"
log "Credenciais salvas em: $CREDENTIALS_FILE"

# ─── Criar script de gerenciamento ───────────────────────────────────────────
cat > "$INSTALL_DIR/supabase-ctl.sh" << 'CTLSCRIPT'
#!/usr/bin/env bash
# Supabase Control Script
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

COMPOSE_CMD="docker compose"
if ! docker compose version &>/dev/null 2>&1; then
    COMPOSE_CMD="docker-compose"
fi

case "${1:-help}" in
    start)
        echo -e "${GREEN}Iniciando Supabase...${NC}"
        $COMPOSE_CMD up -d
        echo -e "${GREEN}Supabase iniciado!${NC}"
        ;;
    stop)
        echo -e "${YELLOW}Parando Supabase (dados serão mantidos)...${NC}"
        $COMPOSE_CMD down
        echo -e "${GREEN}Supabase parado. Dados persistidos em: $SCRIPT_DIR/volumes/${NC}"
        ;;
    restart)
        echo -e "${YELLOW}Reiniciando Supabase...${NC}"
        $COMPOSE_CMD down
        $COMPOSE_CMD up -d
        echo -e "${GREEN}Supabase reiniciado!${NC}"
        ;;
    status)
        $COMPOSE_CMD ps
        echo ""
        echo -e "${CYAN}Uso de disco dos dados:${NC}"
        du -sh "$SCRIPT_DIR/volumes/db/data" 2>/dev/null || echo "  DB: N/A"
        du -sh "$SCRIPT_DIR/volumes/storage" 2>/dev/null || echo "  Storage: N/A"
        ;;
    logs)
        shift
        $COMPOSE_CMD logs -f "$@"
        ;;
    update)
        echo -e "${YELLOW}Atualizando imagens do Supabase...${NC}"
        $COMPOSE_CMD pull
        $COMPOSE_CMD up -d --force-recreate
        echo -e "${GREEN}Supabase atualizado!${NC}"
        ;;
    backup-db)
        BACKUP_FILE="$SCRIPT_DIR/supabase_backup_$(date +%Y%m%d_%H%M%S).sql"
        echo "Criando backup do banco de dados..."
        docker exec supabase-db pg_dumpall -U supabase_admin > "$BACKUP_FILE"
        DUMP_SIZE=$(du -sh "$BACKUP_FILE" | awk '{print $1}')
        echo -e "${GREEN}Backup salvo: $BACKUP_FILE ($DUMP_SIZE)${NC}"
        ;;
    nuke)
        echo -e "${RED}⚠  Para remover completamente o Supabase, use:${NC}"
        echo -e "${RED}   sudo ./uninstall-supabase.sh${NC}"
        echo -e "${RED}   (ou com --backup para salvar os dados antes)${NC}"
        ;;
    help|*)
        echo "Supabase Control Script"
        echo ""
        echo "Uso: $0 {comando}"
        echo ""
        echo "  start      - Inicia todos os serviços"
        echo "  stop       - Para todos os serviços (dados mantidos)"
        echo "  restart    - Reinicia todos os serviços"
        echo "  status     - Status dos serviços e uso de disco"
        echo "  logs [svc] - Logs em tempo real (ex: logs supavisor)"
        echo "  update     - Atualiza imagens e reinicia"
        echo "  backup-db  - Faz backup completo do banco"
        echo "  nuke       - Instruções para remoção total"
        echo ""
        echo -e "  ${YELLOW}⚠ NUNCA use 'docker compose down -v' (apaga dados!)${NC}"
        ;;
esac
CTLSCRIPT

chmod +x "$INSTALL_DIR/supabase-ctl.sh"
log "Script de gerenciamento criado: $INSTALL_DIR/supabase-ctl.sh"

# ─── Resumo Final ────────────────────────────────────────────────────────────
header "Instalação Concluída!"

echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║         🎉 Supabase instalado com sucesso! 🎉              ║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║${NC}                                                            ${GREEN}║${NC}"
echo -e "${GREEN}║${NC}  ${CYAN}Modo:${NC}      ${BIND_DESCRIPTION}"
if [[ "$IS_BEHIND_PROXY" == true ]]; then
    echo -e "${GREEN}║${NC}  ${CYAN}Bind:${NC}      ${SUPABASE_BIND_HOST}:${API_PORT} (API) / :${STUDIO_PORT} (Studio)"
    echo -e "${GREEN}║${NC}  ${CYAN}API:${NC}       ${API_EXTERNAL_URL}  (público)"
    echo -e "${GREEN}║${NC}  ${CYAN}Studio:${NC}    ${SITE_URL}  (público)"
else
    echo -e "${GREEN}║${NC}  ${CYAN}Studio:${NC}    ${SITE_URL}"
    echo -e "${GREEN}║${NC}  ${CYAN}API:${NC}       ${API_EXTERNAL_URL}"
fi
echo -e "${GREEN}║${NC}  ${CYAN}Postgres:${NC}  ${SUPABASE_BIND_HOST}:5432 (session) / :6543 (transaction)"
echo -e "${GREEN}║${NC}                                                            ${GREEN}║${NC}"
echo -e "${GREEN}║${NC}  ${YELLOW}Dashboard:${NC} ${DASHBOARD_USERNAME} / ${DASHBOARD_PASSWORD}"
echo -e "${GREEN}║${NC}                                                            ${GREEN}║${NC}"
echo -e "${GREEN}║${NC}  ${YELLOW}Credenciais:${NC} $CREDENTIALS_FILE"
echo -e "${GREEN}║${NC}  ${YELLOW}Gerenciar:${NC}   $INSTALL_DIR/supabase-ctl.sh"
echo -e "${GREEN}║${NC}                                                            ${GREEN}║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
warn "IMPORTANTE: Guarde o arquivo CREDENCIAIS.txt em local seguro!"
warn "Para produção, configure SMTP real (AWS SES, Mailgun, etc.)."

# Dicas específicas por modo de acesso
case "$ACCESS_MODE" in
    2)
        echo ""
        info "Para acessar na rede interna, verifique se as portas estão liberadas:"
        echo -e "  ${CYAN}sudo ufw allow ${STUDIO_PORT}/tcp   # Studio${NC}"
        echo -e "  ${CYAN}sudo ufw allow ${API_PORT}/tcp   # API${NC}"
        echo -e "  ${CYAN}sudo ufw allow 5432/tcp   # PostgreSQL${NC}"
        ;;
    3)
        echo ""
        warn "⚠ Acesso externo habilitado! Recomendações de segurança:"
        echo -e "  ${YELLOW}1.${NC} Configure SSL/TLS com proxy reverso (Nginx/Caddy)"
        echo -e "  ${YELLOW}2.${NC} Restrinja portas no firewall (apenas ${API_PORT} e ${STUDIO_PORT})"
        echo -e "  ${YELLOW}3.${NC} NÃO exponha a porta 5432 diretamente para a internet"
        echo -e "  ${YELLOW}4.${NC} Use uma senha forte no Dashboard (já gerada automaticamente)"
        echo ""
        info "Firewall básico (UFW):"
        echo -e "  ${CYAN}sudo ufw allow ${STUDIO_PORT}/tcp${NC}"
        echo -e "  ${CYAN}sudo ufw allow ${API_PORT}/tcp${NC}"
        echo -e "  ${CYAN}sudo ufw deny 5432/tcp    # Bloquear acesso externo ao DB${NC}"
        ;;
    5)
        echo ""
        info "Configuração do Proxy Reverso / Load Balancer:"
        echo ""
        echo -e "  O Supabase está escutando em ${CYAN}${SUPABASE_BIND_HOST}:${API_PORT}${NC} (API)"
        echo -e "  e ${CYAN}${SUPABASE_BIND_HOST}:${STUDIO_PORT}${NC} (Studio)"
        echo ""
        echo -e "  ${YELLOW}Configure seu proxy para encaminhar:${NC}"
        echo ""
        if [[ "$SITE_URL" != "$API_EXTERNAL_URL" ]]; then
            echo -e "  ${CYAN}${API_EXTERNAL_URL}${NC}  →  ${CYAN}${SUPABASE_BIND_HOST}:${API_PORT}${NC}  (API / Kong)"
            echo -e "  ${CYAN}${SITE_URL}${NC}  →  ${CYAN}${SUPABASE_BIND_HOST}:${STUDIO_PORT}${NC}  (Studio)"
        else
            echo -e "  ${CYAN}${API_EXTERNAL_URL}${NC}  →  ${CYAN}${SUPABASE_BIND_HOST}:${API_PORT}${NC}  (API / Kong)"
            echo -e "  Studio separadamente  →  ${CYAN}${SUPABASE_BIND_HOST}:${STUDIO_PORT}${NC}  (Studio)"
        fi
        echo ""
        echo -e "  ${YELLOW}Exemplo Nginx (API):${NC}"
        echo -e "  ${CYAN}server {${NC}"
        echo -e "  ${CYAN}    listen 443 ssl;${NC}"
        echo -e "  ${CYAN}    server_name ${SUPABASE_PUBLIC_HOST};${NC}"
        echo -e "  ${CYAN}    location / {${NC}"
        echo -e "  ${CYAN}        proxy_pass http://${SUPABASE_BIND_HOST}:${API_PORT};${NC}"
        echo -e "  ${CYAN}        proxy_set_header Host \$host;${NC}"
        echo -e "  ${CYAN}        proxy_set_header X-Real-IP \$remote_addr;${NC}"
        echo -e "  ${CYAN}        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;${NC}"
        echo -e "  ${CYAN}        proxy_set_header X-Forwarded-Proto \$scheme;${NC}"
        echo -e "  ${CYAN}        proxy_set_header Upgrade \$http_upgrade;${NC}"
        echo -e "  ${CYAN}        proxy_set_header Connection \"upgrade\";${NC}"
        echo -e "  ${CYAN}    }${NC}"
        echo -e "  ${CYAN}}${NC}"
        echo ""
        echo -e "  ${YELLOW}Exemplo Caddy (mais simples):${NC}"
        echo -e "  ${CYAN}${SUPABASE_PUBLIC_HOST} {${NC}"
        echo -e "  ${CYAN}    reverse_proxy ${SUPABASE_BIND_HOST}:${API_PORT}${NC}"
        echo -e "  ${CYAN}}${NC}"
        echo ""
        warn "Headers importantes para WebSocket (Realtime):"
        echo -e "  ${YELLOW}Upgrade${NC} e ${YELLOW}Connection${NC} devem ser encaminhados para o Realtime funcionar."
        echo ""
        warn "NÃO exponha as portas 5432/6543 (PostgreSQL) no proxy."
        ;;
esac
echo ""
