#!/usr/bin/env bash
set -Eeuo pipefail

RCTL_MANAGER_VERSION=1
readonly RCTL_MANAGER_VERSION
readonly REPOSITORY="${RCTL_REPOSITORY:-longxingze0925/yc}"
readonly SOURCE_REF="${RCTL_SOURCE_REF:-main}"
readonly INSTALL_DIR="${RCTL_INSTALL_DIR:-/opt/remote-control}"
readonly APP_DIR="$INSTALL_DIR/app"
readonly CONFIG_DIR="$INSTALL_DIR/config"
readonly ENV_FILE="$CONFIG_DIR/.env"
readonly CERT_DIR="$INSTALL_DIR/certificates"
readonly BACKUP_DIR="$INSTALL_DIR/backups"
readonly COMPOSE_FILE="$APP_DIR/infra/production/compose.yml"
readonly COMMAND_LINK="${RCTL_COMMAND_LINK:-/usr/local/bin/remote-control}"
readonly CRON_FILE="${RCTL_CRON_FILE:-/etc/cron.d/remote-control-cert-renew}"

umask 077

log() {
    printf '[remote-control] %s\n' "$*"
}

warn() {
    printf '[remote-control] WARNING: %s\n' "$*" >&2
}

die() {
    printf '[remote-control] ERROR: %s\n' "$*" >&2
    exit 1
}

validate_install_dir() {
    [[ "$INSTALL_DIR" == /* ]] || die 'RCTL_INSTALL_DIR must be an absolute path'
    [[ "$INSTALL_DIR" != "/" && ${#INSTALL_DIR} -ge 12 ]] \
        || die 'RCTL_INSTALL_DIR is too broad'
    [[ "$INSTALL_DIR" != *$'\n'* ]] || die 'RCTL_INSTALL_DIR contains a newline'
}

require_root() {
    if [[ "${RCTL_ALLOW_NON_ROOT:-0}" != "1" && "$(id -u)" != "0" ]]; then
        die 'run this command as root'
    fi
}

require_install() {
    [[ -f "$ENV_FILE" && -f "$COMPOSE_FILE" ]] \
        || die "installation not found at $INSTALL_DIR"
}

load_env() {
    require_install
    set -a
    # shellcheck disable=SC1090
    source "$ENV_FILE"
    set +a
}

docker_compose() {
    docker compose --env-file "$ENV_FILE" --file "$COMPOSE_FILE" "$@"
}

confirm() {
    local prompt="$1"
    if [[ "${RCTL_ASSUME_YES:-0}" == "1" ]]; then
        return 0
    fi
    [[ -t 0 ]] || die "$prompt; set RCTL_ASSUME_YES=1 for non-interactive use"
    local answer
    read -r -p "$prompt [y/N]: " answer
    [[ "$answer" == "y" || "$answer" == "Y" ]]
}

ensure_system_dependencies() {
    local missing=()
    local command_name
    for command_name in curl openssl jq tar gzip ss; do
        command -v "$command_name" >/dev/null 2>&1 || missing+=("$command_name")
    done
    ((${#missing[@]} == 0)) && return 0

    command -v apt-get >/dev/null 2>&1 \
        || die "missing commands (${missing[*]}); automatic dependency installation supports Debian/Ubuntu"
    log "Installing system dependencies: ${missing[*]}"
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates curl openssl jq tar gzip iproute2
}

ensure_docker() {
    if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
        return 0
    fi

    if [[ "${RCTL_AUTO_INSTALL_DOCKER:-0}" != "1" ]]; then
        confirm 'Docker Engine with Compose v2 is missing. Install it now' \
            || die 'Docker installation was not approved'
    fi

    local installer
    installer="$(mktemp)"
    trap 'rm -f -- "$installer"' RETURN
    curl --fail --silent --show-error --location https://get.docker.com --output "$installer"
    sh "$installer"
    rm -f -- "$installer"
    trap - RETURN
    if command -v systemctl >/dev/null 2>&1; then
        systemctl enable --now docker
    fi
    docker compose version >/dev/null 2>&1 || die 'Docker Compose v2 installation did not complete'
}

is_ipv4() {
    local value="$1"
    local IFS=.
    local octets=()
    read -r -a octets <<< "$value"
    [[ ${#octets[@]} -eq 4 ]] || return 1
    local octet
    for octet in "${octets[@]}"; do
        [[ "$octet" =~ ^[0-9]{1,3}$ ]] || return 1
        ((10#$octet >= 0 && 10#$octet <= 255)) || return 1
    done
}

is_public_ipv4() {
    is_ipv4 "$1" || return 1
    local IFS=.
    local a b c d
    read -r a b c d <<< "$1"
    ((a != 0 && a != 10 && a != 127 && a < 224)) || return 1
    ! ((a == 100 && b >= 64 && b <= 127)) || return 1
    ! ((a == 169 && b == 254)) || return 1
    ! ((a == 172 && b >= 16 && b <= 31)) || return 1
    ! ((a == 192 && b == 168)) || return 1
}

is_domain() {
    local value="$1"
    [[ ${#value} -le 253 && "$value" == *.* && "$value" != *..* ]] || return 1
    [[ "$value" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]] || return 1
    ! is_ipv4 "$value"
}

check_public_ip() {
    local expected="$1"
    [[ "${RCTL_SKIP_PUBLIC_IP_CHECK:-0}" == "1" ]] && return 0

    local endpoint observed found=0 matched=0
    for endpoint in https://api.ipify.org https://ifconfig.me/ip; do
        observed="$(curl --fail --silent --show-error --max-time 8 "$endpoint" 2>/dev/null || true)"
        observed="${observed//$'\n'/}"
        if is_ipv4 "$observed"; then
            found=1
            [[ "$observed" == "$expected" ]] && matched=1
        fi
    done
    ((found == 1)) || die 'no external IPv4 observation source responded; set RCTL_SKIP_PUBLIC_IP_CHECK=1 only after checking the address manually'
    ((matched == 1)) || die "configured IPv4 $expected does not match the observed public address"
}

random_hex() {
    openssl rand -hex "$1"
}

random_base64url_32() {
    openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n'
}

DEPLOY_MODE=''
PUBLIC_HOST=''
LETSENCRYPT_EMAIL=''
CUSTOM_CERT_PATH=''
CUSTOM_KEY_PATH=''
CUSTOM_CA_PATH=''
PUBLIC_HTTP_PORT='80'
PUBLIC_HTTPS_PORT='443'
PUBLIC_HTTPS_REDIRECT_SUFFIX=''
RELAY_PUBLIC_PORT='18082'

validate_port() {
    local value="$1"
    [[ "$value" =~ ^[0-9]+$ ]] && ((value >= 1 && value <= 65535))
}

collect_ports() {
    PUBLIC_HTTP_PORT="${RCTL_PUBLIC_HTTP_PORT:-80}"
    PUBLIC_HTTPS_PORT="${RCTL_PUBLIC_HTTPS_PORT:-443}"
    RELAY_PUBLIC_PORT="${RCTL_RELAY_PUBLIC_PORT:-18082}"
    validate_port "$PUBLIC_HTTP_PORT" || die 'RCTL_PUBLIC_HTTP_PORT must be between 1 and 65535'
    validate_port "$PUBLIC_HTTPS_PORT" || die 'RCTL_PUBLIC_HTTPS_PORT must be between 1 and 65535'
    validate_port "$RELAY_PUBLIC_PORT" || die 'RCTL_RELAY_PUBLIC_PORT must be between 1 and 65535'
    [[ "$PUBLIC_HTTP_PORT" != "$PUBLIC_HTTPS_PORT" && "$PUBLIC_HTTP_PORT" != "$RELAY_PUBLIC_PORT" \
        && "$PUBLIC_HTTPS_PORT" != "$RELAY_PUBLIC_PORT" ]] \
        || die 'public HTTP, HTTPS, and Relay ports must be distinct'
    if [[ "$PUBLIC_HTTPS_PORT" == '443' ]]; then
        PUBLIC_HTTPS_REDIRECT_SUFFIX=''
    else
        PUBLIC_HTTPS_REDIRECT_SUFFIX=":$PUBLIC_HTTPS_PORT"
    fi
}

check_port_available() {
    local port="$1" label="$2"
    command -v ss >/dev/null 2>&1 || return 0
    local listeners
    listeners="$(ss -H -ltnup "sport = :$port" 2>/dev/null || true)"
    if [[ -n "$listeners" ]]; then
        printf '%s\n' "$listeners" >&2
        die "$label port $port is already in use; set a different RCTL_*_PORT or stop the existing service"
    fi
}

check_ports_available() {
    check_port_available "$PUBLIC_HTTP_PORT" 'HTTP'
    check_port_available "$PUBLIC_HTTPS_PORT" 'HTTPS'
    check_port_available "$RELAY_PUBLIC_PORT" 'Relay'
}

collect_deployment_config() {
    DEPLOY_MODE="${RCTL_DEPLOY_MODE:-}"
    if [[ -z "$DEPLOY_MODE" ]]; then
        [[ -t 0 ]] || die 'set RCTL_DEPLOY_MODE for non-interactive installation'
        printf '%s\n' \
            '1) Domain with automatic Let'"'"'s Encrypt certificate' \
            '2) Public IPv4 with a generated private CA and IP SAN certificate' \
            '3) Domain or public IPv4 with an existing certificate'
        local selection
        read -r -p 'Select deployment mode [1-3]: ' selection
        case "$selection" in
            1) DEPLOY_MODE=domain ;;
            2) DEPLOY_MODE=ip_self_signed ;;
            3) DEPLOY_MODE=custom ;;
            *) die 'invalid deployment mode' ;;
        esac
    fi

    case "$DEPLOY_MODE" in
        domain | ip_self_signed | custom) ;;
        *) die 'RCTL_DEPLOY_MODE must be domain, ip_self_signed, or custom' ;;
    esac

    PUBLIC_HOST="${RCTL_PUBLIC_HOST:-}"
    if [[ -z "$PUBLIC_HOST" ]]; then
        read -r -p 'Public domain or IPv4: ' PUBLIC_HOST
    fi

    case "$DEPLOY_MODE" in
        domain)
            is_domain "$PUBLIC_HOST" || die 'domain mode requires a valid domain name'
            [[ "${RCTL_PUBLIC_HTTP_PORT:-80}" == '80' && "${RCTL_PUBLIC_HTTPS_PORT:-443}" == '443' ]] \
                || die 'domain mode with automatic Let\x27s Encrypt requires public ports 80 and 443; use custom certificate mode behind an existing proxy for alternate ports'
            LETSENCRYPT_EMAIL="${RCTL_LETSENCRYPT_EMAIL:-}"
            [[ -n "$LETSENCRYPT_EMAIL" ]] || read -r -p "Let's Encrypt email: " LETSENCRYPT_EMAIL
            [[ "$LETSENCRYPT_EMAIL" == *@*.* ]] || die 'a valid email is required for certificate expiry notices'
            ;;
        ip_self_signed)
            is_public_ipv4 "$PUBLIC_HOST" || die 'ip_self_signed mode requires a public IPv4 address'
            check_public_ip "$PUBLIC_HOST"
            ;;
        custom)
            is_domain "$PUBLIC_HOST" || is_public_ipv4 "$PUBLIC_HOST" \
                || die 'custom mode requires a valid domain or public IPv4 address'
            if is_ipv4 "$PUBLIC_HOST"; then
                check_public_ip "$PUBLIC_HOST"
            fi
            CUSTOM_CERT_PATH="${RCTL_TLS_CERT_PATH:-}"
            CUSTOM_KEY_PATH="${RCTL_TLS_KEY_PATH:-}"
            CUSTOM_CA_PATH="${RCTL_CLIENT_CA_CERT_PATH:-}"
            [[ -n "$CUSTOM_CERT_PATH" ]] || read -r -p 'Certificate chain path: ' CUSTOM_CERT_PATH
            [[ -n "$CUSTOM_KEY_PATH" ]] || read -r -p 'Private key path: ' CUSTOM_KEY_PATH
            ;;
    esac
    collect_ports
    check_ports_available
}

write_environment() {
    local client_ca=''
    [[ "$DEPLOY_MODE" == "ip_self_signed" ]] && client_ca="$CERT_DIR/root-ca.crt"
    [[ "$DEPLOY_MODE" == "custom" && -n "$CUSTOM_CA_PATH" ]] && client_ca="$CERT_DIR/root-ca.crt"

    mkdir -p "$CONFIG_DIR"
    {
        printf 'PUBLIC_HOST=%s\n' "$PUBLIC_HOST"
        printf 'DEPLOY_MODE=%s\n' "$DEPLOY_MODE"
        if [[ "$PUBLIC_HTTPS_PORT" == '443' ]]; then
            printf 'REMOTE_API_PUBLIC_URL=https://%s\n' "$PUBLIC_HOST"
            printf 'REMOTE_SIGNAL_PUBLIC_URL=wss://%s/ws\n' "$PUBLIC_HOST"
        else
            printf 'REMOTE_API_PUBLIC_URL=https://%s:%s\n' "$PUBLIC_HOST" "$PUBLIC_HTTPS_PORT"
            printf 'REMOTE_SIGNAL_PUBLIC_URL=wss://%s:%s/ws\n' "$PUBLIC_HOST" "$PUBLIC_HTTPS_PORT"
        fi
        printf 'REMOTE_RELAY_PUBLIC_URL=%s:%s\n' "$PUBLIC_HOST" "$RELAY_PUBLIC_PORT"
        printf 'RELAY_PUBLIC_PORT=%s\n' "$RELAY_PUBLIC_PORT"
        printf 'PUBLIC_HTTP_PORT=%s\n' "$PUBLIC_HTTP_PORT"
        printf 'PUBLIC_HTTPS_PORT=%s\n' "$PUBLIC_HTTPS_PORT"
        printf 'PUBLIC_HTTPS_REDIRECT_SUFFIX=%s\n' "$PUBLIC_HTTPS_REDIRECT_SUFFIX"
        printf 'POSTGRES_DB=remote_control\n'
        printf 'POSTGRES_USER=remote\n'
        printf 'POSTGRES_PASSWORD=%s\n' "$(random_hex 24)"
        printf 'REMOTE_SERVICE_TOKEN=%s\n' "$(random_hex 32)"
        printf 'REMOTE_TOKEN_SECRET=%s\n' "$(random_hex 32)"
        printf 'REMOTE_RELAY_TOKEN_SECRET=%s\n' "$(random_hex 32)"
        printf 'REMOTE_MFA_SECRET_KEY=%s\n' "$(random_base64url_32)"
        printf 'REMOTE_RELAY_NODE_ID=relay-production-1\n'
        printf 'TLS_CERT_PATH=%s/server.crt\n' "$CERT_DIR"
        printf 'TLS_KEY_PATH=%s/server.key\n' "$CERT_DIR"
        printf 'CLIENT_CA_CERT_PATH=%s\n' "$client_ca"
        printf 'LETSENCRYPT_EMAIL=%s\n' "$LETSENCRYPT_EMAIL"
    } > "$ENV_FILE"
    chmod 0600 "$ENV_FILE"
}

verify_certificate_pair() {
    local certificate="$1"
    local private_key="$2"
    local cert_public key_public
    cert_public="$(mktemp)"
    key_public="$(mktemp)"
    openssl x509 -in "$certificate" -pubkey -noout > "$cert_public"
    openssl pkey -in "$private_key" -pubout > "$key_public"
    cmp -s "$cert_public" "$key_public" || {
        rm -f -- "$cert_public" "$key_public"
        die 'TLS certificate and private key do not match'
    }
    rm -f -- "$cert_public" "$key_public"

    if is_ipv4 "$PUBLIC_HOST"; then
        openssl x509 -in "$certificate" -noout -checkip "$PUBLIC_HOST" >/dev/null \
            || die "TLS certificate has no IP SAN for $PUBLIC_HOST"
    else
        openssl x509 -in "$certificate" -noout -checkhost "$PUBLIC_HOST" >/dev/null \
            || die "TLS certificate does not cover $PUBLIC_HOST"
    fi
}

generate_ip_certificate() {
    mkdir -p "$CERT_DIR"
    if [[ ! -s "$CERT_DIR/root-ca.key" || ! -s "$CERT_DIR/root-ca.crt" ]]; then
        log 'Generating the private root CA for this deployment'
        openssl req -x509 -newkey rsa:3072 -sha256 -days 3650 -nodes \
            -subj '/CN=Remote Control Private Root CA' \
            -keyout "$CERT_DIR/root-ca.key" -out "$CERT_DIR/root-ca.crt"
    fi

    local extension_file request leaf
    extension_file="$(mktemp)"
    request="$(mktemp)"
    leaf="$(mktemp)"
    {
        printf '[req]\n'
        printf 'prompt = no\n'
        printf 'distinguished_name = dn\n'
        printf 'req_extensions = server_ext\n'
        printf '[dn]\n'
        printf 'CN = %s\n' "$PUBLIC_HOST"
        printf '[server_ext]\n'
        printf 'subjectAltName = IP:%s\n' "$PUBLIC_HOST"
        printf 'basicConstraints = critical,CA:FALSE\n'
        printf 'keyUsage = critical,digitalSignature,keyEncipherment\n'
        printf 'extendedKeyUsage = serverAuth\n'
    } > "$extension_file"
    openssl req -new -newkey rsa:3072 -nodes -sha256 \
        -config "$extension_file" -keyout "$CERT_DIR/server.key" -out "$request"
    openssl x509 -req -sha256 -days 397 -in "$request" \
        -CA "$CERT_DIR/root-ca.crt" -CAkey "$CERT_DIR/root-ca.key" -CAcreateserial \
        -extfile "$extension_file" -extensions server_ext -out "$leaf"
    cp "$leaf" "$CERT_DIR/server.crt"
    printf '\n' >> "$CERT_DIR/server.crt"
    cat "$CERT_DIR/root-ca.crt" >> "$CERT_DIR/server.crt"
    rm -f -- "$extension_file" "$request" "$leaf" "$CERT_DIR/root-ca.srl"
    chmod 0600 "$CERT_DIR/root-ca.key" "$CERT_DIR/server.key"
    chmod 0644 "$CERT_DIR/root-ca.crt" "$CERT_DIR/server.crt"
    verify_certificate_pair "$CERT_DIR/server.crt" "$CERT_DIR/server.key"
}

install_certbot() {
    command -v certbot >/dev/null 2>&1 && return 0
    command -v apt-get >/dev/null 2>&1 \
        || die 'automatic Let'"'"'s Encrypt mode requires certbot on Debian/Ubuntu'
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y certbot
}

copy_letsencrypt_certificate() {
    local live_dir="$CERT_DIR/letsencrypt/live/$PUBLIC_HOST"
    [[ -r "$live_dir/fullchain.pem" && -r "$live_dir/privkey.pem" ]] \
        || die "Let's Encrypt certificate was not created for $PUBLIC_HOST"
    cp -L "$live_dir/fullchain.pem" "$CERT_DIR/server.crt"
    cp -L "$live_dir/privkey.pem" "$CERT_DIR/server.key"
    chmod 0644 "$CERT_DIR/server.crt"
    chmod 0600 "$CERT_DIR/server.key"
    verify_certificate_pair "$CERT_DIR/server.crt" "$CERT_DIR/server.key"
}

issue_domain_certificate() {
    install_certbot
    mkdir -p "$CERT_DIR/letsencrypt" "$CERT_DIR/letsencrypt-work" "$CERT_DIR/letsencrypt-logs"
    certbot certonly --standalone --non-interactive --agree-tos \
        --preferred-challenges http \
        --email "$LETSENCRYPT_EMAIL" --domain "$PUBLIC_HOST" \
        --config-dir "$CERT_DIR/letsencrypt" \
        --work-dir "$CERT_DIR/letsencrypt-work" \
        --logs-dir "$CERT_DIR/letsencrypt-logs"
    copy_letsencrypt_certificate
}

install_custom_certificate() {
    [[ -r "$CUSTOM_CERT_PATH" ]] || die "certificate is not readable: $CUSTOM_CERT_PATH"
    [[ -r "$CUSTOM_KEY_PATH" ]] || die "private key is not readable: $CUSTOM_KEY_PATH"
    mkdir -p "$CERT_DIR"
    cp "$CUSTOM_CERT_PATH" "$CERT_DIR/server.crt"
    cp "$CUSTOM_KEY_PATH" "$CERT_DIR/server.key"
    if [[ -n "$CUSTOM_CA_PATH" ]]; then
        [[ -r "$CUSTOM_CA_PATH" ]] || die "client CA certificate is not readable: $CUSTOM_CA_PATH"
        cp "$CUSTOM_CA_PATH" "$CERT_DIR/root-ca.crt"
        chmod 0644 "$CERT_DIR/root-ca.crt"
    fi
    chmod 0644 "$CERT_DIR/server.crt"
    chmod 0600 "$CERT_DIR/server.key"
    verify_certificate_pair "$CERT_DIR/server.crt" "$CERT_DIR/server.key"
}

prepare_certificate() {
    case "$DEPLOY_MODE" in
        domain) issue_domain_certificate ;;
        ip_self_signed) generate_ip_certificate ;;
        custom) install_custom_certificate ;;
    esac
}

SOURCE_SWAPPED=0

download_source() {
    local temp_dir archive extracted source_root next_dir
    temp_dir="$(mktemp -d)"
    archive="$temp_dir/source.tar.gz"
    extracted="$temp_dir/extracted"
    next_dir="$INSTALL_DIR/app.next.$$"
    mkdir -p "$extracted"

    log "Downloading source ${REPOSITORY}@${SOURCE_REF}"
    curl --fail --silent --show-error --location \
        "https://codeload.github.com/${REPOSITORY}/tar.gz/${SOURCE_REF}" \
        --output "$archive"
    tar -xzf "$archive" -C "$extracted"
    source_root="$(find "$extracted" -mindepth 1 -maxdepth 1 -type d -print -quit)"
    [[ -n "$source_root" && -f "$source_root/Cargo.toml" ]] \
        || die 'downloaded source archive has no Cargo.toml'
    [[ -f "$source_root/infra/production/compose.yml" && -f "$source_root/ops/remotectl.sh" ]] \
        || die 'downloaded source archive has no production deployment files'

    rm -rf -- "$next_dir"
    mkdir -p "$next_dir"
    cp -a "$source_root/." "$next_dir/"
    rm -rf -- "$temp_dir"

    if [[ -d "$INSTALL_DIR/app.previous" ]]; then
        rm -rf -- "$INSTALL_DIR/app.previous"
    fi
    if [[ -d "$APP_DIR" ]]; then
        mv "$APP_DIR" "$INSTALL_DIR/app.previous"
    fi
    mv "$next_dir" "$APP_DIR"
    SOURCE_SWAPPED=1
}

rollback_source() {
    if ((SOURCE_SWAPPED == 1)) && [[ -d "$INSTALL_DIR/app.previous" ]]; then
        warn 'Restoring the previous application source'
        rm -rf -- "$APP_DIR"
        mv "$INSTALL_DIR/app.previous" "$APP_DIR"
        SOURCE_SWAPPED=0
    fi
}

install_manager_command() {
    install -m 0755 "$APP_DIR/ops/remotectl.sh" "$INSTALL_DIR/remotectl.sh"
    ln -sfn "$INSTALL_DIR/remotectl.sh" "$COMMAND_LINK"
}

install_certificate_cron() {
    if [[ "$DEPLOY_MODE" != "domain" ]]; then
        rm -f -- "$CRON_FILE"
        return 0
    fi
    {
        printf '23 3 * * * root %s renew-certificate --non-interactive >> /var/log/remote-control-cert-renew.log 2>&1\n' "$COMMAND_LINK"
    } > "$CRON_FILE"
    chmod 0644 "$CRON_FILE"
}

validate_compose_config() {
    docker_compose config --quiet
}

public_curl() {
    local arguments=(--fail --silent --show-error --location --max-time 15)
    if [[ -n "${CLIENT_CA_CERT_PATH:-}" && -r "${CLIENT_CA_CERT_PATH:-}" ]]; then
        arguments+=(--cacert "$CLIENT_CA_CERT_PATH")
    fi
    curl "${arguments[@]}" "$@"
}

local_public_curl() {
    public_curl --resolve "${PUBLIC_HOST}:${PUBLIC_HTTPS_PORT}:127.0.0.1" "$@"
}

check_internal_services() {
    docker_compose exec -T api-server \
        curl --fail --silent --show-error http://127.0.0.1:18080/health >/dev/null
    docker_compose exec -T signal-server \
        curl --fail --silent --show-error http://127.0.0.1:18081/health >/dev/null
    docker_compose exec -T relay-server \
        curl --fail --silent --show-error http://127.0.0.1:18083/health >/dev/null
    docker_compose exec -T caddy \
        caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null
    docker_compose exec -T postgres \
        pg_isready -U "$POSTGRES_USER" -d "$POSTGRES_DB" >/dev/null
    [[ "$(docker_compose exec -T redis redis-cli ping | tr -d '\r')" == "PONG" ]]
}

wait_for_services() {
    local attempt
    for attempt in $(seq 1 60); do
        if check_internal_services >/dev/null 2>&1 \
            && local_public_curl "$REMOTE_API_PUBLIC_URL/health" >/dev/null 2>&1; then
            log 'All service health checks passed'
            return 0
        fi
        sleep 5
    done
    docker_compose ps || true
    docker_compose logs --tail 120 || true
    return 1
}

print_client_config() {
    load_env
    printf 'RCTL_OFFICIAL_API_URL=%s\n' "$REMOTE_API_PUBLIC_URL"
    printf 'RCTL_OFFICIAL_SIGNAL_URL=%s\n' "$REMOTE_SIGNAL_PUBLIC_URL"
    printf 'RCTL_OFFICIAL_RELAY_URL=%s\n' "$REMOTE_RELAY_PUBLIC_URL"
    if [[ -n "${CLIENT_CA_CERT_PATH:-}" ]]; then
        printf 'RCTL_CLIENT_ROOT_CA=%s\n' "$CLIENT_CA_CERT_PATH"
    fi
}

print_install_result() {
    printf '\nInstallation completed.\n'
    print_client_config
    printf 'Management command: %s\n' "$COMMAND_LINK"
    printf 'Configuration: %s\n' "$ENV_FILE"
    printf 'Backups: %s\n' "$BACKUP_DIR"
    if [[ "$DEPLOY_MODE" == "ip_self_signed" ]]; then
        printf '\nInstall and fully trust this root certificate on the iPhone:\n%s\n' \
            "$CERT_DIR/root-ca.crt"
    fi
    printf '\nOpen TCP 80/443/18082 and UDP 443/18082 in the server firewall.\n'
}

backup_database() {
    load_env
    mkdir -p "$BACKUP_DIR"
    local timestamp backup_file
    timestamp="$(date -u +%Y%m%dT%H%M%SZ)-$$"
    backup_file="$BACKUP_DIR/postgres-${timestamp}.dump"
    log "Creating PostgreSQL backup: $backup_file"
    docker_compose exec -T postgres \
        pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" --format=custom > "$backup_file"
    [[ -s "$backup_file" ]] || die 'PostgreSQL backup is empty'
    chmod 0600 "$backup_file"
    (
        cd "$BACKUP_DIR"
        sha256sum "$(basename "$backup_file")" > "$(basename "$backup_file").sha256"
    )
    chmod 0600 "$backup_file.sha256"
    log "Backup verified: $(sha256sum "$backup_file" | awk '{print $1}')"
    printf '%s\n' "$backup_file"
}

start_stack() {
    load_env
    validate_compose_config
    docker_compose up --detach --build --remove-orphans
    if ! wait_for_services; then
        warn 'service startup health checks failed; inspect remote-control logs'
        return 1
    fi
}

install_main() {
    require_root
    validate_install_dir
    ensure_system_dependencies
    ensure_docker

    if [[ -f "$ENV_FILE" ]]; then
        log 'Existing installation detected; running the update path'
        update_main
        return 0
    fi

    mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$CERT_DIR" "$BACKUP_DIR"
    chmod 0700 "$CONFIG_DIR" "$CERT_DIR" "$BACKUP_DIR"
    collect_deployment_config
    prepare_certificate
    write_environment
    download_source
    install_manager_command
    install_certificate_cron

    if ! start_stack; then
        rollback_source
        die 'initial deployment failed'
    fi
    print_install_result
}

update_main() {
    require_root
    validate_install_dir
    require_install
    ensure_system_dependencies
    ensure_docker
    load_env

    if ! docker_compose exec -T postgres \
        pg_isready -U "$POSTGRES_USER" -d "$POSTGRES_DB" >/dev/null 2>&1; then
        log 'Existing containers are stopped; starting the current version before backup'
        docker_compose up --detach
        wait_for_services || die 'current version could not be started; update was not attempted'
    fi
    backup_database >/dev/null
    download_source
    if ! validate_compose_config || ! docker_compose up --detach --build --remove-orphans; then
        rollback_source
        install_manager_command
        docker_compose up --detach --build --remove-orphans || true
        die 'update failed; previous source was restored'
    fi
    install_manager_command
    wait_for_services || {
        rollback_source
        install_manager_command
        docker_compose up --detach --build --remove-orphans || true
        die 'updated services failed health checks; previous source was restored'
    }
    log 'Update completed; app.previous retains the prior source until the next update'
}

status_main() {
    require_root
    load_env
    docker_compose ps
    printf '\n'
    print_client_config
}

logs_main() {
    require_root
    load_env
    docker_compose logs --follow --tail 200 "$@"
}

restart_main() {
    require_root
    load_env
    docker_compose restart
    wait_for_services || die 'health checks failed after restart'
}

start_main() {
    require_root
    load_env
    docker_compose up --detach
    wait_for_services || die 'health checks failed after startup'
}

stop_main() {
    require_root
    load_env
    docker_compose stop
    log 'All application containers are stopped; persistent data is retained'
}

create_account_main() {
    require_root
    load_env
    local email="${RCTL_ACCOUNT_EMAIL:-}"
    local display_name="${RCTL_ACCOUNT_DISPLAY_NAME:-}"
    local password="${RCTL_ACCOUNT_PASSWORD:-}"
    [[ -n "$email" ]] || read -r -p 'Account email: ' email
    [[ -n "$display_name" ]] || read -r -p 'Display name: ' display_name
    if [[ -z "$password" ]]; then
        read -r -s -p 'Password (at least 12 characters): ' password
        printf '\n'
    fi
    [[ "$email" == *@*.* ]] || die 'invalid account email'
    [[ -n "$display_name" && ${#display_name} -le 100 ]] || die 'display name must contain 1 to 100 characters'
    ((${#password} >= 12)) || die 'password must contain at least 12 characters'

    local payload
    payload="$(jq -cn --arg email "$email" --arg password "$password" \
        --arg display_name "$display_name" \
        '{email:$email,password:$password,display_name:$display_name}')"
    local_public_curl --request POST --header 'Content-Type: application/json' \
        --data "$payload" "$REMOTE_API_PUBLIC_URL/v1/auth/register"
    printf '\nAccount created.\n'
}

restore_main() {
    require_root
    load_env
    local backup_file="${1:-}"
    [[ -n "$backup_file" && -r "$backup_file" ]] || die 'usage: remote-control restore /path/to/backup.dump'
    if [[ -r "$backup_file.sha256" ]]; then
        (
            cd "$(dirname "$backup_file")"
            sha256sum --check "$(basename "$backup_file").sha256"
        )
    else
        warn 'No SHA-256 sidecar was found for this backup'
    fi
    confirm 'Restore replaces the current PostgreSQL contents. Continue' \
        || die 'restore cancelled'

    local safety_backup
    safety_backup="$(backup_database | tail -n 1)"
    log "Pre-restore backup: $safety_backup"
    docker_compose stop caddy relay-server signal-server api-server
    if ! docker_compose exec -T postgres \
        pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
        --clean --if-exists --no-owner --no-privileges --single-transaction < "$backup_file"; then
        docker_compose up --detach || true
        die "restore failed; use the pre-restore backup if needed: $safety_backup"
    fi
    docker_compose up --detach
    wait_for_services || die 'restore completed but service health checks failed'
    log 'Restore completed'
}

renew_certificate_main() {
    require_root
    load_env
    case "$DEPLOY_MODE" in
        domain)
            if openssl x509 -checkend 2592000 -noout -in "$TLS_CERT_PATH" >/dev/null; then
                log 'Certificate remains valid for more than 30 days; renewal is not required'
                return 0
            fi
            install_certbot
            docker_compose stop caddy
            if ! certbot renew --non-interactive \
                --config-dir "$CERT_DIR/letsencrypt" \
                --work-dir "$CERT_DIR/letsencrypt-work" \
                --logs-dir "$CERT_DIR/letsencrypt-logs"; then
                docker_compose start caddy || true
                die 'certificate renewal failed'
            fi
            copy_letsencrypt_certificate
            docker_compose restart caddy relay-server
            wait_for_services || die 'health checks failed after certificate renewal'
            ;;
        ip_self_signed)
            if openssl x509 -checkend 2592000 -noout -in "$TLS_CERT_PATH" >/dev/null; then
                log 'Certificate remains valid for more than 30 days; renewal is not required'
                return 0
            fi
            generate_ip_certificate
            docker_compose restart caddy relay-server
            wait_for_services || die 'health checks failed after certificate renewal'
            ;;
        custom)
            die 'custom certificate mode is renewed by replacing the source certificate and running update-certificate'
            ;;
    esac
}

update_custom_certificate_main() {
    require_root
    load_env
    [[ "$DEPLOY_MODE" == "custom" ]] || die 'update-certificate is only available in custom certificate mode'
    CUSTOM_CERT_PATH="${1:-${RCTL_TLS_CERT_PATH:-}}"
    CUSTOM_KEY_PATH="${2:-${RCTL_TLS_KEY_PATH:-}}"
    CUSTOM_CA_PATH="${3:-${RCTL_CLIENT_CA_CERT_PATH:-}}"
    [[ -n "$CUSTOM_CERT_PATH" && -n "$CUSTOM_KEY_PATH" ]] \
        || die 'usage: remote-control update-certificate CERT KEY [CLIENT_CA]'
    install_custom_certificate
    docker_compose restart caddy relay-server
    wait_for_services || die 'health checks failed after certificate replacement'
}

relay_tls_check() {
    local arguments=(-connect "127.0.0.1:${RELAY_PUBLIC_PORT}" -alpn rctl-relay-v1 -verify_return_error)
    if is_domain "$PUBLIC_HOST"; then
        arguments+=(-servername "$PUBLIC_HOST" -verify_hostname "$PUBLIC_HOST")
    else
        arguments+=(-verify_ip "$PUBLIC_HOST")
    fi
    if [[ -n "${CLIENT_CA_CERT_PATH:-}" && -r "${CLIENT_CA_CERT_PATH:-}" ]]; then
        arguments+=(-CAfile "$CLIENT_CA_CERT_PATH")
    fi
    timeout 15 openssl s_client "${arguments[@]}" </dev/null >/dev/null 2>&1
}

diagnose_main() {
    require_root
    load_env
    local failures=0 ws_status
    log 'Checking Compose configuration'
    validate_compose_config || failures=$((failures + 1))
    log 'Checking containers and internal health endpoints'
    docker_compose ps || failures=$((failures + 1))
    check_internal_services || failures=$((failures + 1))
    log 'Checking public API TLS endpoint'
    local_public_curl "$REMOTE_API_PUBLIC_URL/health" >/dev/null || failures=$((failures + 1))
    log 'Checking Signal WebSocket route'
    ws_status="$(local_public_curl --output /dev/null --write-out '%{http_code}' \
        --http1.1 --header 'Connection: Upgrade' --header 'Upgrade: websocket' \
        --header 'Sec-WebSocket-Version: 13' \
        --header 'Sec-WebSocket-Key: cmVtb3RlLWNvbnRyb2w=' \
        "$REMOTE_SIGNAL_PUBLIC_URL" 2>/dev/null || true)"
    if [[ -z "$ws_status" || "$ws_status" == "000" || "$ws_status" == "502" ]]; then
        warn "Signal WebSocket route failed with HTTP ${ws_status:-000}"
        failures=$((failures + 1))
    else
        log "Signal WebSocket route responded with HTTP $ws_status"
    fi
    log 'Checking Relay TLS certificate and ALPN endpoint'
    relay_tls_check || failures=$((failures + 1))
    if ((failures > 0)); then
        die "diagnosis found $failures failed checks"
    fi
    log 'Diagnosis passed'
}

uninstall_main() {
    require_root
    load_env
    local purge=0
    [[ "${1:-}" == "--purge" ]] && purge=1
    if ((purge == 1)); then
        confirm 'This removes containers, database/Redis volumes, configuration, certificates, source, and backups. Continue' \
            || die 'uninstall cancelled'
        docker_compose down --volumes --remove-orphans
        rm -f -- "$COMMAND_LINK" "$CRON_FILE"
        [[ "$INSTALL_DIR" != "/" && ${#INSTALL_DIR} -ge 12 ]] || die 'unsafe install directory'
        rm -rf -- "$INSTALL_DIR"
        log 'Complete removal finished'
    else
        confirm 'Stop and remove application containers while retaining data, configuration, certificates, and backups' \
            || die 'uninstall cancelled'
        docker_compose down --remove-orphans
        log "Application containers removed; retained state is in $INSTALL_DIR"
        log "Run '$COMMAND_LINK start' to recreate them"
    fi
}

show_menu() {
    printf '%s\n' \
        '1) Status' \
        '2) Logs' \
        '3) Diagnose' \
        '4) Client configuration' \
        '5) Create account' \
        '6) Backup PostgreSQL' \
        '7) Update' \
        '8) Restart' \
        '9) Renew certificate' \
        '0) Exit'
    local selection
    read -r -p 'Select [0-9]: ' selection
    case "$selection" in
        1) status_main ;;
        2) logs_main ;;
        3) diagnose_main ;;
        4) print_client_config ;;
        5) create_account_main ;;
        6) backup_database ;;
        7) update_main ;;
        8) restart_main ;;
        9) renew_certificate_main ;;
        0) return 0 ;;
        *) die 'invalid menu selection' ;;
    esac
}

usage() {
    cat <<'EOF'
Usage: remote-control COMMAND [ARGUMENTS]

Commands:
  install                         Install or update the service
  update                          Back up, update source, build, and verify
  start                           Create/start containers and verify services
  stop                            Stop containers while retaining all state
  status                          Show container state and client URLs
  logs [SERVICE]                  Follow service logs
  diagnose                        Check API, Signal, Relay, PostgreSQL, and Redis
  client-config                   Print iOS/Windows build variables
  create-account                  Create the first account
  backup                          Create and hash a PostgreSQL backup
  restore FILE                    Restore a PostgreSQL custom-format backup
  restart                         Restart and verify all services
  renew-certificate               Renew managed domain/IP certificates when due
  update-certificate CERT KEY [CA]
                                  Replace a custom certificate
  uninstall [--purge]             Remove containers; --purge also removes all state
  menu                            Open the interactive management menu
  help                            Show this help
EOF
}

main() {
    validate_install_dir
    local command_name="${1:-menu}"
    case "$command_name" in
        install) shift; install_main "$@" ;;
        update) shift; update_main "$@" ;;
        start) shift; start_main "$@" ;;
        stop) shift; stop_main "$@" ;;
        status) shift; status_main "$@" ;;
        logs) shift; logs_main "$@" ;;
        diagnose) shift; diagnose_main "$@" ;;
        client-config) shift; print_client_config "$@" ;;
        create-account) shift; create_account_main "$@" ;;
        backup) shift; require_root; backup_database "$@" ;;
        restore) shift; restore_main "$@" ;;
        restart) shift; restart_main "$@" ;;
        renew-certificate) shift; renew_certificate_main "$@" ;;
        update-certificate) shift; update_custom_certificate_main "$@" ;;
        uninstall) shift; uninstall_main "$@" ;;
        menu) shift; require_root; show_menu "$@" ;;
        help | --help | -h) usage ;;
        *) usage >&2; exit 64 ;;
    esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
