#!/usr/bin/env bash
set -Eeuo pipefail

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
repository_root="$(CDPATH= cd -- "$script_dir/.." && pwd)"
fixture_root="$(mktemp -d)"
cleanup() {
    rm -rf -- "$fixture_root"
}
trap cleanup EXIT INT TERM

export RCTL_INSTALL_DIR="$fixture_root/remote-control"
export RCTL_COMMAND_LINK="$fixture_root/bin/remote-control"
export RCTL_CRON_FILE="$fixture_root/remote-control-cert-renew"
export RCTL_ALLOW_NON_ROOT=1

# shellcheck disable=SC1091
source "$script_dir/remotectl.sh"

mkdir -p "$CONFIG_DIR" "$CERT_DIR" "$BACKUP_DIR"
DEPLOY_MODE=ip_self_signed
PUBLIC_HOST=203.0.113.10
PUBLIC_HTTP_PORT=8080
PUBLIC_HTTPS_PORT=8443
RELAY_PUBLIC_PORT=18082
PUBLIC_HTTPS_REDIRECT_SUFFIX=:8443
generate_ip_certificate >/dev/null 2>&1
write_environment

openssl verify -CAfile "$CERT_DIR/root-ca.crt" "$CERT_DIR/server.crt" >/dev/null
openssl x509 -in "$CERT_DIR/server.crt" -noout -checkip "$PUBLIC_HOST" >/dev/null
[[ "$(stat -c '%a' "$CERT_DIR/server.key")" == "600" ]]
[[ "$(stat -c '%a' "$ENV_FILE")" == "600" ]]

set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a
[[ "$REMOTE_API_PUBLIC_URL" == "https://203.0.113.10:8443" ]]
[[ "$REMOTE_SIGNAL_PUBLIC_URL" == "wss://203.0.113.10:8443/ws" ]]
[[ "$REMOTE_RELAY_PUBLIC_URL" == "203.0.113.10:18082" ]]
[[ ${#REMOTE_MFA_SECRET_KEY} -eq 43 ]]

docker compose --env-file "$ENV_FILE" \
    --file "$repository_root/infra/production/compose.yml" config --quiet

printf 'production deployment smoke test passed\n'
