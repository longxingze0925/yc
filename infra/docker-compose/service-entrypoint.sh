#!/bin/sh
set -eu

fail() {
    printf 'service entrypoint refused: %s\n' "$1" >&2
    exit 1
}

service=/usr/local/bin/service

if [ "${REMOTE_RELAY_STAGE_TLS:-}" = "1" ]; then
    [ "$(id -u)" = "0" ] || fail 'Relay TLS staging requires a root entrypoint'

    source_dir=/run/secrets/relay
    target_dir=/run/remote-control/relay-tls
    source_cert="$source_dir/relay.crt"
    source_key="$source_dir/relay.key"
    target_cert="$target_dir/relay.crt"
    target_key="$target_dir/relay.key"

    [ -r "$source_cert" ] || fail 'Relay certificate source is not readable'
    [ -r "$source_key" ] || fail 'Relay private key source is not readable'
    [ "$(stat -c '%a' "$source_key")" = "600" ] \
        || fail 'Relay private key source must have mode 0600'

    install -d -m 0700 -o 10001 -g 10001 "$target_dir"
    install -m 0644 -o 10001 -g 10001 "$source_cert" "$target_cert"
    install -m 0600 -o 10001 -g 10001 "$source_key" "$target_key"

    [ "$(stat -c '%u:%g:%a' "$target_key")" = "10001:10001:600" ] \
        || fail 'staged Relay private key ownership or mode is invalid'

    export REMOTE_RELAY_TLS_CERT_PATH=$target_cert
    export REMOTE_RELAY_TLS_KEY_PATH=$target_key
fi

if [ "$(id -u)" = "0" ]; then
    exec gosu 10001:10001 "$service" "$@"
fi

exec "$service" "$@"
