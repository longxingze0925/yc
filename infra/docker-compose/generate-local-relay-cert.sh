#!/bin/sh
set -eu
umask 077

output_dir=${1:-/tmp/remote-control-relay-tls}
mkdir -p "$output_dir"

openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 30 \
    -subj '/CN=relay-server' \
    -addext 'subjectAltName=DNS:relay-server,DNS:localhost,IP:127.0.0.1' \
    -keyout "$output_dir/relay.key" \
    -out "$output_dir/relay.crt"
chmod 0644 "$output_dir/relay.crt"
chmod 0600 "$output_dir/relay.key"
printf 'local Relay certificate written to %s/relay.crt\n' "$output_dir"
printf 'local Relay private key written to %s/relay.key (mode 0600)\n' "$output_dir"
