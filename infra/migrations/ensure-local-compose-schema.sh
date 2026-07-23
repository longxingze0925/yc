#!/bin/sh
set -eu

fail() {
    printf 'local compose migration refused: %s\n' "$1" >&2
    exit 1
}

[ "${REMOTE_LOCAL_COMPOSE_MIGRATION:-}" = "1" ] \
    || fail 'REMOTE_LOCAL_COMPOSE_MIGRATION=1 is required'
[ "${PGHOST:-}" = "postgres" ] || fail 'PGHOST must be the compose postgres service'
[ "${PGPORT:-}" = "5432" ] || fail 'PGPORT must be the internal PostgreSQL port'
[ -n "${PGDATABASE:-}" ] || fail 'PGDATABASE is required'
[ -n "${PGUSER:-}" ] || fail 'PGUSER is required'
[ -n "${DATABASE_URL:-}" ] || fail 'DATABASE_URL is required by the frozen runner'

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
identity_sql="SELECT concat_ws('|', system_identifier::text, current_database(), current_user, COALESCE(inet_server_port()::text, '')) FROM pg_control_system();"

if ! pg_identity=$(psql -X -w -v ON_ERROR_STOP=1 -Atqc "$identity_sql"); then
    fail 'cannot identify the Compose PostgreSQL through PGHOST/PGPORT/PGDATABASE/PGUSER'
fi
if ! url_identity=$(psql "$DATABASE_URL" -X -w -v ON_ERROR_STOP=1 -Atqc "$identity_sql"); then
    fail 'cannot identify the DATABASE_URL PostgreSQL target'
fi
[ "$pg_identity" = "$url_identity" ] \
    || fail 'DATABASE_URL does not match the Compose PostgreSQL instance, database, user, and port'

existing_relations=$(psql -X -w -v ON_ERROR_STOP=1 -Atqc \
    "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','f');")

if [ "$existing_relations" = "0" ]; then
    /bin/sh "$script_dir/run-0001.sh" --apply
else
    psql -X -w -v ON_ERROR_STOP=1 -f "$script_dir/verify-0001.sql"
    printf 'local compose schema already matches the frozen V1 structure\n'
fi
