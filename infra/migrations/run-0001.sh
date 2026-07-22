#!/bin/sh
set -eu

usage() {
    printf 'usage: %s --dry-run|--apply\n' "$0" >&2
    exit 64
}

fail() {
    printf 'schema migration refused: %s\n' "$1" >&2
    exit 1
}

[ "$#" -eq 1 ] || usage
mode=$1
case "$mode" in
    --dry-run | --apply) ;;
    *) usage ;;
esac

[ "${SCHEMA_FREEZE_CONFIRMED:-}" = "1" ] || fail 'SCHEMA_FREEZE_CONFIRMED=1 is required'
[ "${SCHEMA_TARGET_EMPTY_CONFIRMED:-}" = "1" ] || fail 'SCHEMA_TARGET_EMPTY_CONFIRMED=1 is required'
[ -n "${DATABASE_URL:-}" ] || fail 'DATABASE_URL is required'

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
migration="$script_dir/0001_initial_schema.sql"
psql_bin=${PSQL_BIN:-psql}

command -v "$psql_bin" >/dev/null 2>&1 || fail "psql executable not found: $psql_bin"
head -n 1 "$migration" | grep -qx -- '-- SCHEMA_FREEZE_STATUS=FINAL' \
    || fail '0001 is not marked SCHEMA_FREEZE_STATUS=FINAL'
if grep -Eq '^-- SCHEMA_FREEZE_STATUS=(DRAFT|SKELETON)$' "$migration"; then
    fail '0001 still contains a draft or skeleton marker'
fi
tail -n 1 "$migration" | grep -qx 'COMMIT;' || fail '0001 must end with COMMIT;'

existing_relations=$("$psql_bin" "$DATABASE_URL" -X -v ON_ERROR_STOP=1 -Atqc \
    "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'v', 'm', 'f');")
[ "$existing_relations" = "0" ] || fail "target public schema is not empty ($existing_relations relations)"

if [ "$mode" = "--dry-run" ]; then
    sed '$s/^COMMIT;$/ROLLBACK;/' "$migration" \
        | "$psql_bin" "$DATABASE_URL" -X -v ON_ERROR_STOP=1 -f -
    printf 'schema dry-run passed: transaction rolled back; no schema changes persisted\n'
else
    "$psql_bin" "$DATABASE_URL" -X -v ON_ERROR_STOP=1 -f "$migration"
    printf 'schema apply passed: 0001_initial_schema.sql committed\n'
fi
