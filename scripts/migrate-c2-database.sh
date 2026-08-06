#!/usr/bin/env bash
set -euo pipefail

EXECUTE=0
RUNTIME="${C2_ANALYZER_RUNTIME:-${WINSTDT_ROOT:-/srv/winstdt}/libexec/c2-exfil/current}"

usage() { echo 'Usage: scripts/migrate-c2-database.sh [--execute]'; }
while [ "$#" -gt 0 ]; do
  case "$1" in
    --execute) EXECUTE=1 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
  shift
done

if [ "$EXECUTE" -eq 0 ]; then
  echo "[c2-db] would apply schema v3 migration from runtime: $RUNTIME"
  exit 0
fi
test -n "${DATABASE_URL:-}" || { echo 'DATABASE_URL is required' >&2; exit 1; }
schema_root="$RUNTIME/source/sql"
test -f "$schema_root/schema.sql" || { echo 'installed C2 database schema is unavailable' >&2; exit 1; }
present="$(psql "$DATABASE_URL" -Atqc "SELECT to_regclass('public.schema_versions') IS NOT NULL")"
if [ "$present" != t ]; then
  psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f "$schema_root/schema.sql"
else
  version="$(psql "$DATABASE_URL" -Atqc "SELECT version FROM schema_versions WHERE component='c2-exfil'")"
  case "$version" in
    1)
      psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f "$schema_root/migrations/002_winstdt_compat.sql"
      psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f "$schema_root/migrations/003_upstream_1_2.sql"
      ;;
    2) psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f "$schema_root/migrations/003_upstream_1_2.sql" ;;
    3) ;;
    *) echo "unsupported C2 database schema version: ${version:-missing}" >&2; exit 1 ;;
  esac
fi
version="$(psql "$DATABASE_URL" -Atqc "SELECT version FROM schema_versions WHERE component='c2-exfil'")"
test "$version" = 3 || { echo "C2 database schema verification failed: ${version:-missing}" >&2; exit 1; }
echo '[c2-db] schema version 3 verified'
