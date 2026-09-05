#!/bin/sh

set -eu

acknowledgement="${PERIAPSIS_PERFORMANCE_CI_ACKNOWLEDGEMENT:-}"
if [ "$acknowledgement" != "disposable-container-postgres-18.6" ]; then
  echo "performance CI acknowledgement is missing" >&2
  exit 64
fi

if [ "$(id -u)" -ne 0 ] || [ ! -x /usr/local/bin/node ] || [ ! -x /usr/local/bin/psql ]; then
  echo "performance CI runtime boundary is invalid" >&2
  exit 69
fi

case "$(postgres --version)" in
  "postgres (PostgreSQL) 18.6") ;;
  *)
    echo "performance CI requires PostgreSQL 18.6" >&2
    exit 69
    ;;
esac

data_directory="$(mktemp -d /tmp/periapsis-performance-pg-XXXXXXXXXX)"
evidence_directory="/workspace/tmp/performance"
port=55432
server_started=false
gate_pid=""

mkdir -p "$evidence_directory"
chown postgres:postgres "$data_directory" "$evidence_directory"
chmod 0700 "$data_directory"

stop_server() {
  if [ "$server_started" = true ]; then
    server_started=false
    su-exec postgres pg_ctl -D "$data_directory" -m fast -w stop
  fi
}

terminate_gate() {
  signal="$1"
  if [ -n "$gate_pid" ] && kill -0 "$gate_pid" 2>/dev/null; then
    kill "-$signal" "$gate_pid" 2>/dev/null || true
    wait "$gate_pid" 2>/dev/null || true
  fi
  stop_server || true
  if [ "$signal" = INT ]; then
    exit 130
  fi
  exit 143
}

trap 'terminate_gate INT' INT
trap 'terminate_gate TERM' TERM

su-exec postgres initdb \
  -D "$data_directory" \
  -U postgres \
  -A trust \
  --no-locale \
  --encoding=UTF8 >/dev/null

su-exec postgres pg_ctl \
  -D "$data_directory" \
  -l "$data_directory/postgres.log" \
  -o "-p $port -c listen_addresses=127.0.0.1 -c timezone=UTC" \
  -w start
server_started=true

set +e
su-exec postgres env \
  PERIAPSIS_PERFORMANCE_ADMIN_URL="postgresql://postgres@127.0.0.1:$port/postgres?sslmode=disable" \
  PERIAPSIS_PERFORMANCE_EXPECTED_DATA_DIRECTORY="$data_directory" \
  PERIAPSIS_PERFORMANCE_PSQL=/usr/local/bin/psql \
  node scripts/performance/run-ticketing-hot-paths.mjs &
gate_pid=$!
wait "$gate_pid"
gate_status=$?
gate_pid=""
set -e

stop_status=0
stop_server || stop_status=$?

if [ "$gate_status" -ne 0 ]; then
  exit "$gate_status"
fi
exit "$stop_status"
