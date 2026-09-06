#!/bin/sh

set -eu

acknowledgement="${PERIAPSIS_PERFORMANCE_CI_ACKNOWLEDGEMENT:-}"
if [ "$acknowledgement" != "disposable-container-postgres-18.6" ]; then
  echo "performance CI acknowledgement is missing" >&2
  exit 64
fi

if [ "$(id -u)" != 10001 ] || [ "$(id -g)" != 10001 ] || [ ! -x /usr/local/bin/node ] || [ ! -x /usr/local/bin/psql ]; then
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

evidence_directory="/workspace/tmp/performance"
if [ ! -d "$evidence_directory" ] || [ ! -w "$evidence_directory" ]; then
  echo "performance CI requires a writable evidence mount for UID/GID 10001" >&2
  exit 69
fi

umask 077
data_directory="$(mktemp -d /tmp/periapsis-performance-pg-XXXXXXXXXX)"
port=55432
server_start_attempted=false
gate_pid=""

chmod 0700 "$data_directory"

stop_server() {
  if [ "$server_start_attempted" = true ]; then
    if pg_ctl -D "$data_directory" status >/dev/null 2>&1; then
      pg_ctl -D "$data_directory" -m fast -w stop
    else
      # pg_ctl status returns 3 only when this exact cluster is not running.
      status=$?
      if [ "$status" -ne 3 ]; then
        return "$status"
      fi
    fi
  fi
}

finish_gate() {
  exit_status=$?
  trap - EXIT
  trap '' INT TERM
  stop_server || {
    stop_status=$?
    if [ "$exit_status" -eq 0 ]; then
      exit_status=$stop_status
    fi
  }
  exit "$exit_status"
}

terminate_gate() {
  signal="$1"
  trap '' INT TERM
  if [ -n "$gate_pid" ] && kill -0 "$gate_pid" 2>/dev/null; then
    kill "-$signal" "$gate_pid" 2>/dev/null || true
    wait "$gate_pid" 2>/dev/null || true
  fi
  if [ "$signal" = INT ]; then
    exit 130
  fi
  exit 143
}

trap 'terminate_gate INT' INT
trap 'terminate_gate TERM' TERM
trap finish_gate EXIT

initdb \
  -D "$data_directory" \
  -U postgres \
  -A trust \
  --no-locale \
  --encoding=UTF8 >/dev/null

# A failed pg_ctl wait can still leave its server alive; the EXIT trap probes it.
server_start_attempted=true
pg_ctl \
  -D "$data_directory" \
  -l "$data_directory/postgres.log" \
  -o "-p $port -c listen_addresses=127.0.0.1 -c timezone=UTC -c unix_socket_directories=$data_directory" \
  -w start

set +e
env \
  PERIAPSIS_PERFORMANCE_ADMIN_URL="postgresql://postgres@127.0.0.1:$port/postgres?sslmode=disable" \
  PERIAPSIS_PERFORMANCE_EXPECTED_DATA_DIRECTORY="$data_directory" \
  PERIAPSIS_PERFORMANCE_PSQL=/usr/local/bin/psql \
  node scripts/performance/run-ticketing-hot-paths.mjs &
gate_pid=$!
wait "$gate_pid"
gate_status=$?
gate_pid=""
set -e

exit "$gate_status"
