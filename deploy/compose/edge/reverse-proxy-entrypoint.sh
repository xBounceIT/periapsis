#!/bin/sh
set -eu

# Caddy accepts space-separated peers; application configuration uses commas.
# Admit only IP/CIDR characters before tokenization, never evaluate input as code.
case "${PERIAPSIS_WEB_TRUSTED_PROXY_CIDRS:-}" in
  ''|*[!0-9a-fA-F:.,/]*|,*|*,|*,,*)
    printf '%s\n' 'Configure explicit external proxy IP/CIDR peers.' >&2
    exit 1
    ;;
esac
PERIAPSIS_CADDY_TRUSTED_PROXY_CIDRS=$(printf '%s' "$PERIAPSIS_WEB_TRUSTED_PROXY_CIDRS" | tr ',' ' ')
for peer in $PERIAPSIS_CADDY_TRUSTED_PROXY_CIDRS; do
  case "$peer" in
    */0*)
      printf '%s\n' 'Universal external proxy CIDRs are forbidden.' >&2
      exit 1
      ;;
  esac
done
export PERIAPSIS_CADDY_TRUSTED_PROXY_CIDRS
exec caddy run --config /etc/caddy/Caddyfile --adapter caddyfile
