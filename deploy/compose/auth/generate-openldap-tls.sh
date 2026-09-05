#!/bin/sh

set -eu
umask 077

target=/tls

valid_material() {
  directory=$1
  [ -s "$directory/ca.crt" ] &&
    [ -s "$directory/server.crt" ] &&
    [ -s "$directory/server.key" ] || return 1
  [ "$(stat -c %a "$directory/server.key" 2>/dev/null)" = 400 ] || return 1
  openssl verify -CAfile "$directory/ca.crt" "$directory/server.crt" >/dev/null 2>&1 || return 1
  openssl x509 -checkend 86400 -noout -in "$directory/server.crt" >/dev/null 2>&1 || return 1
  openssl x509 -checkhost openldap -noout -in "$directory/server.crt" >/dev/null 2>&1 || return 1
  certificate_modulus=$(openssl x509 -noout -modulus -in "$directory/server.crt" 2>/dev/null) || return 1
  private_modulus=$(openssl rsa -noout -modulus -in "$directory/server.key" 2>/dev/null) || return 1
  [ "$certificate_modulus" = "$private_modulus" ]
}

if valid_material "$target"; then
  exit 0
fi

work=$(mktemp -d)
cleanup() {
  rm -f \
    "$work/ca.crt" "$work/ca.key" "$work/ca.srl" \
    "$work/server.crt" "$work/server.csr" "$work/server.key"
  rmdir "$work" 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

openssl req -x509 -newkey rsa:3072 -nodes -sha256 -days 30 \
  -subj "/CN=Periapsis local LDAP test CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -keyout "$work/ca.key" -out "$work/ca.crt" >/dev/null 2>&1

openssl req -newkey rsa:3072 -nodes -sha256 \
  -subj "/CN=openldap" \
  -addext "subjectAltName=DNS:openldap" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth" \
  -keyout "$work/server.key" -out "$work/server.csr" >/dev/null 2>&1

openssl x509 -req -sha256 -days 30 -copy_extensions copy \
  -in "$work/server.csr" -CA "$work/ca.crt" -CAkey "$work/ca.key" \
  -CAcreateserial -out "$work/server.crt" >/dev/null 2>&1

openssl verify -CAfile "$work/ca.crt" "$work/server.crt" >/dev/null
chmod 0444 "$work/ca.crt" "$work/server.crt"
chmod 0400 "$work/server.key"
mv "$work/ca.crt" "$work/server.crt" "$work/server.key" "$target/"

if ! valid_material "$target"; then
  echo "generated LDAP TLS material failed validation" >&2
  exit 1
fi
