#!/usr/bin/env bash

# Fixed-purpose auth-test/full fixture, not a general-purpose LDAP image.
# Functions take explicit paths so the same bootstrap is exercised without Docker.
set -euo pipefail
set +x
set +a
umask 077

ldap_fail() {
  printf 'PERIAPSIS_OPENLDAP_ERROR stage=%s\n' "$1" >&2
  return 1
}

ldap_owned_directory() {
  [[ -d $1 && ! -L $1 && $(stat -c '%u:%g:%a' "$1") == 10001:10001:700 ]]
}

ldap_private_file() {
  [[ -f $1 && ! -L $1 && $(stat -c '%u:%g:%a' "$1") == 10001:10001:600 ]]
}

ldap_bootstrap() (
  local storage=$1 runtime=$2 assets=$3 password_file=$4 schema=$5 tls=$6
  local work hash entry
  export -n hash
  [[ $(id -u) == 10001 && $(id -g) == 10001 ]] || ldap_fail identity
  ldap_owned_directory "$storage" && ldap_owned_directory "$runtime" || ldap_fail storage
  [[ -f $password_file && ! -L $password_file && -s $password_file &&
     $(stat -c '%s' "$password_file") -le 65536 ]] || ldap_fail password_file
  # Match prepare-compose-secrets' exact single-line bytes; never let a tool's
  # newline handling silently change the password used by the bind healthcheck.
  [[ $(LC_ALL=C tr -d '\000\r\n' <"$password_file" | wc -c) -eq $(stat -c '%s' "$password_file") ]] || ldap_fail password_file
  for entry in ca.crt server.crt server.key; do
    [[ -f $tls/$entry && ! -L $tls/$entry && -r $tls/$entry && -s $tls/$entry ]] || ldap_fail tls
  done
  [[ $(stat -c '%u:%g:%a' "$tls/server.key") == 10001:10001:400 ]] || ldap_fail tls
  [[ -z $(find "$storage" -type l -print -quit) ]] || ldap_fail storage

  work=$(mktemp -d "$runtime/bootstrap.XXXXXXXX") || ldap_fail storage
  trap 'rm -f "$work/config.ldif"; rmdir "$work"' EXIT

  if [[ -e $storage/initialized ]]; then
    ldap_private_file "$storage/initialized" &&
      [[ $(<"$storage/initialized") == periapsis-openldap-test-v1 ]] &&
      ldap_private_file "$storage/rootpw" &&
      ldap_owned_directory "$storage/config" &&
      ldap_owned_directory "$storage/data" || ldap_fail existing_state
    # Retain the initial password hash. The real TLS/admin bind healthcheck uses
    # the mounted password and rejects a changed mount without rotating data.
    hash=$(<"$storage/rootpw")
    [[ $hash =~ ^\{SSHA\}[A-Za-z0-9+/]+={0,2}$ && ${#hash} -le 128 ]] || ldap_fail existing_state
    unset hash
  else
    # Refuse legacy, partial, or foreign state. Never erase/reseed a volume.
    [[ -z $(find "$storage" -mindepth 1 -maxdepth 1 -print -quit) ]] || ldap_fail existing_state
    mkdir "$storage/config" "$storage/data" || ldap_fail storage
    hash=$(slappasswd -h '{SSHA}' -T "$password_file" 2>/dev/null) || ldap_fail password_hash
    [[ $hash =~ ^\{SSHA\}[A-Za-z0-9+/]+={0,2}$ && ${#hash} -le 128 ]] || ldap_fail password_hash
    printf '%s\n' "$hash" >"$storage/rootpw"
    unset hash
    {
      cat "$assets/openldap-config.ldif"
      printf '\n'
      for entry in core cosine inetorgperson; do
        cat "$schema/$entry.ldif"
        printf '\n'
      done
      printf '%s\n' "$(<"$assets/openldap-database.ldif")"
      # This attribute must stay in the final MDB entry, not a new LDIF record.
      printf 'olcRootPW: %s\n\n' "$(<"$storage/rootpw")"
    } >"$work/config.ldif"
    slapadd -n 0 -F "$storage/config" -l "$work/config.ldif" >/dev/null 2>&1 || ldap_fail config_import
    slapadd -n 1 -F "$storage/config" -l "$assets/openldap-tree.ldif" >/dev/null 2>&1 || ldap_fail tree_import
    slaptest -u -F "$storage/config" >/dev/null 2>&1 || ldap_fail config_validation
    printf '%s\n' periapsis-openldap-test-v1 >"$storage/initialized"
  fi
  slaptest -u -F "$storage/config" >/dev/null 2>&1 || ldap_fail config_validation
)

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  export PATH=/usr/sbin:/usr/bin:/sbin:/bin
  readonly ldap_storage_root=/var/lib/periapsis-ldap
  readonly ldap_runtime_root=/run/periapsis-ldap
  [[ ${LDAP_INIT_ROOT_USER_PW_FILE:-} == /run/secrets/ldap-admin-password &&
     ${LDAP_TLS_ENABLED:-} == true && ${LDAP_LDAPS_ENABLED:-} == true &&
     ${LDAP_TLS_SSF:-} == 128 ]] || ldap_fail settings
  ldap_bootstrap "$ldap_storage_root" "$ldap_runtime_root" /usr/local/share/periapsis-ldap \
    /run/secrets/ldap-admin-password /etc/ldap/schema /run/secrets/ldap
  printf 'PERIAPSIS_OPENLDAP_READY_TO_START\n'
  exec slapd -d 0 -F "$ldap_storage_root/config" -h 'ldap://0.0.0.0:1389/ ldaps://0.0.0.0:1636/' >/dev/null 2>&1
fi
