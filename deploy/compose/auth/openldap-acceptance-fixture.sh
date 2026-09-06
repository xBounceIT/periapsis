#!/bin/sh

set -eu

readonly directory_uri="ldaps://openldap:1636"
readonly directory_root="DC=periapsis,DC=test"
readonly administrator_dn="uid=admin,${directory_root}"
readonly administrator_password_file="/run/secrets/ldap-admin-password"
readonly people_dn="ou=people,${directory_root}"
readonly groups_dn="ou=groups,${directory_root}"
readonly user_dn="uid=soc-l2-user,${people_dn}"
readonly second_user_dn="uid=soc-l2-user-two,${people_dn}"
readonly group_dn="cn=SOC-L2,${groups_dn}"
readonly customer_user_dn="uid=customer-user,${people_dn}"
readonly customer_group_dn="cn=CUSTOMER,${groups_dn}"
readonly isolation_user_dn="uid=globex-user,${people_dn}"
readonly isolation_group_dn="cn=GLOBEX,${groups_dn}"

temporary_directory=""

cleanup() {
  if [ -n "${temporary_directory}" ] && [ -d "${temporary_directory}" ]; then
    rm -f \
      "${temporary_directory}/password" \
      "${temporary_directory}/entries.ldif" \
      "${temporary_directory}/ldapsearch-error"
    rmdir "${temporary_directory}" 2>/dev/null || true
  fi
}

trap cleanup EXIT HUP INT TERM

ldap_search() {
  ldapsearch -x -H "${directory_uri}" -D "${administrator_dn}" \
    -y "${administrator_password_file}" "$@"
}

ldap_add() {
  ldapadd -x -H "${directory_uri}" -D "${administrator_dn}" \
    -y "${administrator_password_file}" "$@"
}

ldap_delete() {
  ldapdelete -x -H "${directory_uri}" -D "${administrator_dn}" \
    -y "${administrator_password_file}" "$@"
}

entry_exists() {
  if ldap_search -LLL -s base -b "$1" '(objectClass=*)' dn \
    >/dev/null 2>"${temporary_directory}/ldapsearch-error"; then
    rm -f "${temporary_directory}/ldapsearch-error"
    return 0
  else
    ldap_status=$?
  fi
  if [ "${ldap_status}" -eq 32 ]; then
    rm -f "${temporary_directory}/ldapsearch-error"
    return 1
  fi
  echo "LDAP lookup failed for $1" >&2
  cat "${temporary_directory}/ldapsearch-error" >&2
  rm -f "${temporary_directory}/ldapsearch-error"
  return "${ldap_status}"
}

delete_if_present() {
  if entry_exists "$1"; then
    ldap_delete "$1" >/dev/null
    return
  else
    entry_status=$?
  fi
  [ "${entry_status}" -eq 1 ] || return "${entry_status}"
}

ensure_organizational_unit() {
  organizational_unit_dn="$1"
  organizational_unit_name="$2"
  if entry_exists "${organizational_unit_dn}"; then
    return
  else
    entry_status=$?
  fi
  [ "${entry_status}" -eq 1 ] || return "${entry_status}"

  printf '%s\n' \
    "dn: ${organizational_unit_dn}" \
    'objectClass: organizationalUnit' \
    "ou: ${organizational_unit_name}" \
    '' >"${temporary_directory}/entries.ldif"
  ldap_add -f "${temporary_directory}/entries.ldif" >/dev/null
}

provision() {
  : "${PERIAPSIS_LDAP_ACCEPTANCE_USER_PASSWORD:?set PERIAPSIS_LDAP_ACCEPTANCE_USER_PASSWORD in the acceptance process environment}"
  : "${PERIAPSIS_LDAP_ACCEPTANCE_SECOND_USER_PASSWORD:?set PERIAPSIS_LDAP_ACCEPTANCE_SECOND_USER_PASSWORD in the acceptance process environment}"
  : "${PERIAPSIS_LDAP_ACCEPTANCE_CUSTOMER_PASSWORD:?set PERIAPSIS_LDAP_ACCEPTANCE_CUSTOMER_PASSWORD in the acceptance process environment}"
  : "${PERIAPSIS_LDAP_ACCEPTANCE_ISOLATION_PASSWORD:?set PERIAPSIS_LDAP_ACCEPTANCE_ISOLATION_PASSWORD in the acceptance process environment}"
  single_line_password="$(printf '%s' "${PERIAPSIS_LDAP_ACCEPTANCE_USER_PASSWORD}" | tr -d '\r\n')"
  single_line_second_password="$(printf '%s' "${PERIAPSIS_LDAP_ACCEPTANCE_SECOND_USER_PASSWORD}" | tr -d '\r\n')"
  single_line_customer_password="$(printf '%s' "${PERIAPSIS_LDAP_ACCEPTANCE_CUSTOMER_PASSWORD}" | tr -d '\r\n')"
  single_line_isolation_password="$(printf '%s' "${PERIAPSIS_LDAP_ACCEPTANCE_ISOLATION_PASSWORD}" | tr -d '\r\n')"
  if [ "${single_line_password}" != "${PERIAPSIS_LDAP_ACCEPTANCE_USER_PASSWORD}" ]; then
    echo 'LDAP acceptance password must be one line' >&2
    exit 64
  fi
  if [ "${single_line_customer_password}" != "${PERIAPSIS_LDAP_ACCEPTANCE_CUSTOMER_PASSWORD}" ]; then
    echo 'LDAP acceptance customer password must be one line' >&2
    exit 64
  fi
  if [ "${single_line_second_password}" != "${PERIAPSIS_LDAP_ACCEPTANCE_SECOND_USER_PASSWORD}" ]; then
    echo 'LDAP acceptance second operator password must be one line' >&2
    exit 64
  fi
  if [ "${single_line_isolation_password}" != "${PERIAPSIS_LDAP_ACCEPTANCE_ISOLATION_PASSWORD}" ]; then
    echo 'LDAP acceptance isolation password must be one line' >&2
    exit 64
  fi
  if [ "${#PERIAPSIS_LDAP_ACCEPTANCE_USER_PASSWORD}" -lt 16 ] || [ "${#PERIAPSIS_LDAP_ACCEPTANCE_USER_PASSWORD}" -gt 512 ]; then
    echo 'LDAP acceptance password must contain 16 through 512 characters' >&2
    exit 64
  fi
  if [ "${#PERIAPSIS_LDAP_ACCEPTANCE_CUSTOMER_PASSWORD}" -lt 16 ] || [ "${#PERIAPSIS_LDAP_ACCEPTANCE_CUSTOMER_PASSWORD}" -gt 512 ]; then
    echo 'LDAP acceptance customer password must contain 16 through 512 characters' >&2
    exit 64
  fi
  if [ "${#PERIAPSIS_LDAP_ACCEPTANCE_SECOND_USER_PASSWORD}" -lt 16 ] || [ "${#PERIAPSIS_LDAP_ACCEPTANCE_SECOND_USER_PASSWORD}" -gt 512 ]; then
    echo 'LDAP acceptance second operator password must contain 16 through 512 characters' >&2
    exit 64
  fi
  if [ "${#PERIAPSIS_LDAP_ACCEPTANCE_ISOLATION_PASSWORD}" -lt 16 ] || [ "${#PERIAPSIS_LDAP_ACCEPTANCE_ISOLATION_PASSWORD}" -gt 512 ]; then
    echo 'LDAP acceptance isolation password must contain 16 through 512 characters' >&2
    exit 64
  fi

  temporary_directory="$(mktemp -d /tmp/periapsis-ldap-acceptance.XXXXXX)"
  chmod 0700 "${temporary_directory}"
  umask 077
  printf '%s' "${PERIAPSIS_LDAP_ACCEPTANCE_USER_PASSWORD}" >"${temporary_directory}/password"
  password_hash="$(slappasswd -T "${temporary_directory}/password")"
  printf '%s' "${PERIAPSIS_LDAP_ACCEPTANCE_SECOND_USER_PASSWORD}" >"${temporary_directory}/password"
  second_password_hash="$(slappasswd -T "${temporary_directory}/password")"
  printf '%s' "${PERIAPSIS_LDAP_ACCEPTANCE_CUSTOMER_PASSWORD}" >"${temporary_directory}/password"
  customer_password_hash="$(slappasswd -T "${temporary_directory}/password")"
  printf '%s' "${PERIAPSIS_LDAP_ACCEPTANCE_ISOLATION_PASSWORD}" >"${temporary_directory}/password"
  isolation_password_hash="$(slappasswd -T "${temporary_directory}/password")"
  rm -f "${temporary_directory}/password"

  ensure_organizational_unit "${people_dn}" people
  ensure_organizational_unit "${groups_dn}" groups

  delete_if_present "${group_dn}"
  delete_if_present "${customer_group_dn}"
  delete_if_present "${isolation_group_dn}"
  delete_if_present "${user_dn}"
  delete_if_present "${second_user_dn}"
  delete_if_present "${customer_user_dn}"
  delete_if_present "${isolation_user_dn}"

  printf '%s\n' \
    "dn: ${user_dn}" \
    'objectClass: inetOrgPerson' \
    'uid: soc-l2-user' \
    'cn: SOC L2 Analyst' \
    'sn: Analyst' \
    'givenName: SOC L2' \
    'displayName: SOC L2 Analyst' \
    'mail: soc-l2-user@periapsis.test' \
    "userPassword: ${password_hash}" \
    '' \
    "dn: ${second_user_dn}" \
    'objectClass: inetOrgPerson' \
    'uid: soc-l2-user-two' \
    'cn: SOC L2 Analyst Two' \
    'sn: Analyst Two' \
    'givenName: SOC L2' \
    'displayName: SOC L2 Analyst Two' \
    'mail: soc-l2-user-two@periapsis.test' \
    "userPassword: ${second_password_hash}" \
    '' \
    "dn: ${customer_user_dn}" \
    'objectClass: inetOrgPerson' \
    'uid: customer-user' \
    'cn: Acme Customer' \
    'sn: Customer' \
    'givenName: Acme' \
    'displayName: Acme Customer' \
    'mail: customer-user@periapsis.test' \
    "userPassword: ${customer_password_hash}" \
    '' \
    "dn: ${isolation_user_dn}" \
    'objectClass: inetOrgPerson' \
    'uid: globex-user' \
    'cn: Globex Isolation User' \
    'sn: Isolation User' \
    'givenName: Globex' \
    'displayName: Globex Isolation User' \
    'mail: globex-user@periapsis.test' \
    "userPassword: ${isolation_password_hash}" \
    '' \
    "dn: ${group_dn}" \
    'objectClass: groupOfNames' \
    'cn: SOC-L2' \
    "member: ${user_dn}" \
    "member: ${second_user_dn}" \
    '' \
    "dn: ${customer_group_dn}" \
    'objectClass: groupOfNames' \
    'cn: CUSTOMER' \
    "member: ${customer_user_dn}" \
    '' \
    "dn: ${isolation_group_dn}" \
    'objectClass: groupOfNames' \
    'cn: GLOBEX' \
    "member: ${isolation_user_dn}" \
    '' >"${temporary_directory}/entries.ldif"
  ldap_add -f "${temporary_directory}/entries.ldif" >/dev/null
  echo 'OpenLDAP acceptance operator/customer/isolation identities and groups provisioned'
}

remove_group() {
  temporary_directory="$(mktemp -d /tmp/periapsis-ldap-acceptance.XXXXXX)"
  chmod 0700 "${temporary_directory}"
  delete_if_present "${group_dn}"
  echo 'OpenLDAP acceptance SOC-L2 group removed'
}

case "${1:-}" in
  provision)
    provision
    ;;
  remove-group)
    remove_group
    ;;
  *)
    echo 'usage: openldap-acceptance-fixture provision|remove-group' >&2
    exit 64
    ;;
esac
