#!/bin/sh
set -eu

umask 077

read_secret() {
  secret_file=$1
  [ -f "$secret_file" ] || exit 1
  secret_value=$(tr -d '\r\n' < "$secret_file")
  [ -n "$secret_value" ] || exit 1
  case "$secret_value" in
    *[!A-Za-z0-9._~-]*) exit 1 ;;
  esac
  printf '%s' "$secret_value"
}

root_user=$(read_secret /run/secrets/minio_root_user)
root_password=$(read_secret /run/secrets/minio_root_password)
access_key=$(read_secret /run/secrets/minio_access_key)
secret_key=$(read_secret /run/secrets/minio_secret_key)

bucket=${PERIAPSIS_S3_BUCKET:-}
origin=${PERIAPSIS_DFIR_CORS_ORIGIN:-}
[ "$bucket" = "periapsis-evidence" ] || exit 1
case "$origin" in
  https://localhost:[0-9]*) ;;
  *) exit 1 ;;
esac
origin_port=${origin#https://localhost:}
case "$origin_port" in
  ''|*[!0-9]*|0*) exit 1 ;;
esac
[ "${#origin_port}" -le 5 ] || exit 1
[ "$origin_port" -ge 1024 ] && [ "$origin_port" -le 65535 ] || exit 1

mkdir -p /tmp/minio-client
/usr/local/bin/mc --config-dir /tmp/minio-client alias set local http://minio:9000 "$root_user" "$root_password" >/dev/null
/usr/local/bin/mc --config-dir /tmp/minio-client mb --ignore-existing "local/$bucket" >/dev/null
/usr/local/bin/mc --config-dir /tmp/minio-client version enable "local/$bucket" >/dev/null

printf '%s\n' \
  '{' \
  '  "Version": "2012-10-17",' \
  '  "Statement": [' \
  '    {' \
  '      "Effect": "Allow",' \
  '      "Action": ["s3:GetBucketLocation", "s3:ListBucket"],' \
  "      \"Resource\": [\"arn:aws:s3:::$bucket\"]" \
  '    },' \
  '    {' \
  '      "Effect": "Allow",' \
  '      "Action": ["s3:ListBucketVersions"],' \
  "      \"Resource\": [\"arn:aws:s3:::$bucket\"]," \
  '      "Condition": {' \
  '        "StringLike": {' \
  '          "s3:prefix": ["????????-????-7???-????-????????????/????????-????-7???-????-????????????"]' \
  '        }' \
  '      }' \
  '    },' \
  '    {' \
  '      "Effect": "Allow",' \
  '      "Action": ["s3:DeleteObject", "s3:GetObject", "s3:PutObject"],' \
  "      \"Resource\": [\"arn:aws:s3:::$bucket/*\"]" \
  '    },' \
  '    {' \
  '      "Effect": "Allow",' \
  '      "Action": ["s3:DeleteObjectVersion"],' \
  "      \"Resource\": [\"arn:aws:s3:::$bucket/????????-????-7???-????-????????????/????????-????-7???-????-????????????\"]" \
  '    }' \
  '  ]' \
  '}' > /tmp/dfir-policy.json

/usr/local/bin/mc --config-dir /tmp/minio-client admin policy create local periapsis-dfir /tmp/dfir-policy.json >/dev/null
/usr/local/bin/mc --config-dir /tmp/minio-client admin user add local "$access_key" "$secret_key" >/dev/null
/usr/local/bin/mc --config-dir /tmp/minio-client admin policy attach local periapsis-dfir --user "$access_key" >/dev/null

printf '%s\n' \
  '<CORSConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">' \
  '  <CORSRule>' \
  "    <AllowedOrigin>$origin</AllowedOrigin>" \
  '    <AllowedMethod>GET</AllowedMethod>' \
  '    <AllowedMethod>HEAD</AllowedMethod>' \
  '    <AllowedMethod>PUT</AllowedMethod>' \
  '    <AllowedHeader>Cache-Control</AllowedHeader>' \
  '    <AllowedHeader>Content-Disposition</AllowedHeader>' \
  '    <AllowedHeader>Content-Length</AllowedHeader>' \
  '    <AllowedHeader>Content-Type</AllowedHeader>' \
  '    <AllowedHeader>If-None-Match</AllowedHeader>' \
  '    <AllowedHeader>X-Amz-Meta-Periapsis-Declared-Mime</AllowedHeader>' \
  '    <AllowedHeader>X-Amz-Meta-Periapsis-Expected-Size</AllowedHeader>' \
  '    <ExposeHeader>ETag</ExposeHeader>' \
  '    <MaxAgeSeconds>300</MaxAgeSeconds>' \
  '  </CORSRule>' \
  '</CORSConfiguration>' > /tmp/cors.xml

/usr/local/bin/mc --config-dir /tmp/minio-client cors set "local/$bucket" /tmp/cors.xml >/dev/null
/usr/local/bin/mc --config-dir /tmp/minio-client stat "local/$bucket" >/dev/null
