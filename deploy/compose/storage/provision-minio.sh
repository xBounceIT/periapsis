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
[ "$bucket" = "periapsis-evidence" ] || exit 1

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

# Per-bucket CORS is unsupported by the pinned local MinIO. The loopback TLS
# edge owns the exact browser policy; this service only provisions S3 resources.
/usr/local/bin/mc --config-dir /tmp/minio-client stat "local/$bucket" >/dev/null
