#!/usr/bin/env bash
set -euo pipefail
umask 077
export LC_ALL=C AWS_PAGER='' AWS_CLI_AUTO_PROMPT=off AWS_RETRY_MODE=standard AWS_MAX_ATTEMPTS=3

fail() { printf '%s\n' "$*" >&2; exit 1; }

case ${1:-}:$# in
  publish:4|fetch:4|check:2) ;;
  *)
    printf '%s\n' \
      'Usage: s3-backup.sh publish PROJECT ENV_FILE RECIPIENTS_FILE' \
      '       s3-backup.sh fetch OBJECT_KEY ARCHIVE.age SHA256_BASE64' \
      '       s3-backup.sh check MAX_AGE_HOURS' >&2
    exit 2 ;;
esac

bucket=${ZEKVAR_BACKUP_BUCKET:-}
owner=${ZEKVAR_BACKUP_BUCKET_OWNER:-}
prefix=${ZEKVAR_BACKUP_PREFIX:-}
[[ $bucket =~ ^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$ ]] || fail 'Set ZEKVAR_BACKUP_BUCKET to a general purpose bucket name without dots.'
[[ $owner =~ ^[0-9]{12}$ ]] || fail 'Set ZEKVAR_BACKUP_BUCKET_OWNER to the bucket owner account ID.'
[[ $prefix =~ ^[a-z0-9_-]+(/[a-z0-9_-]+)*$ && ${#prefix} -le 120 ]] || fail 'Set ZEKVAR_BACKUP_PREFIX to a dedicated backup prefix.'
command -v aws >/dev/null || fail 'Install the AWS CLI on the operator host.'

s3() {
  local operation=$1
  shift
  aws s3api "$operation" --bucket "$bucket" --expected-bucket-owner "$owner" \
    --cli-connect-timeout 10 --cli-read-timeout 60 --no-cli-pager --output text "$@"
}

checksum() { openssl dgst -sha256 -binary <"$1" | openssl base64 -A; }

timestamp_pattern='[0-9]{8}T[0-9]{6}Z'
filename_pattern="^($timestamp_pattern)-[a-f0-9]{16}\.age$"
checksum_pattern='^[A-Za-z0-9+/]{43}=$'
timestamp_format='+%Y%m%dT%H%M%SZ'
scratch=''
cleanup() {
  if [[ -n $scratch ]]; then
    rm -r -- "$scratch"
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

case $1 in
  publish)
    release=${ZEKVAR_BACKUP_RELEASE:-}
    key_id=${ZEKVAR_BACKUP_KEY_ID:-}
    [[ $release =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$ ]] || fail 'Set ZEKVAR_BACKUP_RELEASE to the deployed release ID.'
    [[ $key_id =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$ ]] || fail 'Set ZEKVAR_BACKUP_KEY_ID to the public recovery key identifier.'
    pilot_dir=$(cd -- "$(dirname -- "$0")" && pwd -P)
    started=$(date -u "$timestamp_format")
    suffix=$(openssl rand -hex 8)
    key="$prefix/$started-$suffix.age"
    scratch=$(mktemp -d "${TMPDIR:-/tmp}/zekvar-offsite.XXXXXXXX")
    archive="$scratch/backup.age"
    "$pilot_dir/database-backup.sh" backup "$2" "$3" "$archive" "$4" >/dev/null
    size=$(wc -c <"$archive" | tr -d '[:space:]')
    (( size > 0 && size <= 5000000000 )) || fail 'The encrypted archive exceeds the 5 GB single-upload limit or is empty.'
    digest=$(checksum "$archive")
    [[ $digest =~ $checksum_pattern ]] || fail 'Could not compute the encrypted archive checksum.'
    uploaded=$(s3 put-object --key "$key" --body "$archive" --content-type application/octet-stream \
      --if-none-match '*' --checksum-algorithm SHA256 --checksum-sha256 "$digest" \
      --metadata "snapshot-started-utc=$started,release=$release,recovery-key-id=$key_id" \
      --query ChecksumSHA256) || fail 'Off-host backup upload failed.'
    [[ $uploaded == "$digest" ]] || fail 'The storage service did not confirm the encrypted archive checksum.'
    printf 'Backup published bucket=%s key=%s bytes=%s sha256=%s release=%s recovery-key-id=%s snapshot-started-utc=%s\n' \
      "$bucket" "$key" "$size" "$digest" "$release" "$key_id" "$started"
    ;;
  fetch)
    key=$2
    archive=$3
    expected=$4
    [[ $key == "$prefix/"* && ${key#"$prefix/"} =~ $filename_pattern ]] || fail 'Specify an object key in the configured backup prefix.'
    [[ $archive == *.age ]] || fail 'Specify a backup archive ending in .age.'
    [[ $expected =~ $checksum_pattern ]] || fail 'Specify the SHA-256 checksum from the backup job record.'
    directory=$(cd -- "$(dirname -- "$archive")" && pwd -P) || fail 'Create the destination directory first.'
    filename=$(basename -- "$archive")
    [[ ! -e $directory/$filename && ! -L $directory/$filename ]] || fail 'The download destination already exists.'
    scratch=$(mktemp -d "$directory/.zekvar-download.XXXXXXXX")
    path="$scratch/$filename"
    remote=$(s3 get-object --key "$key" --checksum-mode ENABLED --query ChecksumSHA256 "$path") \
      || fail 'Off-host backup download failed. No archive was published.'
    actual=$(checksum "$path")
    [[ $remote == "$expected" && $actual == "$expected" ]] || fail 'The download did not match the recorded checksum. No archive was published.'
    ln -- "$path" "$directory/" || fail 'Could not publish the download at the requested path.'
    printf 'Verified encrypted backup saved to %s\n' "$directory/$filename"
    ;;
  check)
    hours=$2
    [[ $hours =~ ^[1-9][0-9]{0,2}$ ]] && (( hours <= 168 )) || fail 'Specify a freshness window between 1 and 168 hours.'
    now=$(date -u "$timestamp_format")
    cutoff=$(date -u -d "$hours hours ago" "$timestamp_format" 2>/dev/null || date -u "-v-${hours}H" "$timestamp_format")
    objects=$(s3 list-objects-v2 --prefix "$prefix/" --start-after "$prefix/$cutoff-" \
      --query 'Contents[?Size > `0`].[Key, LastModified]') || fail 'Could not check off-host backup freshness.'
    newest=''
    while IFS=$'\t' read -r key modified; do
      [[ $key == "$prefix/"* && ${key#"$prefix/"} =~ $filename_pattern ]] || continue
      started=${BASH_REMATCH[1]}
      [[ $modified =~ ^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(\.[0-9]+)?(Z|\+00:00)$ ]] || continue
      stored=${BASH_REMATCH[1]}${BASH_REMATCH[2]}${BASH_REMATCH[3]}T${BASH_REMATCH[4]}${BASH_REMATCH[5]}${BASH_REMATCH[6]}Z
      [[ $started < $cutoff || $started > $now || $stored < $cutoff ]] && continue
      if [[ $key > $newest ]]; then
        newest=$key
      fi
    done <<< "$objects"
    [[ -n $newest ]] || fail "No off-host backup within the last $hours hours."
    printf 'Off-host backup is current bucket=%s key=%s\n' "$bucket" "$newest"
    ;;
esac
