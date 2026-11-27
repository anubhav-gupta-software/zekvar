#!/usr/bin/env bash
set -euo pipefail
umask 077

fail() { printf '%s\n' "$*" >&2; exit 1; }

# Backup retention: delete local encrypted archives older than DAYS. Deleted Control data stays recoverable from
# every archive taken before the deletion until that archive is pruned here or expires in off-host storage.
if [[ ${1:-} == prune ]]; then
  [[ $# == 3 ]] || fail 'Usage: database-backup.sh prune DIRECTORY DAYS'
  [[ -d $2 && ! -L $2 ]] || fail 'Specify an existing backup directory.'
  [[ $3 =~ ^[1-9][0-9]{0,3}$ ]] && (( $3 <= 3650 )) || fail 'Specify a retention period from 1 to 3650 days.'
  pruned=0
  while IFS= read -r -d '' archive; do
    rm -f -- "$archive"
    pruned=$((pruned + 1))
  done < <(find "$2" -mindepth 1 -maxdepth 1 -type f -name '*.age' -mmin "+$(( $3 * 1440 ))" -print0)
  printf 'Pruned %s encrypted backups older than %s days from %s\n' "$pruned" "$3" "$2"
  exit
fi

if [[ $# != 5 || ( $1 != backup && $1 != restore ) ]]; then
  printf '%s\n' \
    'Usage: database-backup.sh backup PROJECT ENV_FILE ARCHIVE.age RECIPIENTS_FILE' \
    '       database-backup.sh restore PROJECT ENV_FILE ARCHIVE.age IDENTITY_FILE' \
    '       database-backup.sh prune DIRECTORY DAYS' >&2
  exit 2
fi

action=$1
project=$2
env_file=$3
archive=$4
keys=$5
[[ $project =~ ^[a-z0-9][a-z0-9_-]*$ ]] || fail 'Specify a valid Compose project name.'
[[ $archive == *.age ]] || fail 'Specify a backup archive ending in .age.'
[[ -f $env_file && -r $env_file ]] || fail 'The Compose environment file must be readable.'
[[ -f $keys && -r $keys ]] || fail 'The age key file must be readable.'
command -v age >/dev/null || fail 'Install age on the operator host.'
pilot_dir=$(cd -- "$(dirname -- "$0")" && pwd -P)
compose=(docker compose --project-name "$project" --env-file "$env_file" --file "$pilot_dir/compose.yaml")

postgres() {
  "${compose[@]}" exec -T postgres "$@"
}

database() {
  postgres sh -ec '
    export PGPASSWORD="${ZEKVAR_POSTGRES_APP_PASSWORD:?}" PGCONNECT_TIMEOUT=5
    program=$1
    shift
    exec "$program" --host=127.0.0.1 --username=zekvar_app --dbname="$POSTGRES_DB" --no-password "$@"
  ' sh "$@"
}

scratch=''
cleanup() {
  if [[ -n $scratch ]]; then
    rm -r -- "$scratch"
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if [[ $action == backup ]]; then
  directory=$(cd -- "$(dirname -- "$archive")" && pwd -P) || fail 'Create the destination directory first.'
  filename=$(basename -- "$archive")
  [[ ! -e $directory/$filename && ! -L $directory/$filename ]] || fail 'The backup destination already exists.'
  initialized=$(database psql -XAt -v ON_ERROR_STOP=1 -c "SELECT to_regclass('public.schema_migrations') IS NOT NULL" </dev/null)
  [[ $initialized == t ]] || fail 'The source is missing the Control schema.'
  scratch=$(mktemp -d "$directory/.zekvar-backup.XXXXXXXX")
  if ! database pg_dump --format=custom --no-owner --no-privileges </dev/null | age --encrypt -R "$keys" >"$scratch/$filename"; then
    fail 'The backup failed. No archive was published.'
  fi
  # Linking by basename publishes the completed file and refuses a concurrent destination.
  ln -- "$scratch/$filename" "$directory/" || fail 'Could not publish the backup at the requested path.'
  printf 'Encrypted backup saved to %s\n' "$directory/$filename"
  exit
fi

[[ -f $archive && -r $archive ]] || fail 'The backup archive must be readable.'
containers=$("${compose[@]}" ps --all --format '{{.Service}}:{{.State}}:{{.Health}}')
[[ $containers == postgres:running:healthy ]] || fail 'Use a separate recovery project with only a healthy postgres container.'

scratch=$(mktemp -d "${TMPDIR:-/tmp}/zekvar-restore.XXXXXXXX")
cp -- "$archive" "$scratch/source.age"
# Authenticate the complete encrypted snapshot before sending restore commands to PostgreSQL.
age --decrypt -i "$keys" "$scratch/source.age" >/dev/null || fail 'The backup could not be decrypted and verified.'

restore_sql() {
  cat <<'SQL'
BEGIN;
DO $$
BEGIN
    -- Control initialization also takes this lock.
    PERFORM pg_advisory_xact_lock(52824960);
    IF EXISTS (SELECT FROM pg_class WHERE relnamespace = 'public'::regnamespace)
        OR EXISTS (SELECT FROM pg_proc WHERE pronamespace = 'public'::regnamespace)
        OR EXISTS (SELECT FROM pg_namespace WHERE nspname NOT IN ('public', 'information_schema') AND left(nspname, 3) <> 'pg_') THEN
        RAISE EXCEPTION 'The target database already contains application objects.';
    END IF;
END;
$$;
SQL
  # An incomplete stream leaves this transaction open and psql rolls it back on disconnect.
  if ! age --decrypt -i "$keys" "$scratch/source.age" | postgres pg_restore --file=- --no-owner --no-privileges; then
    return 1
  fi
  cat "$pilot_dir/recover-access.sql"
}

if ! restore_sql | database psql -Xq -v ON_ERROR_STOP=1; then
  fail 'The restore failed. Review the PostgreSQL error before retrying.'
fi
printf 'Restored the database for %s. Keep this environment isolated while verifying recovery.\n' "$project"
