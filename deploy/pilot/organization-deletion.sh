#!/usr/bin/env bash
set -euo pipefail
umask 077
export LC_ALL=C

fail() { printf '%s\n' "$*" >&2; exit 1; }

case ${1:-}:$# in
  verify:4|verify-file:2) ;;
  *)
    printf '%s\n' \
      'Usage: organization-deletion.sh verify PROJECT ENV_FILE DELETION_ID' \
      '       organization-deletion.sh verify-file RECEIPT.json' >&2
    exit 2 ;;
esac

command -v openssl >/dev/null || fail 'Install OpenSSL on the operator host.'

# HMAC-SHA256 of standard input with the hex receipt key, as lowercase hex.
sign() { openssl dgst -sha256 -mac HMAC -macopt "hexkey:$1" | awk '{ print $NF }'; }

valid_key() { [[ $1 =~ ^[a-f0-9]{64}$ ]] || fail 'Set the 64-character lowercase hex receipt key.'; }

if [[ $1 == verify-file ]]; then
  # Checks a receipt the owner downloaded. Requires ZEKVAR_DELETION_RECEIPT_KEY in the environment and jq.
  command -v jq >/dev/null || fail 'Install jq on the operator host.'
  key=${ZEKVAR_DELETION_RECEIPT_KEY:-}
  valid_key "$key"
  [[ -f $2 && -r $2 ]] || fail 'The receipt file must be readable.'
  expected=$(jq -er '.signature.value' "$2") || fail 'The file is not a Zekvar deletion receipt.'
  [[ $(jq -er '.signature.algorithm' "$2") == HMAC-SHA256 ]] || fail 'Unsupported receipt signature algorithm.'
  # The receipt is signed as compact JSON in its original property order, which jq -c reproduces.
  actual=$(jq -cj '.receipt' "$2" | sign "$key")
  [[ $actual == "$expected" ]] || fail 'The receipt signature does not match this key. Treat the receipt as altered.'
  printf 'Receipt signature verified deletion=%s organization=%s status=%s\n' \
    "$(jq -r '.receipt.deletionId' "$2")" "$(jq -r '.receipt.organizationId' "$2")" "$(jq -r '.receipt.status' "$2")"
  exit
fi

project=$2
env_file=$3
deletion=$4
[[ $project =~ ^[a-z0-9][a-z0-9_-]*$ ]] || fail 'Specify a valid Compose project name.'
[[ -f $env_file && -r $env_file ]] || fail 'The Compose environment file must be readable.'
[[ $deletion =~ ^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$ ]] || fail 'Specify the deletion ID from the receipt.'
key=$(sed -n 's/^ZEKVAR_DELETION_RECEIPT_KEY=//p' "$env_file" | tail -n 1)
valid_key "$key"
pilot_dir=$(cd -- "$(dirname -- "$0")" && pwd -P)
compose=(docker compose --project-name "$project" --env-file "$env_file" --file "$pilot_dir/compose.yaml")

query() {
  "${compose[@]}" exec -T postgres sh -ec '
    export PGPASSWORD="${ZEKVAR_POSTGRES_APP_PASSWORD:?}" PGCONNECT_TIMEOUT=5
    exec psql --host=127.0.0.1 --username=zekvar_app --dbname="$POSTGRES_DB" --no-password -XAtq -v ON_ERROR_STOP=1 "$@"
  ' sh "$@" </dev/null
}

status=$(query -c "SELECT status FROM organization_deletions WHERE id = '$deletion'")
[[ $status == completed ]] || fail "The deletion is not complete (status: ${status:-not found})."
organization=$(query -c "SELECT organization_id FROM organization_deletions WHERE id = '$deletion'")
receipt=$(query -c "SELECT receipt FROM organization_deletions WHERE id = '$deletion'")
stored=$(query -c "SELECT receipt_signature FROM organization_deletions WHERE id = '$deletion'")
actual=$(printf '%s' "$receipt" | sign "$key")
[[ $actual == "$stored" ]] || fail 'The stored receipt does not match its signature under this key.'

# Re-run the zero-count check across every table that has an organization_id column, including tables added since.
remaining=$(query -c "
  DO \$\$
  DECLARE table_name text; total bigint := 0; found bigint;
  BEGIN
    FOR table_name IN SELECT c.table_name FROM information_schema.columns c JOIN information_schema.tables t USING (table_schema, table_name)
      WHERE c.table_schema = 'public' AND c.column_name = 'organization_id' AND t.table_type = 'BASE TABLE'
        AND c.table_name <> 'organization_deletions'
    LOOP
      EXECUTE format('SELECT count(*) FROM %I WHERE organization_id = \$1', table_name) INTO found USING '$organization'::uuid;
      IF found > 0 THEN RAISE WARNING 'table % still holds % rows', table_name, found; END IF;
      total := total + found;
    END LOOP;
    SELECT total + count(*) INTO total FROM organizations WHERE id = '$organization'::uuid;
    PERFORM set_config('zekvar.remaining', total::text, false);
  END \$\$;
  SELECT current_setting('zekvar.remaining');" | tail -n 1)
[[ $remaining == 0 ]] || fail "Organization $organization still has $remaining rows. Do not issue the receipt."
printf '%s\n' "{\"receipt\":$receipt,\"signature\":{\"algorithm\":\"HMAC-SHA256\",\"value\":\"$stored\"}}"
printf 'Verified deletion=%s organization=%s remaining_rows=0\n' "$deletion" "$organization" >&2
