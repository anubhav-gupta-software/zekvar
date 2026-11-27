#!/usr/bin/env bash
# Verifies encryption at rest for the pilot host before PostgreSQL holds customer metadata.
# Usage: deploy/pilot/storage-preflight.sh COMPOSE_PROJECT ENV_FILE [--provider-encrypted REFERENCE]
#
# Passes when the PostgreSQL volume sits on a dm-crypt (LUKS) device. Cloud block-storage encryption is invisible
# inside the guest, so it is accepted only with --provider-encrypted naming the provider evidence (for example an
# EBS volume ID and KMS key) and is reported as "attested", not "verified". The environment file must be private
# and must define the Control data keys. Prints one JSON line and exits nonzero on failure.
set -euo pipefail

fail() {
  printf '{"status":"fail","check":"%s","detail":"%s"}\n' "$1" "$2"
  exit 1
}

[[ $# -eq 2 || ( $# -eq 4 && $3 == --provider-encrypted ) ]] ||
  fail usage "Usage: storage-preflight.sh COMPOSE_PROJECT ENV_FILE [--provider-encrypted REFERENCE]"
project=$1
env_file=$2
attestation=${4:-}
[[ $project =~ ^[a-z0-9][a-z0-9_-]{0,62}$ ]] || fail usage "Use a Compose project name of lowercase letters, digits, dashes or underscores."
[[ -z $attestation || $attestation =~ ^[A-Za-z0-9:/._@=,+-]{3,200}$ ]] || fail usage "Use a provider reference of 3 to 200 safe characters."
[[ $(uname -s) == Linux ]] || fail platform "Run this check on the Linux pilot host."

[[ -f $env_file ]] || fail env_file "The environment file does not exist."
mode=$(stat -c '%a' "$env_file")
[[ $mode == 600 || $mode == 400 ]] || fail env_file "Set the environment file mode to 0600 or 0400; it is $mode."
grep -Eq '^ZEKVAR_DATA_KEYS=("?)[a-z0-9._-]{1,32}=[0-9a-f]{64}' "$env_file" ||
  fail data_keys "Set ZEKVAR_DATA_KEYS to id=64-hex-character keys, with the active key first."

mountpoint=$(docker volume inspect "${project}_postgres_data" --format '{{.Mountpoint}}' 2>/dev/null) ||
  fail volume "Docker has no ${project}_postgres_data volume. Start PostgreSQL once, then rerun this check."
[[ -n $mountpoint ]] || fail volume "Docker reported no mountpoint for the PostgreSQL volume."
source=$(findmnt -n -o SOURCE --target "$mountpoint" 2>/dev/null) || fail device "Could not resolve the filesystem holding the PostgreSQL volume."
source=${source%%[*}
case $source in
  /dev/*) ;;
  *) fail device "The PostgreSQL volume is on $source, which is not a local block device. Use a volume on an encrypted disk." ;;
esac

if lsblk -n -s -o TYPE "$source" 2>/dev/null | grep -qx crypt; then
  printf '{"status":"pass","encryption":"dm-crypt","device":"%s","mountpoint":"%s"}\n' "$source" "$mountpoint"
  exit 0
fi
if [[ -n $attestation ]]; then
  printf '{"status":"attested","encryption":"provider","reference":"%s","device":"%s","detail":"%s"}\n' "$attestation" "$source" \
    "Provider disk encryption is not visible inside the host; keep the provider evidence with this result."
  exit 0
fi
fail encryption "The PostgreSQL volume device $source has no dm-crypt layer. Move Docker data to a LUKS volume or pass --provider-encrypted with the encrypted disk reference."
