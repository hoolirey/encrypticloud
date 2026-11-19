#!/usr/bin/env bash
# Signed request helper. Usage: npt_client.sh [BASE_URL] [PATH]
set -euo pipefail
ROOT="${NPT_ROOT:-$HOME/encrypticloud/geomatrix4}"
KID="${NPT_KEY_ID:-client1}"
BASE="${1:-http://[::1]:8443}"
REQ_PATH="${2:-/}"
KEY="$(cat "$ROOT/etc/abs256_4/keys/$KID.key")"
TS="$(date +%s)"
CTR="$(date +%s%3N)"
SIG="$(printf 'GET|%s|%s|%s' "$REQ_PATH" "$TS" "$CTR" \
  | openssl dgst -sha3-256 -mac HMAC -macopt "hexkey:$KEY" -r | cut -d' ' -f1)"
curl -sg -H "X-NPT-Key-Id: $KID" -H "X-NPT-Timestamp: $TS" \
     -H "X-NPT-Counter: $CTR" -H "X-NPT-Signature: $SIG" "$BASE$REQ_PATH"
