#!/bin/sh
set -eu

if [ "$#" -ne 7 ]; then
  echo "usage: sign-release.sh SIGNER PURPOSE INPUT SHA256 PRIVATE_KEY PUBLIC_KEY NEW_SIGNATURE" >&2
  exit 2
fi

signer=$1
purpose=$2
input=$3
expected_sha256=$4
private_key=$5
public_key=$6
output=$7

case "$purpose" in
  plugin-executable|plugin-archive|plugin-index|cli-checksums) ;;
  *) echo "unsupported signing purpose" >&2; exit 2 ;;
esac
case "$expected_sha256" in
  ''|*[!0-9a-f]*) echo "expected SHA-256 must be 64 lowercase hex digits" >&2; exit 2 ;;
esac
if [ "${#expected_sha256}" -ne 64 ]; then
  echo "expected SHA-256 must be 64 lowercase hex digits" >&2
  exit 2
fi

case "$output" in
  /*) ;;
  *) output="$PWD/$output" ;;
esac
umask 077
staging=$(mktemp -d "$(dirname "$output")/.enkv-sign.XXXXXXXX")
trap 'rm -rf "$staging"' EXIT
trap 'exit 1' HUP INT TERM

python3 - "$input" "$public_key" "$staging" <<'PY'
from pathlib import Path
import sys

for source, name, limit in zip(sys.argv[1:3], ("input", "public.pem"),
                               (1048576, 16384)):
    with open(source, "rb") as incoming:
        body = incoming.read(limit + 1)
    if len(body) > limit:
        raise RuntimeError("signing input exceeds byte limit")
    with (Path(sys.argv[3]) / name).open("xb") as output:
        output.write(body)
PY
actual_sha256=$(shasum -a 256 < "$staging/input")
actual_sha256=${actual_sha256%% *}
if [ "$actual_sha256" != "$expected_sha256" ]; then
  echo "qualified input SHA-256 mismatch" >&2
  exit 1
fi

"$signer" -purpose "$purpose" -input "$staging/input" \
  -key "$private_key" -output "$staging/signature"
"$signer" -verify -purpose "$purpose" -input "$staging/input" \
  -key "$staging/public.pem" -signature "$staging/signature"

"$signer" -purpose "$purpose" -input "$staging/input" \
  -key "$private_key" -output "$output"
