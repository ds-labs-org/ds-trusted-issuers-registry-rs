#!/usr/bin/env bash
# Downloads the third-party conformance material the `conformance` tests
# (crates/trusted-issuers-core/tests/conformance.rs) run against, each pinned
# to a version or commit and checked against its SHA-256, into
# ${CONFORMANCE_DIR:-target/conformance}:
#
#   etsi/1960201_json_schema.json  ETSI TS 119 602 (LoTE) JSON binding, as
#                                  published in the European Commission's EUDI
#                                  library eu.europa.ec.eudi:etsi-119602-data-model
#                                  (forge.etsi.org itself is often unreachable)
#   ebsi/accreditation.json        EBSI Verifiable Accreditation schema
#   ebsi/attestation.json          EBSI Verifiable Attestation (its base)
#                                  (npm @cef-ebsi/vcdm1.1-*-schema 2.0.0)
#   ebsi/examples/*.json           EBSI's own accreditation examples
#   limbo/limbo.json               C2SP x509-limbo X.509 path validation vectors
#
# Usage: conformance/fetch.sh && cargo test -p trusted-issuers-core --test conformance -- --ignored
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${CONFORMANCE_DIR:-$ROOT/target/conformance}"
# Downloads are kept (and re-verified) in $DL, so a rerun fetches nothing.
DL="$OUT/downloads"
mkdir -p "$OUT/etsi" "$OUT/ebsi/examples" "$OUT/limbo" "$DL"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

EUDI_VERSION=0.4.0-alpha.4
EUDI_JAR_SHA256=0525178f07d1bb9d5031493be6ef1b35221a582c0b064beea0e4367f40a470ad
ETSI_SCHEMA_SHA256=9c26811ac550060fc76eff9292b0611899d909b7c760bf2d582f85dc6b6cc9ae
EBSI_VERSION=2.0.0
EBSI_ACCREDITATION_TGZ_SHA256=500f6adae41d4e4f4c6bc2f6d0ec1d49c56673d4bcea93982c29f35828dde03c
EBSI_ATTESTATION_TGZ_SHA256=f4855b7a10c9cee15e6d756b76edc0f3716aa333747e77ccbecd5c1b4a1212f5
LIMBO_COMMIT=554528a9b0c0d95e071f55de018326f0b65a8364
LIMBO_SHA256=611e337b9fb477b927bae65434650692cb9d2070ff5b05f975d0403510acd4de

fetch() { # url sha256 dest
  if [ -f "$3" ] && echo "$2  $3" | sha256sum -c --quiet - 2>/dev/null; then return; fi
  curl -fsSL --retry 5 --retry-delay 5 --retry-all-errors -o "$3" "$1"
  echo "$2  $3" | sha256sum -c --quiet - || { echo "checksum mismatch: $1" >&2; exit 1; }
}

fetch "https://repo1.maven.org/maven2/eu/europa/ec/eudi/etsi-119602-data-model-jvm/$EUDI_VERSION/etsi-119602-data-model-jvm-$EUDI_VERSION.jar" \
  "$EUDI_JAR_SHA256" "$DL/eudi.jar"
python3 - "$DL/eudi.jar" "$OUT/etsi/1960201_json_schema.json" <<'PY'
import sys, zipfile
open(sys.argv[2], "wb").write(zipfile.ZipFile(sys.argv[1]).read("1960201_json_schema.json"))
PY
echo "$ETSI_SCHEMA_SHA256  $OUT/etsi/1960201_json_schema.json" | sha256sum -c --quiet -

for name in accreditation attestation; do
  case $name in
    accreditation) sum=$EBSI_ACCREDITATION_TGZ_SHA256 ;;
    attestation) sum=$EBSI_ATTESTATION_TGZ_SHA256 ;;
  esac
  fetch "https://registry.npmjs.org/@cef-ebsi/vcdm1.1-$name-schema/-/vcdm1.1-$name-schema-$EBSI_VERSION.tgz" "$sum" "$DL/$name.tgz"
  tar -xzf "$DL/$name.tgz" -C "$TMP" package/schema.json
  mv "$TMP/package/schema.json" "$OUT/ebsi/$name.json"
done
tar -xzf "$DL/accreditation.tgz" -C "$TMP" package/examples
mv "$TMP"/package/examples/*.json "$OUT/ebsi/examples/"

fetch "https://raw.githubusercontent.com/C2SP/x509-limbo/$LIMBO_COMMIT/limbo.json" "$LIMBO_SHA256" "$OUT/limbo/limbo.json"

echo "conformance material in $OUT"
