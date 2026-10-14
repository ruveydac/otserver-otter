#!/usr/bin/env bash
# Full remote-management gate: real client, HTTPS fault recovery, and OTserver integration suite.
set -euo pipefail

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
MANAGEMENT=$(CDPATH='' cd -- "${1:-$ROOT/..}" && pwd -P)

fail() { printf '%s\n' "$*" >&2; exit 1; }

for tool in cargo cut git openssl node pnpm python3 sha256sum; do
  command -v "$tool" >/dev/null || fail "Required command not found: $tool"
done
[[ $(node -p 'process.versions.node.split(".")[0]') == 22 ]] || fail 'Node.js 22 is required.'
[[ $(pnpm --version) == 10.* ]] || fail 'pnpm 10 is required.'
for file in package.json pnpm-lock.yaml vitest.config.mts tests/int/otter-client.int.spec.ts \
  tests/int/otter-management.int.spec.ts tests/int/otter-security.int.spec.ts; do
  [[ -f "$MANAGEMENT/$file" ]] || fail "Missing $file in $MANAGEMENT; select an OTserver checkout with controller-v1 tests."
done
[[ -d "$MANAGEMENT/node_modules" ]] || fail "Install management dependencies first: pnpm --dir \"$MANAGEMENT\" install --frozen-lockfile"
[[ $(CDPATH='' cd -- "$MANAGEMENT/otserver-otter" && pwd -P) == "$ROOT" ]] || \
  fail 'Run the client checkout at MANAGEMENT/otserver-otter so contract tests use the same source as the binary.'

RUNTIME=${CONTAINER_RUNTIME:-}
if [[ -z "$RUNTIME" ]]; then
  for candidate in docker podman; do
    if command -v "$candidate" >/dev/null && "$candidate" info >/dev/null 2>&1; then
      RUNTIME=$candidate
      break
    fi
  done
fi
[[ -n "$RUNTIME" ]] || fail 'Docker or Podman is required for the disposable MongoDB replica set.'
"$RUNTIME" info >/dev/null 2>&1 || fail "Container runtime is unavailable: $RUNTIME"

mkdir -p "$ROOT/lab/artifacts"
ARTIFACTS=$(mktemp -d "$ROOT/lab/artifacts/controller.XXXXXX")
MONGO="otter-${ARTIFACTS##*/}"
UPLOADS=$(mktemp -d "${TMPDIR:-/tmp}/otter-controller-uploads.XXXXXX")
CONTAINER=''
cleanup() {
  status=$?
  trap - EXIT INT TERM
  if [[ -n "$CONTAINER" ]]; then
    "$RUNTIME" logs "$CONTAINER" >"$ARTIFACTS/mongo.log" 2>&1 || true
    "$RUNTIME" rm --force --volumes "$CONTAINER" >/dev/null || status=1
  fi
  rm -rf -- "$UPLOADS"
  printf 'Exit status: %s\nReports: %s\n' "$status" "$ARTIFACTS"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

step() {
  local name=$1
  shift
  printf '\n[%s]\n' "$name"
  "$@" 2>&1 | tee "$ARTIFACTS/$name.log"
}

# Pin both build and runtime paths even when a caller has CARGO_TARGET_DIR configured.
export CARGO_TARGET_DIR="$ROOT/target"
export OTTER_CLIENT_BIN="$CARGO_TARGET_DIR/debug/otserver-otter"
step build cargo build --locked --no-default-features --manifest-path "$ROOT/Cargo.toml"
{
  printf 'management_commit=%s\n' "$(git -C "$MANAGEMENT" rev-parse HEAD)"
  printf 'otter_commit=%s\n' "$(git -C "$ROOT" rev-parse HEAD)"
  printf 'otter_client_sha256=%s\n' "$(sha256sum "$OTTER_CLIENT_BIN" | cut -d' ' -f1)"
} | tee "$ARTIFACTS/revisions.txt"
step controller-unit cargo test --locked --no-default-features --manifest-path "$ROOT/Cargo.toml" \
  --bin otserver-otter controller:: -- --test-threads=1
step controller-https python3 -I "$ROOT/lab/controller_verify.py" "$OTTER_CLIENT_BIN"

# Always create our own database. Never use DATABASE_URL/TEST_DATABASE_URL from the caller or .env.
CONTAINER=$("$RUNTIME" run --detach --name "$MONGO" \
  --publish 127.0.0.1::27017 docker.io/library/mongo:8 --replSet rs0 --bind_ip_all)
wait_for_mongo() {
  local expression=$1
  for ((attempt = 0; attempt < 60; attempt++)); do
    if "$RUNTIME" exec "$CONTAINER" mongosh --quiet --eval "$expression" >/dev/null 2>&1; then
      return
    fi
    sleep 1
  done
  fail 'MongoDB replica set did not become ready within 60 attempts.'
}
wait_for_mongo 'if (!db.runCommand({ping: 1}).ok) quit(1)'
"$RUNTIME" exec "$CONTAINER" mongosh --quiet --eval \
  'const result = rs.initiate({_id:"rs0",members:[{_id:0,host:"localhost:27017"}]}); if (!result.ok) quit(1)' \
  >"$ARTIFACTS/mongo-init.log" 2>&1
wait_for_mongo 'if (!db.hello().isWritablePrimary) quit(1)'
ADDRESS=$("$RUNTIME" port "$CONTAINER" 27017/tcp)
[[ "$ADDRESS" =~ ^127\.0\.0\.1:[0-9]+$ ]] || fail 'Expected one loopback-only MongoDB port mapping.'
export TEST_DATABASE_URL="mongodb://$ADDRESS/otter-controller-test?replicaSet=rs0&directConnection=true"
export DATABASE_URL="$TEST_DATABASE_URL"
export OTSERVER_TEST_DATABASE_OWNER="${ARTIFACTS##*/}"
export OTSERVER_TEST_UPLOAD_DIR="$UPLOADS"
export OTSERVER_SECRET
OTSERVER_SECRET=$(openssl rand -hex 32)
export OTSERVER_OTTER_ENCRYPTION_KEY
OTSERVER_OTTER_ENCRYPTION_KEY=$(openssl rand -hex 32)
export OTSERVER_PUBLIC_URL='http://127.0.0.1:3000'
export OTSERVER_VULNERABILITY_FEEDS=off
export OTSERVER_QUEUED_IMPORTS=off
export NODE_ENV=test

# Run the whole management suite: UI controls, authorization, schedules, imports, workers,
# migrations, and the real Rust REST client (which normally skips without OTTER_CLIENT_BIN).
step management pnpm --dir "$MANAGEMENT" test:int \
  --reporter=default --reporter=junit --outputFile.junit="$ARTIFACTS/management.junit.xml"
step management-report python3 -I - "$ARTIFACTS/management.junit.xml" <<'PY'
import sys
import xml.etree.ElementTree as ET

report = ET.parse(sys.argv[1]).getroot()
for name in ("otter-client", "otter-management", "otter-security"):
    suite = report.find(f"testsuite[@name='tests/int/{name}.int.spec.ts']")
    assert suite is not None, f"Missing required suite: {name}"
    assert int(suite.get("tests", "0")) > 0, f"Empty required suite: {name}"
    assert all(int(suite.get(key, "0")) == 0 for key in ("skipped", "failures", "errors")), name
print("All required remote-management suites ran without skipped or failed tests.")
PY
printf '\nFull Otter remote-management integration passed.\n'
