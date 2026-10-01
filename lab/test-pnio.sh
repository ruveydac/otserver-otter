#!/bin/sh
set -eu

LAB_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_NAME="otserver-otter-pnio-lab-${CI_JOB_ID:-$$}"
COMPOSE="docker compose -p $PROJECT_NAME -f $LAB_DIR/compose.yml"

mkdir -p "$LAB_DIR/artifacts"
chmod a+rwx "$LAB_DIR/artifacts"

cleanup() {
  $COMPOSE logs --no-color >"$LAB_DIR/artifacts/pnio-compose.log" 2>&1 || true
  $COMPOSE down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

OTTER_DCP_RESPONSE_DELAY_SECONDS=0 $COMPOSE up --build --detach siemens
$COMPOSE run --build --rm --no-deps -e OTTER_PNIO_ONLY=1 test
