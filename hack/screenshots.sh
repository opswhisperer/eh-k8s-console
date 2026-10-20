#!/usr/bin/env bash
# Capture README screenshots from the synthetic demo (go run ./hack/demo must be running).
# Everything shown is made up: no real cluster, sensor, or names.
#   hack/screenshots.sh [out-dir]          (default docs/images)
# Set GRAFANA (for example http://127.0.0.1:3000) to also capture the dashboard from a Grafana
# that has deploy/components/grafana/eh-k8s-console.json loaded and a Prometheus scraping the
# demo's metrics (127.0.0.1:9095) for at least 15 minutes.
# Needs Google Chrome. Uses a throwaway Chrome profile.
set -euo pipefail
OUT=${1:-docs/images}
BASE=${BASE:-http://127.0.0.1:8090}
CHROME=${CHROME:-"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"}
PROFILE=$(mktemp -d)
trap 'rm -rf "$PROFILE"' EXIT
mkdir -p "$OUT"

capture() { # name url height [extra chrome flags...]
  local name=$1 url=$2 height=$3; shift 3
  "$CHROME" --headless=new --disable-gpu --hide-scrollbars --no-first-run --no-default-browser-check \
    --user-data-dir="$PROFILE" --window-size=1440,"$height" --force-device-scale-factor=2 \
    --virtual-time-budget=30000 "$@" --screenshot="$OUT/$name.png" "$url" >/dev/null 2>&1
  echo "$OUT/$name.png"
}
shot() { local name=$1 route=$2; shift 2; capture "$name" "$BASE/#/$route" "$@"; }

shot overview overview 1000
shot overview-dark overview 1000 --force-dark-mode --blink-settings=preferredColorScheme=0
shot settings settings 1250
shot filtering filtering 1400
shot certificate certs 1250
shot logs "logs?follow=0" 1250   # the frozen view: a live stream never lets the page settle
shot history history 760
if [[ -n ${GRAFANA:-} ]]; then
  capture dashboard "$GRAFANA/d/eh-k8s-console?orgId=1&kiosk&from=now-15m&to=now&theme=light" 1520
fi
