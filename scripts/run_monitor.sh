#!/usr/bin/env bash
# 감시기만 실행 (서버용). 종료: Ctrl+C
set -euo pipefail
source "$(dirname "$0")/env.sh"
exec "$AWAKE_REPO/build/awake_monitor" "$AWAKE_INBOX"
