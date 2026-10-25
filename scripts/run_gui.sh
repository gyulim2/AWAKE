#!/usr/bin/env bash
# GUI 실행 (감시 시작/중지는 화면에서)
set -euo pipefail
source "$(dirname "$0")/env.sh"
exec "$AWAKE_REPO/build/awake_gui" "$AWAKE_INBOX" "$AWAKE_RESULTS"
