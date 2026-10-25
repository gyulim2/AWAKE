# 공통 환경: 저장소 위치, PYTHONPATH, Maildir 경로 (awake/config.py와 같은 기본값)
AWAKE_REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PYTHONPATH="$AWAKE_REPO/src${PYTHONPATH:+:$PYTHONPATH}"
export AWAKE_MAILDIR="${AWAKE_MAILDIR:-$HOME/Maildir}"
AWAKE_INBOX="$AWAKE_MAILDIR/A-Awake"
AWAKE_RESULTS="$AWAKE_MAILDIR/awake-results"
mkdir -p "$AWAKE_INBOX" "$AWAKE_RESULTS"
