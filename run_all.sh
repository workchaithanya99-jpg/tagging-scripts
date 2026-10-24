cd ~/tagging-scripts
cat > run_all.sh <<'EOF'
#!/bin/bash
export TZ=Asia/Kolkata
cd "$(dirname "$0")"
LOGDIR=./logs
mkdir -p "$LOGDIR"
STAMP=$(date +%Y-%m-%d_%H-%M-%S)
LOG="$LOGDIR/tagging-$STAMP.log"
SUMMARY="$LOGDIR/summary-$STAMP.log"
TMP=$(mktemp)

stamp() { while IFS= read -r l; do printf '%(%Y-%m-%d %H:%M:%S)T [%s] %s\n' -1 "$1" "$l"; done; }

for a in $(cat "${1:-accounts.txt}"); do
  echo "=== account $a start ===" | stamp "$a" | tee -a "$LOG"
  AWS_PROFILE=acct-$a /usr/bin/python3 -u tag-script.py --yes --quiet 2>&1 | tee "$TMP" | stamp "$a" | tee -a "$LOG"
  rc=${PIPESTATUS[0]}
  ok=$(grep -oP 'Successfully tagged : \K[0-9]+' "$TMP" | tail -1)
  fail=$(grep -oP 'Failed +: \K[0-9]+' "$TMP" | tail -1)
  ok=${ok:-0}; fail=${fail:-0}
  if [ "$rc" -eq 0 ] && [ "$fail" -eq 0 ]; then status="SUCCESS"
  elif [ "$rc" -eq 0 ]; then status="DONE, SOME RESOURCES FAILED"
  elif [ "$rc" -eq 2 ]; then status="SCAN ERRORS"
  else status="FAILED"; fi
  line=$(printf '%s | account %s | %s | tagged=%s failed=%s | exit=%s' \
    "$(date '+%a %Y-%m-%d %H:%M:%S %Z')" "$a" "$status" "$ok" "$fail" "$rc")
  echo "$line" >> "$SUMMARY"
  echo "=== $line ===" | stamp "$a" | tee -a "$LOG"
done

rm -f "$TMP"
find "$LOGDIR" \( -name 'tagging-*.log' -o -name 'summary-*.log' \) -type f -mtime +2 -delete
EOF
chmod +x run_all.sh
