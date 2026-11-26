#!/bin/bash
# One lock per board for anything that uses core 3 or the eth0 link.
#   boardlock.sh acquire <owner> <purpose> [wait_seconds]   exit 0 = you hold it
#   boardlock.sh release <owner>                            only the holder can release
#   boardlock.sh status
# The marker ~/array_rev/MEASURING outranks the lock: while it exists nobody acquires.
L="$HOME/array_rev/lock"
case "${1:-}" in
acquire)
    owner="${2:?owner}"; purpose="${3:-unspecified}"; wait="${4:-0}"; t0=$(date +%s)
    while :; do
        if [ -e "$HOME/array_rev/MEASURING" ]; then
            reason="campaign measurement in progress (MEASURING)"
        elif mkdir "$L" 2>/dev/null; then
            printf '%s\n' "$owner" > "$L/owner"; printf '%s\n' "$purpose" > "$L/purpose"; date -Is > "$L/started"
            echo "acquired by $owner"; exit 0
        else
            reason="held by $(cat "$L/owner" 2>/dev/null) since $(cat "$L/started" 2>/dev/null) for $(cat "$L/purpose" 2>/dev/null)"
        fi
        [ $(( $(date +%s) - t0 )) -ge "$wait" ] && { echo "busy: $reason" >&2; exit 1; }
        sleep 2
    done ;;
release)
    owner="${2:?owner}"
    if [ "$(cat "$L/owner" 2>/dev/null)" = "$owner" ]; then rm -rf "$L"; echo released; exit 0; fi
    echo "not held by $owner (holder: $(cat "$L/owner" 2>/dev/null || echo none))" >&2; exit 1 ;;
status)
    if [ -d "$L" ]; then echo "held by $(cat "$L/owner") since $(cat "$L/started") for $(cat "$L/purpose")"; else echo free; fi
    [ -e "$HOME/array_rev/MEASURING" ] && echo "MEASURING present"; exit 0 ;;
*) echo "usage: boardlock.sh acquire <owner> <purpose> [wait_seconds] | release <owner> | status" >&2; exit 2 ;;
esac
