#!/bin/bash
# Part 0 (analyst): prepare the authorized target.
#   - starts the SSH daemon
#   - starts one `python3 -m http.server <port>` per argument, each from its own
#     EMPTY directory (ports < 1024 are privileged, hence sudo)
# Usage : sudo bash part0/start_target.sh 311 444 808
# Stop  : touch /tmp/lab15_target/STOP   -> listeners are killed and SSH is
#         returned to the state it had before the lab.
set -u
BASE=/tmp/lab15_target
[ "$(id -u)" -eq 0 ] || { echo "error: run with sudo (ports below 1024 are privileged)" >&2; exit 1; }
[ $# -ge 1 ] || { echo "usage: sudo bash $0 <port> [<port> ...]" >&2; exit 2; }

rm -rf "$BASE"; mkdir -p "$BASE"; chmod 755 "$BASE"
[ -n "${SUDO_USER:-}" ] && chown "$SUDO_USER" "$BASE"      # lets the invoking user create STOP without sudo
ssh_before="$(systemctl is-active ssh)"
systemctl start ssh

pids=()
for port in "$@"; do
    mkdir -p "$BASE/www_$port"                       # empty directory: nothing to leak
    ( cd "$BASE/www_$port" && exec python3 -u -m http.server "$port" ) \
        > "$BASE/listener_$port.log" 2>&1 &
    pids+=("$!")
done
echo "$(date -Is) target ready: ssh=$(systemctl is-active ssh) listeners=$* pids=${pids[*]}"

while [ ! -e "$BASE/STOP" ]; do sleep 2; done
kill "${pids[@]}" 2>/dev/null
[ "$ssh_before" = "active" ] || systemctl stop ssh
echo "$(date -Is) target stopped (ssh back to: $(systemctl is-active ssh))"
