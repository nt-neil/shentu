#!/bin/bash
# Before each model: fresh SSH attack lines (20/12/11), recent file changes, clean Shentu state.
set -e
truncate -s0 /var/log/auth.log
b() { local src=$1 n=$2 u=$3 i=0; while [ $i -lt $n ]; do ip netns exec atk ssh -b $src -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -l "$u$i" 10.99.0.1 true 2>/dev/null || true; i=$((i+1)); done; }
b 10.99.0.2 20 admin; b 10.99.0.3 12 oracle
i=0; while [ $i -lt 11 ]; do ip netns exec atk ssh -b 10.99.0.4 -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -l SYSTEM 10.99.0.1 true 2>/dev/null || true; i=$((i+1)); done
touch /var/www/html/upload.php /root/.ssh/authorized_keys
python3 - <<'PY'
# Port baseline = every current listener except the planted 31337 (Ollama's own are skipped by Shentu).
import json, subprocess
ports = {}
for flag, proto in (("-ltnH", "tcp"), ("-lunH", "udp")):
    for line in subprocess.run(["ss", flag], capture_output=True, text=True).stdout.splitlines():
        local = line.split()[3]
        port = local.rsplit(":", 1)[1]
        k = f"{proto}{'6' if local.startswith('[') else ''}:{port}"
        if port != "31337":
            ports[k] = True
json.dump({"alerted": {}, "ports": ports, "last_run": "0001-01-01T00:00:00Z"}, open("/var/lib/shentu/state.json", "w"))
PY
nft delete table inet shentu 2>/dev/null || true
echo RESET_OK
