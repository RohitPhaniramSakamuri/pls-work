#!/usr/bin/env bash
# InfluxDB 2.x idempotent setup script
# Run after influxdb container is healthy

set -euo pipefail

INFLUX_URL="${INFLUX_URL:-http://localhost:8086}"
INFLUX_TOKEN="${INFLUX_TOKEN:-honeypot-super-secret-token}"
INFLUX_ORG="${INFLUX_ORG:-honeypot}"
INFLUX_BUCKET="${INFLUX_BUCKET:-attacks}"

echo "[setup] Waiting for InfluxDB at $INFLUX_URL..."
until curl -sf "$INFLUX_URL/ping" > /dev/null 2>&1; do
    sleep 2
done
echo "[setup] InfluxDB is up."

# Check if org already exists
ORG_EXISTS=$(curl -sf \
    -H "Authorization: Token $INFLUX_TOKEN" \
    "$INFLUX_URL/api/v2/orgs?org=$INFLUX_ORG" \
    | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('orgs',[])))" 2>/dev/null || echo "0")

if [ "$ORG_EXISTS" -gt "0" ]; then
    echo "[setup] Org '$INFLUX_ORG' already exists — skipping init."
else
    echo "[setup] Initialising org=$INFLUX_ORG bucket=$INFLUX_BUCKET..."
    influx setup \
        --host "$INFLUX_URL" \
        --username admin \
        --password adminpassword \
        --org "$INFLUX_ORG" \
        --bucket "$INFLUX_BUCKET" \
        --retention 8760h \
        --token "$INFLUX_TOKEN" \
        --force
    echo "[setup] Init complete."
fi

# Verify bucket exists
echo "[setup] Verifying bucket '$INFLUX_BUCKET'..."
curl -sf \
    -H "Authorization: Token $INFLUX_TOKEN" \
    "$INFLUX_URL/api/v2/buckets?org=$INFLUX_ORG" \
    | python3 -c "import sys,json; d=json.load(sys.stdin); buckets=[b['name'] for b in d.get('buckets',[])]; print('[setup] Buckets:', buckets)"

echo "[setup] Done."
