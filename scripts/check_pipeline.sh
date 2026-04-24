#!/usr/bin/env bash
# check_pipeline.sh — Verify all honeypot Docker services are running and data flows
set -euo pipefail

BACKEND_DIR="$(dirname "$0")/../backend"
INFLUX_URL="http://localhost:8086"
INFLUX_TOKEN="${INFLUX_TOKEN:-honeypot-super-secret-token}"
GRAFANA_URL="http://localhost:3000"

PASS=0
FAIL=0

ok()   { echo "[PASS] $*"; PASS=$((PASS+1)); }
fail() { echo "[FAIL] $*"; FAIL=$((FAIL+1)); }

# ─── 1. Docker services ───────────────────────────────────────────────────────
echo "=== Checking Docker services ==="
for svc in honeypot_mosquitto honeypot_influxdb honeypot_telegraf honeypot_grafana; do
    STATUS=$(docker inspect --format '{{.State.Status}}' "$svc" 2>/dev/null || echo "missing")
    if [ "$STATUS" = "running" ]; then
        ok "$svc is running"
    else
        fail "$svc is $STATUS"
    fi
done

# ─── 2. MQTT broker reachable ─────────────────────────────────────────────────
echo ""
echo "=== MQTT broker ==="
if docker exec honeypot_mosquitto mosquitto_pub -h localhost -p 1883 -t "honeypot/check" -m "ping" -q 0 2>/dev/null; then
    ok "MQTT broker accepts publishes on :1883"
else
    fail "MQTT broker unreachable on :1883"
fi

# ─── 3. InfluxDB health ───────────────────────────────────────────────────────
echo ""
echo "=== InfluxDB ==="
INFLUX_HEALTH=$(curl -sf "$INFLUX_URL/ping" -o /dev/null -w "%{http_code}")
if [ "$INFLUX_HEALTH" = "204" ]; then
    ok "InfluxDB ping returned 204"
else
    fail "InfluxDB ping returned $INFLUX_HEALTH"
fi

# ─── 4. InfluxDB has data ─────────────────────────────────────────────────────
DATA_COUNT=$(curl -sf "$INFLUX_URL/api/v2/query?org=honeypot" \
    -H "Authorization: Token $INFLUX_TOKEN" \
    -H "Content-Type: application/vnd.flux" \
    --data 'from(bucket:"attacks") |> range(start: -1h) |> count()' \
    | grep -c "_value" || echo "0")

if [ "$DATA_COUNT" -gt "0" ]; then
    ok "InfluxDB has $DATA_COUNT measurement(s) in the last hour"
else
    fail "InfluxDB has no data in the last hour — run simulate_attacks.py first"
fi

# ─── 5. Grafana health ────────────────────────────────────────────────────────
echo ""
echo "=== Grafana ==="
GRAFANA_CODE=$(curl -sf -o /dev/null -w "%{http_code}" "$GRAFANA_URL/api/health")
if [ "$GRAFANA_CODE" = "200" ]; then
    ok "Grafana /api/health returned 200"
else
    fail "Grafana /api/health returned $GRAFANA_CODE"
fi

# ─── Summary ─────────────────────────────────────────────────────────────────
echo ""
echo "=== Summary: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
