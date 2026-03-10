#!/bin/bash

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

API_GATEWAY_URL="${API_GATEWAY_URL:-http://localhost:8080}"
JWT_SECRET="${JWT_SECRET:-test-secret-key-do-not-use-in-production}"

TESTS_PASSED=0
TESTS_FAILED=0

API_BODY=""
API_STATUS=""

print_section() {
  echo ""
  echo -e "${YELLOW}>>> $1${NC}"
  echo ""
}

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo -e "${RED}Missing required command: $cmd${NC}"
    exit 1
  fi
}

json_get() {
  local json_input="$1"
  local path="$2"
  python3 - "$path" "$json_input" <<'PY'
import json, sys
path = sys.argv[1]
raw = sys.argv[2]
try:
    data = json.loads(raw)
except Exception:
    print("null")
    sys.exit(0)
cur = data
for part in [p for p in path.split('.') if p != '']:
    if isinstance(cur, list):
        try:
            idx = int(part)
            cur = cur[idx]
        except Exception:
            cur = None
            break
    elif isinstance(cur, dict):
        cur = cur.get(part)
    else:
        cur = None
        break
if cur is None:
    print("null")
elif isinstance(cur, bool):
    print("true" if cur else "false")
elif isinstance(cur, (dict, list)):
    print(json.dumps(cur))
else:
    print(cur)
PY
}

json_len() {
  local json_input="$1"
  local path="$2"
  python3 - "$path" "$json_input" <<'PY'
import json, sys
path = sys.argv[1]
raw = sys.argv[2]
try:
    data = json.loads(raw)
except Exception:
    print(0)
    sys.exit(0)
cur = data
for part in [p for p in path.split('.') if p != '']:
    if isinstance(cur, list):
        try:
            idx = int(part)
            cur = cur[idx]
        except Exception:
            cur = None
            break
    elif isinstance(cur, dict):
        cur = cur.get(part)
    else:
        cur = None
        break
if isinstance(cur, list):
    print(len(cur))
elif isinstance(cur, dict):
    print(len(cur))
else:
    print(0)
PY
}

generate_jwt() {
  local secret="$1"
  python3 - "$secret" <<'PY'
import base64, hashlib, hmac, json, sys, time
secret = sys.argv[1].encode()
header = {"alg": "HS256", "typ": "JWT"}
now = int(time.time())
payload = {
    "user_id": "e2e-user",
    "username": "e2e",
    "roles": ["tester", "admin"],
    "iss": "ioc-api-gateway",
    "iat": now,
    "exp": now + 3600,
}
def b64url(v):
    return base64.urlsafe_b64encode(json.dumps(v, separators=(",", ":")).encode()).rstrip(b"=")
msg = b".".join([b64url(header), b64url(payload)])
sig = base64.urlsafe_b64encode(hmac.new(secret, msg, hashlib.sha256).digest()).rstrip(b"=")
print((msg + b"." + sig).decode())
PY
}

api_call() {
  local method="$1"
  local path="$2"
  local body="${3:-}"
  local url="${API_GATEWAY_URL}${path}"
  local resp

  if [[ -n "$body" ]]; then
    resp=$(curl -sS -X "$method" "$url" \
      -H "Authorization: Bearer ${AUTH_TOKEN}" \
      -H "Content-Type: application/json" \
      -d "$body" \
      -w "\n%{http_code}")
  else
    resp=$(curl -sS -X "$method" "$url" \
      -H "Authorization: Bearer ${AUTH_TOKEN}" \
      -w "\n%{http_code}")
  fi

  API_STATUS=$(echo "$resp" | tail -n1)
  API_BODY=$(echo "$resp" | sed '$d')
}

expect_status_200() {
  local step="$1"
  if [[ "$API_STATUS" == "200" ]]; then
    echo -e "${GREEN}[O] $step${NC}"
    TESTS_PASSED=$((TESTS_PASSED + 1))
  else
    echo -e "${RED}[X] $step (HTTP $API_STATUS)${NC}"
    echo "Response: $API_BODY"
    TESTS_FAILED=$((TESTS_FAILED + 1))
  fi
}

check_service_health() {
  local max_retries=30
  local retry_count=0
  print_section "Step 1: Health Checks"

  while [[ $retry_count -lt $max_retries ]]; do
    if curl -s -f "${API_GATEWAY_URL}/health" >/dev/null 2>&1; then
      echo -e "${GREEN}[O] API Gateway is ready${NC}"
      return 0
    fi
    retry_count=$((retry_count + 1))
    sleep 1
  done

  echo -e "${RED}[X] API Gateway failed health check${NC}"
  return 1
}

require_cmd curl
require_cmd python3

echo -e "${GREEN}----------------------------------------${NC}"
echo -e "${GREEN}IoC Enrichment System - E2E Test Suite${NC}"
echo -e "${GREEN}----------------------------------------${NC}"

check_service_health || exit 1

AUTH_TOKEN=$(generate_jwt "$JWT_SECRET")
SUFFIX=$(date +%s)
TEST_SOURCE="e2e-${SUFFIX}"
IP_VALUE="198.51.100.$((SUFFIX % 200 + 1))"
DOMAIN_VALUE="e2e-${SUFFIX}.example.com"
HASH_VALUE="a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27a$((SUFFIX % 10))"
THREAT_NAME="E2E-TEST-THREAT-${SUFFIX}"

print_section "Step 2: IoC Ingestion"
IOC_PAYLOAD=$(cat <<JSON
{
  "iocs": [
    {"type": "ip", "value": "$IP_VALUE", "source": "$TEST_SOURCE", "description": "E2E test ip", "severity": "high", "tags": ["e2e", "ip"]},
    {"type": "domain", "value": "$DOMAIN_VALUE", "source": "$TEST_SOURCE", "description": "E2E test domain", "severity": "high", "tags": ["e2e", "domain"]},
    {"type": "sha256", "value": "$HASH_VALUE", "source": "$TEST_SOURCE", "description": "E2E test hash", "severity": "high", "tags": ["e2e", "hash"]}
  ],
  "auto_enrich": false
}
JSON
)
api_call POST "/api/v1/iocs/batch" "$IOC_PAYLOAD"
expect_status_200 "Batch upsert IoCs"
IOC_IP_ID=$(json_get "$API_BODY" "data.upserted_ids.0")
IOC_DOMAIN_ID=$(json_get "$API_BODY" "data.upserted_ids.1")
IOC_HASH_ID=$(json_get "$API_BODY" "data.upserted_ids.2")

if [[ "$IOC_IP_ID" == "null" || "$IOC_DOMAIN_ID" == "null" || "$IOC_HASH_ID" == "null" ]]; then
  echo -e "${RED}✗ Missing IoC IDs from batch response${NC}"
  echo "$API_BODY"
  exit 1
fi

print_section "Step 3: IoC Retrieval"
api_call GET "/api/v1/iocs/${IOC_IP_ID}" ""
expect_status_200 "Get IoC by ID"
IOC_VALUE=$(json_get "$API_BODY" "data.ioc.value")
if [[ "$IOC_VALUE" == "$IP_VALUE" ]]; then
  echo -e "${GREEN}[O] IoC value matches expected${NC}"
  TESTS_PASSED=$((TESTS_PASSED + 1))
else
  echo -e "${RED}[X] IoC value mismatch: expected $IP_VALUE, got $IOC_VALUE${NC}"
  TESTS_FAILED=$((TESTS_FAILED + 1))
fi

print_section "Step 4: IoC Find"
FIND_IOC_PAYLOAD=$(cat <<JSON
{
  "pagination": {"page": 1, "page_size": 20},
  "filter": {"source": "$TEST_SOURCE"}
}
JSON
)
api_call POST "/api/v1/iocs/find" "$FIND_IOC_PAYLOAD"
expect_status_200 "Find IoCs"
FOUND_IOC_COUNT=$(json_len "$API_BODY" "data.iocs")
if [[ "$FOUND_IOC_COUNT" -ge 1 ]]; then
  echo -e "${GREEN}[O] Found $FOUND_IOC_COUNT IoCs for source $TEST_SOURCE${NC}"
  TESTS_PASSED=$((TESTS_PASSED + 1))
else
  echo -e "${RED}[X] No IoCs found for source $TEST_SOURCE${NC}"
  TESTS_FAILED=$((TESTS_FAILED + 1))
fi

print_section "Step 5: Threat Ingestion"
THREAT_PAYLOAD=$(cat <<JSON
{
  "threats": [
    {
      "name": "$THREAT_NAME",
      "description": "E2E threat",
      "category": "c2",
      "severity": "high",
      "confidence": 0.95,
      "campaigns": ["e2e-campaign"],
      "threat_actors": ["e2e-actor"],
      "metadata": {"ttps": ["T1566.001", "T1053.005"], "references": ["https://example.com"]}
    }
  ]
}
JSON
)
api_call POST "/api/v1/threats/batch" "$THREAT_PAYLOAD"
expect_status_200 "Batch upsert threats"
THREAT_ID=$(json_get "$API_BODY" "data.upserted_ids.0")
if [[ "$THREAT_ID" == "null" ]]; then
  echo -e "${RED}✗ Missing threat ID from batch response${NC}"
  echo "$API_BODY"
  exit 1
fi

print_section "Step 6: Link IoCs to Threat"
LINK_PAYLOAD=$(cat <<JSON
{"ioc_ids": ["$IOC_IP_ID", "$IOC_DOMAIN_ID", "$IOC_HASH_ID"]}
JSON
)
api_call POST "/api/v1/threats/${THREAT_ID}/link" "$LINK_PAYLOAD"
expect_status_200 "Link IoCs to threat"

print_section "Step 7: Get Threats by IoC"
api_call GET "/api/v1/threats/by-ioc/${IOC_IP_ID}" ""
expect_status_200 "Get threats by IoC"
FOUND_THREAT_COUNT=$(json_len "$API_BODY" "data.threats")
echo "Threats found by IoC: $FOUND_THREAT_COUNT"

print_section "Step 8: Statistics"
api_call GET "/api/v1/iocs/stats" ""
expect_status_200 "Get IoC stats"
api_call GET "/api/v1/threats/stats" ""
if [[ "$API_STATUS" == "200" ]]; then
  echo -e "${GREEN}[O] Get threat stats${NC}"
  TESTS_PASSED=$((TESTS_PASSED + 1))
else
  echo -e "${YELLOW}[!] Threat stats unavailable (HTTP $API_STATUS)${NC}"
fi

print_section "Step 9: Correlate Threat"
CORRELATE_PAYLOAD=$(cat <<JSON
{"ioc_id":"$IOC_IP_ID", "min_confidence":0.5}
JSON
)
api_call POST "/api/v1/threats/correlate" "$CORRELATE_PAYLOAD"
expect_status_200 "Correlate threat by IoC"

print_section "Step 10: Cleanup"
api_call DELETE "/api/v1/iocs/batch" "{\"ids\":[\"$IOC_IP_ID\",\"$IOC_DOMAIN_ID\",\"$IOC_HASH_ID\"],\"reason\":\"e2e cleanup\"}"
if [[ "$API_STATUS" == "200" ]]; then
  echo -e "${GREEN}[O] Cleanup IoCs${NC}"
else
  echo -e "${YELLOW}[!] Cleanup IoCs skipped (HTTP $API_STATUS)${NC}"
fi
api_call DELETE "/api/v1/threats/batch" "{\"ids\":[\"$THREAT_ID\"],\"reason\":\"e2e cleanup\"}"
if [[ "$API_STATUS" == "200" ]]; then
  echo -e "${GREEN}[O] Cleanup threats${NC}"
else
  echo -e "${YELLOW}[!] Cleanup threats skipped (HTTP $API_STATUS)${NC}"
fi

print_section "Test Summary"
TOTAL_TESTS=$((TESTS_PASSED + TESTS_FAILED))
echo "Total Tests: $TOTAL_TESTS"
echo -e "${GREEN}[O] Passed: $TESTS_PASSED${NC}"
echo -e "${RED}[X] Failed: $TESTS_FAILED${NC}"

if [[ $TESTS_FAILED -eq 0 ]]; then
  echo -e "${GREEN}[O] ALL END-TO-END TESTS PASSED${NC}"
  exit 0
fi

echo -e "${RED}[X] SOME END-TO-END TESTS FAILED${NC}"
exit 1
