#!/bin/bash
set -euo pipefail

# ============================================================
# snyk_ignore.sh
#
# 1. Fetch vulnerability data from Elasticsearch
# 2. Ignore the vulnerability in Snyk
# ============================================================

## Elasticsearch
ES_HOST="${ES_HOST:-http://localhost:9200}"
ES_INDEX="${ES_INDEX:-snyk_vulnerabilities}"

## Snyk
SNYK_HOST="${SNYK_HOST:-https://app.snyk.io}"

## Cookies
# The snyk_id cookie from an active snyk session (urlencoded)
# Required.
#SNYK_ID=

## Headers
# The x-csrf-token request header from an active snyk session
# Required.
#X_CSRF_TOKEN

## Params

# the vulnerability (snyk) id... used to read a file: $VULN_ID.json which contains 
# info about exactly what should be ignored (records the from 
# snyk_vulnerabilities index in ES).  NOT a CVE, but the SNYK_##### id.
VULN_ID=${1:-}

# the ignore message... hint: use quotes.
MESSAGE=${2:-}

# ------------------------------------------------------------
# Validate required environment variables
# ------------------------------------------------------------
if [[ -z "${SNYK_ID:-}" ]]; then
  echo "Error: SNYK_ID environment variable is not set." >&2
  exit 1
fi

if [[ -z "${X_CSRF_TOKEN:-}" ]]; then
  echo "Error: X_CSRF_TOKEN environment variable is not set." >&2
  exit 1
fi

if [[ -z "${ES_API_KEY:-}" ]]; then
  echo "Error: ES_API_KEY environment variable is not set." >&2
  exit 1
fi

if [[ -z "${VULN_ID:-}" ]]; then
  echo "Error: A vulnerability (Snyk ID) must be specified." >&2
  exit 1
fi

if [[ -z "${MESSAGE:-}" ]]; then
  echo "Error: An ignore message must be specified." >&2
  exit 1
fi

ES_AUTH="Authorization: ApiKey ${ES_API_KEY}"

# ------------------------------------------------------------
# Clean up and recreate working directories
# ------------------------------------------------------------
echo "Cleaning up previous run artifacts..."

rm -f ignore_report.$VULN_ID

# ------------------------------------------------------------
# Check access to Snyk
# ------------------------------------------------------------
echo "Checking access to Snyk..."
HTTP_CODE=`curl "${SNYK_HOST}/registry/org/folio-org/projects/total-count" \
  -H 'accept: application/json' \
  -b "snyk.id=${SNYK_ID}" \
  -H "x-csrf-token: ${X_CSRF_TOKEN}" \
  -sko /dev/null -w "%{http_code}"`
if [[ ${HTTP_CODE} -ne 200 ]]; then
  echo "Error: Call to Snyk failed.  Check your cookies/headers and try again" >&2
  exit 1
fi

# ------------------------------------------------------------
# Check access to Elasticsearch
# ------------------------------------------------------------
echo "Checking access to Elasticsearch..."
HTTP_CODE=`curl "${ES_HOST}/${ES_INDEX}" -H "${ES_AUTH}" -sko /dev/null -w "%{http_code}"`
if [[ ${HTTP_CODE} -ne 200 ]]; then
  echo "Error: Call to Elasticsearch failed:  ${ES_HOST}/${ES_INDEX} (${HTTP_CODE})" >&2
  exit 1
fi

# ============================================================
# PHASE 1: Fetch vulnerability from Elasticsearch
# ============================================================
echo ""
echo "=== Phase 1: Fetching vulnerability data from Elasticsearch ==="

# Fetch all documents for this Snyk ID
curl -s -o $VULN_ID.json -XPOST "${ES_HOST}/${ES_INDEX}/_search" \
  -H "${ES_AUTH}" \
  -H "Content-Type: application/json" \
  -d "{
    \"size\": 10000,
    \"query\": {
      \"bool\": {
        \"filter\": [
          {
            \"term\": {
              \"identifiers.id\": \"${VULN_ID}\"
            }
          },
          {
            \"range\": {
              \"date\": {
                \"gte\": \"now/d\",
                \"lte\": \"now/d\"
              }
            }
          }
        ]
      }
    }
  }"
COUNT=`cat ${VULN_ID}.json | jq '.hits.hits|length'`
echo "Found ${COUNT}:"
cat ${VULN_ID}.json | jq ".hits.hits[]._source.project.name" -r

echo ""
read -rp "Proceed with ignoring ${VULN_ID} for these projects? [y/N] " CONFIRM

if [[ "${CONFIRM,,}" != "y" ]]; then
  echo "Aborted."
  exit 0
fi

# ============================================================
# PHASE 2: Ignore vulnerability in Snyk
# ============================================================
echo ""
echo "=== Phase 2: Ignoring vulnerability in Snyk ==="

for ((i=0; i<${COUNT}; i++)); do
  PROJECT_NAME=`cat ${VULN_ID}.json | jq ".hits.hits[$i]._source.project.name" -r`
  PROJECT_ID=`cat ${VULN_ID}.json | jq ".hits.hits[$i]._source.project.id" -r`
  printf '[%d/%d] %s\n' $((i+1)) ${COUNT} "${PROJECT_NAME}"

  printf '[%d/%d] %s\n' $((i+1)) ${COUNT} "${PROJECT_NAME}" >> ignore_report.${VULN_ID}
  echo "https://app.snyk.io/org/folio-org/project/${PROJECT_ID}/ignore/${VULN_ID}" >> ignore_report.${VULN_ID}

  curl "https://app.snyk.io/org/folio-org/project/${PROJECT_ID}/ignore/${VULN_ID}" \
    -s -XPOST \
    -H 'accept: application/json' \
    -H 'content-type: application/json' \
    -b "snyk.id=${SNYK_ID}" \
    -H "x-csrf-token: ${X_CSRF_TOKEN}" \
    -H "x-requested-with: XMLHttpRequest" \
    --data-raw "
{
  \"reasonType\": \"not-vulnerable\",
  \"reason\": \"${MESSAGE}\",
  \"expires\": null,
  \"disregardIfFixable\": false
}" -w'\n' -D - >> ignore_report.${VULN_ID}
done

echo ""
echo "Done.  See ignore_report.${VULN_ID} for details."
