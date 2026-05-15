#!/bin/bash
set -euo pipefail

# ============================================================
# snyk_jira_check.sh
#
# 1. Fetches unique Snyk vulnerabilities from Elasticsearch
#    for today (date: now/d)
# 2. Writes per-CVE files to /tmp (skips vulns with no CVE)
# 3. Checks each CVE against all Jira projects
# 4. Writes missing vulnerabilities partitioned by severity
#    to OUTPUT_DIR
# ============================================================

## Elasticsearch
ES_HOST="${ES_HOST:-http://localhost:9200}"
ES_INDEX="${ES_INDEX:-snyk_vulnerabilities}"

## Jira
JIRA_BASE_URL="https://folio-org.atlassian.net"

#================================================================

TMPDIR="/tmp/snyk_cve_files"
OUTPUT_DIR="${OUTPUT_DIR:-/tmp/jira_check}"

CRITICAL_FILE="${OUTPUT_DIR}/critical.json"
HIGH_FILE="${OUTPUT_DIR}/high.json"
MEDIUM_FILE="${OUTPUT_DIR}/medium.json"
LOW_FILE="${OUTPUT_DIR}/low.json"

# ------------------------------------------------------------
# Validate required environment variables
# ------------------------------------------------------------
if [[ -z "${ES_API_KEY:-}" ]]; then
  echo "Error: ES_API_KEY environment variable is not set." >&2
  exit 1
fi

if [[ -z "${JIRA_API_TOKEN:-}" ]]; then
  echo "Error: JIRA_API_TOKEN environment variable is not set." >&2
  exit 1
fi

if [[ -z "${JIRA_USER:-}" ]]; then
  echo "Error: JIRA_USER environment variable is not set (e.g. user@example.com)." >&2
  exit 1
fi

ES_AUTH="Authorization: ApiKey ${ES_API_KEY}"
JIRA_AUTH="Authorization: Basic $(echo -n "${JIRA_USER}:${JIRA_API_TOKEN}" | base64 -w0)"

# ------------------------------------------------------------
# Clean up and recreate working directories
# ------------------------------------------------------------
echo "Cleaning up previous run artifacts..."
rm -rf "${TMPDIR}" "${OUTPUT_DIR}"
mkdir -p "${TMPDIR}" "${OUTPUT_DIR}"

echo "[]" > "${CRITICAL_FILE}"
echo "[]" > "${HIGH_FILE}"
echo "[]" > "${MEDIUM_FILE}"
echo "[]" > "${LOW_FILE}"

# ------------------------------------------------------------
# Check access to Elasticsearch
# ------------------------------------------------------------
echo "Checking access to Elasticsearch..."
HTTP_CODE=`curl ${ES_HOST}/${ES_INDEX} -H "${ES_AUTH}" -sko /dev/null -w "%{http_code}"`
if [[ ${HTTP_CODE} -ne 200 ]]; then 
  echo "Error: Call to Elasticsearch failed:  ${ES_HOST}/${ES_INDEX} (${HTTP_CODE})" >&2
  exit 1
fi

# ------------------------------------------------------------
# Check access to JIRA
# ------------------------------------------------------------
echo "Checking access to JIRA..."

HTTP_CODE=`curl -G "${JIRA_BASE_URL}/rest/api/3/myself" -H "${JIRA_AUTH}" -sko /dev/null -w "%{http_code}"`
if [[ ${HTTP_CODE} -ne 200 ]]; then 
  echo "Error: Call to JIRA  failed:  ${JIRA_BASE_URL} (${HTTP_CODE})" >&2
  exit 1
fi

# ============================================================
# PHASE 1: Fetch vulnerabilities from Elasticsearch
# ============================================================
echo ""
echo "=== Phase 1: Fetching vulnerabilities from Elasticsearch ==="

UNIQUE_IDS_RESPONSE=`curl -s -XPOST "${ES_HOST}/${ES_INDEX}/_search" \
  -H "${ES_AUTH}" \
  -H "Content-Type: application/json" \
  -d '{
    "size": 0,
    "query": {
      "range": {
        "date": {
          "gte": "now/d",
          "lte": "now/d"
        }
      }
    },
    "aggs": {
      "unique_vuln_ids": {
        "terms": {
          "field": "identifiers.id",
          "size": 10000
        }
      }
    }
  }'`

VULN_IDS=`echo "${UNIQUE_IDS_RESPONSE}" | jq -r '.aggregations.unique_vuln_ids.buckets[].key'`

if [[ -z "${VULN_IDS}" ]]; then
  echo "No vulnerabilities found for today."
  exit 0
fi

TOTAL_VULNS=`echo "${VULN_IDS}" | wc -l | tr -d ' '`
echo "Found ${TOTAL_VULNS} unique Snyk vulnerability IDs."

COUNT=0
SKIPPED=0

while IFS= read -r SNYK_ID; do
  [[ -z "${SNYK_ID}" ]] && continue
  COUNT=$((COUNT + 1))

  # Fetch all documents for this Snyk ID
  DOCS_RESPONSE=`curl -s -X POST "${ES_HOST}/${ES_INDEX}/_search" \
    -H "${ES_AUTH}" \
    -H "Content-Type: application/json" \
    -d "{
      \"size\": 10000,
      \"query\": {
        \"bool\": {
          \"filter\": [
            {
              \"term\": {
                \"identifiers.id\": \"${SNYK_ID}\"
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
    }"`

  DOCS=`echo "${DOCS_RESPONSE}" | jq '[.hits.hits[]._source]'`

  # Extract first CVE from the first document
  CVE=`echo "${DOCS}" | jq -r '.[0].identifiers.CVE | if type == "array" then .[0] elif type == "string" then . else null end // empty'`

  if [[ -z "${CVE:-}" ]]; then
    SKIPPED=$((SKIPPED + 1))
    echo "[${COUNT}/${TOTAL_VULNS}] SKIP ${SNYK_ID} (no CVE)"
    continue
  fi

  OUTPUT_FILE="${TMPDIR}/${CVE}.json"
  echo "${DOCS}" > "${OUTPUT_FILE}"
  echo "[${COUNT}/${TOTAL_VULNS}] Saved ${SNYK_ID} -> ${OUTPUT_FILE}"

done <<< "${VULN_IDS}"

echo ""
echo "Phase 1 complete. $((COUNT - SKIPPED)) CVE files written, ${SKIPPED} skipped (no CVE)."

# ============================================================
# PHASE 2: Check each CVE file against Jira
# ============================================================
echo ""
echo "=== Phase 2: Checking CVEs against Jira ==="

# Search all Jira projects for a given term, return total hits
jira_search() {
  local CVE=`printf '%s' "$1" | sed 's/"/\\"/g'`
  local QUERY="text ~ \"${CVE}\""

  if [[ -n "$2" ]]; then
    local SNYK_ID=`printf '%s' "$2" | sed 's/"/\\"/g'`
    QUERY="${QUERY} OR text ~ \"${SNYK_ID}\""
  fi

  if [[ -n "$3" ]]; then
    local GHSA=`printf '%s' "$3" | sed 's/"/\\"/g'`
    QUERY="${QUERY} OR text ~ \"${GHSA}\""
  fi

  QUERY="${QUERY} ORDER BY created DESC"

  curl -sG "${JIRA_BASE_URL}/rest/api/3/search/jql" \
    -H "${JIRA_AUTH}" \
    -H "Content-Type: application/json" \
    --data-urlencode "jql=${QUERY}" \
    --data-urlencode "fields=summary,key,project" \
	| jq '[.issues[].key]' -c
}

# Append a record to the appropriate severity output file
append_to_severity_file() {
  local severity="$1"
  local record="$2"
  local file

  case "${severity,,}" in
    critical) file="${CRITICAL_FILE}" ;;
    high)     file="${HIGH_FILE}" ;;
    medium)   file="${MEDIUM_FILE}" ;;
    low)      file="${LOW_FILE}" ;;
  esac

  local tmp
  tmp=$(mktemp)
  jq --argjson rec "${record}" '. += [$rec]' "${file}" > "${tmp}"
  mv "${tmp}" "${file}"
}

CVE_FILES=("${TMPDIR}"/CVE-*.json)

if [[ ${#CVE_FILES[@]} -eq 0 ]] || [[ ! -f "${CVE_FILES[0]}" ]]; then
  echo "No CVE files found in ${TMPDIR}."
  exit 0
fi

TOTAL_CVES=${#CVE_FILES[@]}
COUNT=0
MISSING=0
FOUND=0

for FILE in "${CVE_FILES[@]}"; do
  CVE=$(basename "${FILE}" .json)
  COUNT=$((COUNT + 1))

  FIRST_DOC=$(jq '.[0] // {}' "${FILE}")

  SNYK_ID=`echo "${FIRST_DOC}"  | jq -r '.identifiers.ID // .identifiers.id // "" | if type == "array" then .[0] else . end // ""'`
  GHSA=`echo "${FIRST_DOC}"     | jq -r '.identifiers.GHSA // .identifiers.ghsa // "" | if type == "array" then .[0] else . end // ""'`
  SEVERITY=`echo "${FIRST_DOC}" | jq -r '.severity'`
  TITLE=`echo "${FIRST_DOC}"    | jq -r '.title // ""'`
  PUBLISHED=`echo "${FIRST_DOC}" | jq -r '.published // ""'`

  # Search JIRA
  MATCHING=`jira_search "${CVE}" "${SNYK_ID}" "${GHSA}"`
  MATCH_COUNT=`echo ${MATCHING} | jq '. | length //0'`

  if [[ "${MATCH_COUNT}" -gt 0 ]]; then
    FOUND=$((FOUND + 1))
    echo "[${COUNT}/${TOTAL_CVES}] FOUND   ${CVE} (${SEVERITY}) - ${MATCHING}"
  else
    MISSING=$((MISSING + 1))
    echo "[${COUNT}/${TOTAL_CVES}] MISSING ${CVE} (${SEVERITY})"

    RECORD=`jq -n \
      --arg cve       "${CVE}" \
      --arg snyk_id   "${SNYK_ID}" \
      --arg ghsa      "${GHSA}" \
      --arg severity  "${SEVERITY}" \
      --arg title     "${TITLE}" \
      --arg published "${PUBLISHED}" \
      '{
        cve:       $cve,
        snyk_id:   $snyk_id,
        ghsa:      $ghsa,
        severity:  $severity,
        title:     $title,
        published: $published
      }'`

    append_to_severity_file "${SEVERITY}" "${RECORD}"
  fi
done

# ------------------------------------------------------------
# Summary
# ------------------------------------------------------------
echo ""
echo "=== Summary ==="
echo "CVEs checked : ${TOTAL_CVES}"
echo "Found in Jira: ${FOUND}"
echo "Missing      : ${MISSING}"
echo ""
N_CRITICAL=`jq 'length' "${CRITICAL_FILE}"`
N_HIGH=`jq 'length' "${HIGH_FILE}"`
N_MEDIUM=`jq 'length' "${MEDIUM_FILE}"`
N_LOW=`jq 'length' "${LOW_FILE}"`
N_TOTAL=$((N_CRITICAL + N_HIGH + N_MEDIUM + N_LOW))

echo "Missing CVEs by severity:"
printf "%4d critical\n" "${N_CRITICAL}"
printf "%4d high\n"     "${N_HIGH}"
printf "%4d medium\n"   "${N_MEDIUM}"
printf "%4d low\n"      "${N_LOW}"
printf "%4d total\n"    "${N_TOTAL}"
