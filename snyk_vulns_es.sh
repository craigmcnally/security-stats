#!/bin/bash
set -euo pipefail

# ============================================================
# snyk_vuln_es.sh
#
# 1. Fetch vulnerabilities in snyk for all targets/projects
# 2. Insert vulnerability data into Elasticsearch
#
# Usage: snyk_vulns_es.sh [-h|--help] [ES_FILE]
#
#   ES_FILE  (optional) Path to an existing Elasticsearch bulk (.es) file,
#            e.g. one produced by a previous run.  If given, Phase 1 (fetching
#            from Snyk) is skipped entirely and ES_FILE is treated as the
#            complete data set, going straight to Phase 2 (insert into
#            Elasticsearch).  This does NOT resume a partial fetch.
#            If omitted, Phase 1 runs and writes a new file named
#            ./snyk-vulns.<timestamp>.es
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

#================================================================

usage() {
  cat <<EOF
Usage: $(basename "$0") [-h|--help] [ES_FILE]

Fetch vulnerabilities from Snyk and insert them into Elasticsearch.

  ES_FILE  Optional. Path to an existing Elasticsearch bulk (.es) file from a
           previous run. If given, fetching from Snyk (Phase 1) is skipped and
           ES_FILE is inserted into Elasticsearch as-is (Phase 2). If omitted,
           Phase 1 runs and writes ./snyk-vulns.<timestamp>.es

Required environment variables: SNYK_ID, X_CSRF_TOKEN, ES_API_KEY
Optional environment variables: ES_HOST, ES_INDEX, SNYK_HOST
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

DATESTAMP=`date +%Y-%m-%dT%H%M`
DATESTAMP_W_COLON=`date +%Y-%m-%dT%H:%M`
OUT_ES="${1:-./snyk-vulns.${DATESTAMP}.es}"
PARTS_PREFIX=./snyk-vulns.${DATESTAMP}.part_
NEXT=null
PAGE=0

# Retry transient failures (network drops, timeouts, 429/5xx) with exponential backoff
CURL_RETRY="--retry 5 --retry-all-errors --connect-timeout 10 --max-time 60"

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

ES_AUTH="Authorization: ApiKey ${ES_API_KEY}"

# ------------------------------------------------------------
# Clean up and recreate working directories
# ------------------------------------------------------------
echo "Cleaning up previous run artifacts..."

rm -f /tmp/snyk-*
rm -f /tmp/scratch.*
touch ${OUT_ES}

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
# PHASE 1: Fetch all vulnerabilities from Snyk
# ============================================================
echo ""
echo "=== Phase 1: Fetching vulnerability data from Snyk ==="

if [[ -z "${1:-}" ]]; then

  echo "Getting total target count..."
  curl -XPOST "${SNYK_HOST}/registry/org/folio-org/targets/initialState" \
    ${CURL_RETRY} \
    -H 'content-length: 0' \
    -b "snyk.id=${SNYK_ID}" \
    -H "x-csrf-token: ${X_CSRF_TOKEN}" \
    -H 'x-requested-with: XMLHttpRequest' -sko /tmp/snyk-initial-state
  TOTAL_TARGETS=`jq '.totalTargets // 0' /tmp/snyk-initial-state`

  echo "Fetching vulnerabilities from Snyk..."
  COUNT=0
  while [[ ${PAGE} -lt 1 || ${NEXT} != null ]]; do
    curl "${SNYK_HOST}/registry/org/folio-org/targets" \
      ${CURL_RETRY} \
      -H 'accept: application/json' \
      -H 'content-type: application/json' \
      -b "snyk.id=${SNYK_ID}" \
      -H "x-csrf-token: ${X_CSRF_TOKEN}" \
      -H "x-requested-with: XMLHttpRequest" \
      -d "{
      \"filters\":{
        \"Show\":[],
        \"Integrations\":[],
        \"CollectionIds\":[]
      },
      \"searchQuery\":\"\",
      \"paginationParams\":{
        \"after\":${NEXT},
        \"before\":null,
        \"limit\":50,
        \"options\":{
          \"calcTotal\":true
        },
        \"sort\":{
          \"unique\":\"id\",
          \"optional\":[\"displayName\"],
          \"direction\":\"ASC\"
        }
      }
    }" -sko /tmp/snyk-project-stats.${PAGE}

    for TARGET_ID in `cat /tmp/snyk-project-stats.${PAGE} | jq '.paginatedCollection.collection[].id' -r`; do
      # Get the projects for a target
      TARGET_NAME=`cat /tmp/snyk-project-stats.${PAGE} | jq ".paginatedCollection.collection[] | select(.id == \"${TARGET_ID}\") | .name" -r`
      COUNT=$((COUNT + 1))
      echo "[${COUNT}/${TOTAL_TARGETS}] ${TARGET_NAME}"

      curl "${SNYK_HOST}/registry/org/folio-org/projects/projects-by-target" \
        ${CURL_RETRY} \
        -H 'accept: application/json' \
        -H 'content-type: application/json' \
        -b "snyk.id=${SNYK_ID}" \
        -H "x-csrf-token: ${X_CSRF_TOKEN}" \
        -H "x-requested-with: XMLHttpRequest" \
        --data-raw "{
        \"targetPublicId\":\"${TARGET_ID}\",
        \"filters\":{
          \"Show\":[],
          \"Integrations\":[],
          \"CollectionIds\":[]
        }
      }" -sko /tmp/snyk-projects.${TARGET_ID}

      for PROJECT_ID in `cat /tmp/snyk-projects.${TARGET_ID} | jq .projects[].id -r`; do
          PROJECT_JSON=`cat /tmp/snyk-projects.${TARGET_ID} | jq ".projects[] | select(.id == \"${PROJECT_ID}\") | {id, name, targetFile, type, origin, url: \"${SNYK_HOST}/org/folio-org/project/${PROJECT_ID}\"}" -c`

        curl "${SNYK_HOST}/org/folio-org/project/${PROJECT_ID}/snapshots" \
          ${CURL_RETRY} \
          -H 'accept: application/json' \
          -H 'content-type: application/json' \
          -b "snyk.id=${SNYK_ID}" \
          -H "x-csrf-token: ${X_CSRF_TOKEN}" \
          -H "x-requested-with: XMLHttpRequest" -sko /tmp/snyk-snapshots.${TARGET_ID}.${PROJECT_ID}

        SNAPSHOT_ID=`cat /tmp/snyk-snapshots.${TARGET_ID}.${PROJECT_ID} | jq .snapshots[0].publicId -r`

        curl "${SNYK_HOST}/org/folio-org/project/${PROJECT_ID}/vulns/${SNAPSHOT_ID}?latest=true" \
          ${CURL_RETRY} \
          -H 'accept: application/json' \
          -H 'content-type: application/json' \
          -b "snyk.id=${SNYK_ID}" \
          -H "x-csrf-token: ${X_CSRF_TOKEN}" \
          -H "x-requested-with: XMLHttpRequest" \
          -sko /tmp/snyk-vulns-raw.${TARGET_ID}.${PROJECT_ID}.${SNAPSHOT_ID}

        jq '.vulnData |= map(select(.isIgnored != true ))' /tmp/snyk-vulns-raw.${TARGET_ID}.${PROJECT_ID}.${SNAPSHOT_ID} > /tmp/snyk-vulns.${TARGET_ID}.${PROJECT_ID}.${SNAPSHOT_ID}

        cat /tmp/snyk-vulns.${TARGET_ID}.${PROJECT_ID}.${SNAPSHOT_ID} | jq -c ".vulnData[] | {identifiers} * { identifiers: { id: [.metadata.id] }} * {title: .metadata.title, severity: .metadata.severity, published: .metadata.publicationTime, isNew: .metadata.isNew, name: .metadata.name, overview: .overview, target: { name:\"${TARGET_NAME}\", id: \"${TARGET_ID}\"}} * {project: ${PROJECT_JSON}, date: \"${DATESTAMP_W_COLON}\"}" > /tmp/scratch.${TARGET_ID}.${PROJECT_ID}.${SNAPSHOT_ID}

        while IFS= read -r line; do
          echo "{ \"index\" : { \"_index\" : \"${ES_INDEX}\" } }" >> ${OUT_ES}
          echo "${line}"  >> ${OUT_ES}
        done < /tmp/scratch.${TARGET_ID}.${PROJECT_ID}.${SNAPSHOT_ID}
      done
    done
    NEXT=`cat /tmp/snyk-project-stats.${PAGE} | jq .paginatedCollection.cursors.last`
    PAGE=$((PAGE+1))
  done;

  echo ""
  echo "Phase 1 complete. Vulnerability data obtaind for ${COUNT} targets."

else
  echo ""
  echo "Skip fetching.  Vulnerability data file specified: ${OUT_ES}."
fi

# ============================================================
# PHASE 2: Insert vulnerability data into Elasticsearch
# ============================================================
echo ""
echo "=== Phase 2: Insert vulnerability data into Elasticsearch ==="

echo ""
echo "Preparing data for insertion into Elasticsearch..."
# Need to split since ES will reject requests which are too large
split -l 1000 ${OUT_ES} ${PARTS_PREFIX}

read -rp "Proceed with push to Elasticsearch (index: ${ES_INDEX})? [y/N] " CONFIRM
if [[ "${CONFIRM,,}" != "y" ]]; then
  echo "Aborted."
  exit 0
fi

echo "Inserting data into Elasticsearch..."
for i in `ls ${PARTS_PREFIX}*`; do
  printf '%s\t' ${i}
  curl -XPOST ${ES_HOST}/_bulk?pretty \
    -H "${ES_AUTH}" \
    -H "Content-Type: application/x-ndjson" \
    -sko /dev/null -w "%{http_code}\n" \
    --data-binary @${i}
done

echo "Done!"
