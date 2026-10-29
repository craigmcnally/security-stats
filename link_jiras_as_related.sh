#!/bin/bash
set -euo pipefail

# ============================================================
# link_jiras_as_related.sh
#
# Links a set of Jira issues to one another ("relates to" by default).
# Every issue given is linked to every other issue given (pairwise),
# skipping any pair that already carries a link of the chosen type.
#
# Usage: ./link_jiras_as_related.sh KEY-1 KEY-2 [KEY-3 ...]
#   Keys may also be given as a single comma- and/or space-separated
#   argument, e.g. "SECURITY-1867, SECURITY-1868, SECURITY-1869".
#   Every issue is verified to exist before any links are created; if
#   any key cannot be found, the script errors out and makes no changes.
#
# Environment variables:
#   JIRA_USER        Jira account email (required)
#   JIRA_API_TOKEN   Jira API token (required)
#   JIRA_CLOUD_ID    Atlassian cloud id (default: folio-org)
# ============================================================

JIRA_BASE_URL="https://api.atlassian.com"
JIRA_CLOUD_ID="${JIRA_CLOUD_ID:-11f731c9-c476-4b99-a086-9ad1c7425130}"
JIRA_API="${JIRA_BASE_URL}/ex/jira/${JIRA_CLOUD_ID}/rest/api/2"
JIRA_LINK_TYPE="Relates"

usage() {
  sed -n '/^# Usage:/,/^# ====/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ $# -eq 0 ]]; then
  usage >&2
  exit 1
fi

# ------------------------------------------------------------
# Validate required environment variables
# ------------------------------------------------------------
if [[ -z "${JIRA_API_TOKEN:-}" ]]; then
  echo "Error: JIRA_API_TOKEN environment variable is not set." >&2
  exit 1
fi

if [[ -z "${JIRA_USER:-}" ]]; then
  echo "Error: JIRA_USER environment variable is not set (e.g. user@example.com)." >&2
  exit 1
fi

JIRA_AUTH="Authorization: Basic $(echo -n "${JIRA_USER}:${JIRA_API_TOKEN}" | base64 -w0)"

# ------------------------------------------------------------
# Parse and normalize the issue keys given on the command line.
#
# Splits every argument on commas/whitespace into tokens, each of
# which must look like a Jira key (PROJECT-NUMBER).
# ------------------------------------------------------------
RAW_TOKENS=()
for ARG in "$@"; do
  while IFS= read -r TOK; do
    [[ -n "${TOK}" ]] && RAW_TOKENS+=("${TOK}")
  done < <(echo "${ARG}" | tr ',' '\n' | tr -s '[:space:]' '\n')
done

ISSUES=()
for TOK in "${RAW_TOKENS[@]}"; do
  TOK="${TOK^^}"
  if [[ "${TOK}" =~ ^[A-Z][A-Z0-9_]*-[0-9]+$ ]]; then
    ISSUES+=("${TOK}")
  else
    echo "Error: '${TOK}' does not look like a Jira issue key (expected PROJECT-NUMBER, e.g. SECURITY-1868)." >&2
    exit 1
  fi
done

# Dedupe while preserving order
UNIQUE_ISSUES=()
declare -A SEEN
for ISSUE in "${ISSUES[@]}"; do
  if [[ -z "${SEEN[${ISSUE}]:-}" ]]; then
    SEEN["${ISSUE}"]=1
    UNIQUE_ISSUES+=("${ISSUE}")
  fi
done
ISSUES=("${UNIQUE_ISSUES[@]}")

if [[ ${#ISSUES[@]} -lt 2 ]]; then
  echo "Error: need at least 2 distinct issue keys to link; got: ${ISSUES[*]:-none}" >&2
  exit 1
fi

echo "Issues to link (${#ISSUES[@]}): ${ISSUES[*]}"
echo "Link type: ${JIRA_LINK_TYPE}"

# ------------------------------------------------------------
# Check access to JIRA
# ------------------------------------------------------------
echo "Checking access to JIRA..."
HTTP_CODE=`curl -G "${JIRA_API}/issue/${ISSUES[0]}" -H "${JIRA_AUTH}" -sko /dev/null -w "%{http_code}"`
if [[ "${HTTP_CODE}" != "200" && "${HTTP_CODE}" != "404" ]]; then
  echo "Error: Call to JIRA failed: ${JIRA_API}/issue/${ISSUES[0]} (${HTTP_CODE})" >&2
  exit 1
fi

# ------------------------------------------------------------
# Resolve and validate the link type name against Jira's configured
# issue link types (case-insensitive match on name).
# ------------------------------------------------------------
LINK_TYPES=`curl --retry 3 --retry-delay 1 --retry-connrefused --retry-all-errors -s "${JIRA_API}/issueLinkType" -H "${JIRA_AUTH}"`

RESOLVED_TYPE=`echo "${LINK_TYPES}" | jq -r --arg t "${JIRA_LINK_TYPE}" \
  '.issueLinkTypes[] | select(.name | ascii_downcase == ($t | ascii_downcase)) | .name' | head -n1`

if [[ -z "${RESOLVED_TYPE}" ]]; then
  echo "Error: link type '${JIRA_LINK_TYPE}' not found. Available types:" >&2
  echo "${LINK_TYPES}" | jq -r '.issueLinkTypes[].name' >&2
  exit 1
fi

JIRA_LINK_TYPE="${RESOLVED_TYPE}"
echo "Resolved link type: ${JIRA_LINK_TYPE}"

# ------------------------------------------------------------
# Verify every issue exists, and fetch its existing links, before
# making any changes. If any issue cannot be found, bail out here
# without creating any links.
# ------------------------------------------------------------
WORK_DIR=$(mktemp -d)
trap 'rm -rf "${WORK_DIR}"' EXIT

echo "Verifying all ${#ISSUES[@]} issue(s) exist..."

declare -A EXISTING_LINKS
NOT_FOUND=()
for ISSUE in "${ISSUES[@]}"; do
  RESP_FILE="${WORK_DIR}/${ISSUE}.json"
  HTTP_CODE=`curl --retry 3 --retry-delay 1 --retry-connrefused --retry-all-errors -sG \
    -o "${RESP_FILE}" -w "%{http_code}" "${JIRA_API}/issue/${ISSUE}" \
    -H "${JIRA_AUTH}" \
    --data-urlencode "fields=issuelinks"`

  if [[ "${HTTP_CODE}" != "200" ]]; then
    NOT_FOUND+=("${ISSUE} (HTTP ${HTTP_CODE})")
    continue
  fi

  LINKED_KEYS=`jq -r --arg t "${JIRA_LINK_TYPE}" \
    '.fields.issuelinks[]? | select(.type.name == $t) | (.inwardIssue.key // .outwardIssue.key)' "${RESP_FILE}"`
  while IFS= read -r KEY; do
    [[ -z "${KEY}" ]] && continue
    EXISTING_LINKS["${ISSUE}|${KEY}"]=1
    EXISTING_LINKS["${KEY}|${ISSUE}"]=1
  done <<< "${LINKED_KEYS}"
done

if [[ ${#NOT_FOUND[@]} -gt 0 ]]; then
  echo "Error: the following issue(s) could not be found; no links were created:" >&2
  for ENTRY in "${NOT_FOUND[@]}"; do
    echo "  ${ENTRY}" >&2
  done
  exit 1
fi

echo "All issues exist."

# ------------------------------------------------------------
# Build the list of pairs to link
# ------------------------------------------------------------
PAIRS_FILE="${WORK_DIR}/pairs.tsv"
: > "${PAIRS_FILE}"

N=${#ISSUES[@]}
for ((a = 0; a < N; a++)); do
  for ((b = a + 1; b < N; b++)); do
    A="${ISSUES[$a]}"
    B="${ISSUES[$b]}"
    if [[ -n "${EXISTING_LINKS[${A}|${B}]:-}" ]]; then
      echo "Skipping ${A} <-> ${B} (already linked via '${JIRA_LINK_TYPE}')"
    else
      printf "%s\t%s\n" "${A}" "${B}" >> "${PAIRS_FILE}"
    fi
  done
done

TOTAL=`wc -l < "${PAIRS_FILE}" | tr -d ' '`

if [[ "${TOTAL}" -eq 0 ]]; then
  echo ""
  echo "Nothing to do; all pairs are already linked."
  exit 0
fi

echo ""
echo "Creating ${TOTAL} link(s)..."

DONE=0
FAILED=0
COUNT=0

while IFS=$'\t' read -r A B; do
  COUNT=$((COUNT + 1))

  BODY=`jq -n --arg type "${JIRA_LINK_TYPE}" --arg inward "${A}" --arg outward "${B}" \
    '{type: {name: $type}, inwardIssue: {key: $inward}, outwardIssue: {key: $outward}}'`

  HTTP_CODE=`curl --retry 3 --retry-delay 1 --retry-connrefused --retry-all-errors -s -o "${WORK_DIR}/resp.txt" -w "%{http_code}" \
    -XPOST "${JIRA_API}/issueLink" \
    -H "${JIRA_AUTH}" \
    -H "Content-Type: application/json" \
    -d "${BODY}"`

  if [[ "${HTTP_CODE}" == "201" ]]; then
    DONE=$((DONE + 1))
    echo "[${COUNT}/${TOTAL}] ${A} <-> ${B}"
  else
    FAILED=$((FAILED + 1))
    echo "[${COUNT}/${TOTAL}] FAILED ${A} <-> ${B} (HTTP ${HTTP_CODE}): $(cat "${WORK_DIR}/resp.txt")" >&2
  fi
done < "${PAIRS_FILE}"

echo ""
echo "=== Summary ==="
echo "Issues linked together : ${#ISSUES[@]}"
echo "Link type               : ${JIRA_LINK_TYPE}"
echo "Links created           : ${DONE}"
echo "Links failed            : ${FAILED}"

[[ "${FAILED}" -eq 0 ]] || exit 1
