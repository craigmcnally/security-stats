#!/bin/bash
set -euo pipefail

# ============================================================
# create_jira_issue.sh
#
# Reads a CVE file produced by snyk_jira_check.sh, builds a
# Jira issue body from jira-issue-template.json, shows a
# draft for review, then creates the issue in the SECURITY
# project on folio-org.atlassian.net.
#
# Usage: ./create_jira_issue.sh <CVE-ID>
#   e.g. ./create_jira_issue.sh CVE-2024-12345
# ============================================================

JIRA_BASE_URL="https://folio-org.atlassian.net"
CVE_DIR="${CVE_DIR:-/tmp/snyk_cve_files}"
TEMPLATE_FILE="${TEMPLATE_FILE:-$(dirname "$0")/jira-issue-template.json}"

# ------------------------------------------------------------
# Validate arguments
# ------------------------------------------------------------
if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <CVE-ID>" >&2
  echo "  e.g. $0 CVE-2024-12345" >&2
  exit 1
fi

CVE="$1"
CVE_FILE="${CVE_DIR}/${CVE}.json"

if [[ ! -f "${CVE_FILE}" ]]; then
  echo "Error: CVE file not found: ${CVE_FILE}" >&2
  exit 1
fi

if [[ ! -f "${TEMPLATE_FILE}" ]]; then
  echo "Error: Template file not found: ${TEMPLATE_FILE}" >&2
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
# Extract fields from CVE file
# ------------------------------------------------------------
FIRST_DOC=$(jq '.[0]' "${CVE_FILE}")

SNYK_ID=$(echo "${FIRST_DOC}"   | jq -r '.identifiers.id // .identifiers.ID // "" | if type == "array" then .[0] else . end // ""')
GHSA=$(echo "${FIRST_DOC}"      | jq -r '.identifiers.GHSA // "" | if type == "array" then .[0] else . end // ""')
SEVERITY=$(echo "${FIRST_DOC}"  | jq -r '.severity // "unknown"')
AFFECTING=$(echo "${FIRST_DOC}" | jq -r '.name // ""')
TITLE=$(echo "${FIRST_DOC}"     | jq -r '.title // ""')
OVERVIEW=$(echo "${FIRST_DOC}"  | jq -r '.overview // ""' | sed 's/^## Overview$//' | sed '/^$/d; 1{/^$/d}')

# ------------------------------------------------------------
# Build LINKS bullet list
# ------------------------------------------------------------
LINKS="* https://security.snyk.io/vuln/${SNYK_ID}"
LINKS+=$'\n'"* https://nvd.nist.gov/vuln/detail/${CVE}"
if [[ -n "${GHSA}" ]]; then
  LINKS+=$'\n'"* https://github.com/advisories/${GHSA}"
fi

# ------------------------------------------------------------
# Build MODULES_IMPACTED single-column table
# ------------------------------------------------------------
MODULES_IMPACTED=""
while IFS= read -r NAME; do
  [[ -z "${NAME}" ]] && continue
  MODULES_IMPACTED+="| ${NAME} |"$'\n'
done < <(jq -r '.[].project.name // "" | select(. != "")' "${CVE_FILE}" | sort -u)

if [[ -z "${MODULES_IMPACTED}" ]]; then
  MODULES_IMPACTED="| (none) |"$'\n'
fi

# ------------------------------------------------------------
# Build summary and description using jq for safe JSON encoding
# ------------------------------------------------------------
SUMMARY=`jq -rn \
  --arg cve       "${CVE}" \
  --arg affecting "${AFFECTING}" \
  --arg title     "${TITLE}" \
  '"{{CVE}} - {{AFFECTING}} - {{TITLE}}"
   | gsub("{{CVE}}";       $cve)
   | gsub("{{AFFECTING}}"; $affecting)
   | gsub("{{TITLE}}";     $title)'`

DESCRIPTION=`jq -rn \
  --arg severity  "${SEVERITY}" \
  --arg links     "${LINKS}" \
  --arg affecting "${AFFECTING}" \
  --arg overview  "${OVERVIEW}" \
  --arg modules   "${MODULES_IMPACTED}" \
  '"*Severity*: {{SEVERITY}}\n\n*Link*:\n\n{{LINKS}}\n\n*Affecting*: {{AFFECTING}}\n\n*Overview*:\n{{OVERVIEW}}\n\n*Modules impacted*:\n\n{{MODULES_IMPACTED}}"
   | gsub("{{SEVERITY}}";         $severity)
   | gsub("{{LINKS}}";            $links)
   | gsub("{{AFFECTING}}";        $affecting)
   | gsub("{{OVERVIEW}}";         $overview)
   | gsub("{{MODULES_IMPACTED}}"; $modules)'`

# ------------------------------------------------------------
# Build the final Jira API payload using jq
# ------------------------------------------------------------
PAYLOAD=`jq -n \
  --arg summary     "${SUMMARY}" \
  --arg description "${DESCRIPTION}" \
  --slurpfile tmpl  "${TEMPLATE_FILE}" \
  '$tmpl[0] | .fields.summary = $summary | .fields.description = $description'`

# ------------------------------------------------------------
# Show draft and prompt for confirmation
# ------------------------------------------------------------
echo ""
echo "================================================================"
echo " DRAFT JIRA ISSUE"
echo "================================================================"
echo ""
echo "Summary: ${SUMMARY}"
echo ""
echo "Description:"
echo "${DESCRIPTION}"
echo ""
echo "================================================================"
echo ""
read -rp "Create this issue in JIRA SECURITY project? [y/N] " CONFIRM

if [[ "${CONFIRM,,}" != "y" ]]; then
  echo "Aborted."
  exit 0
fi

# ------------------------------------------------------------
# Create the Jira issue
# ------------------------------------------------------------
echo ""
echo "Creating Jira issue..."

RESPONSE=`curl -XPOST "${JIRA_BASE_URL}/rest/api/2/issue" \
  -H "${JIRA_AUTH}" \
  -H "Content-Type: application/json" \
  -sd "${PAYLOAD}"`

ISSUE_KEY=`echo "${RESPONSE}" | jq -r '.key // empty'`

if [[ -z "${ISSUE_KEY}" ]]; then
  echo "Error creating issue. Response:" >&2
  echo "${RESPONSE}" | jq . >&2
  exit 1
fi

echo "Created: ${JIRA_BASE_URL}/browse/${ISSUE_KEY}"