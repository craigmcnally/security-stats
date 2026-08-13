#!/bin/bash
set -euo pipefail

# ============================================================
# create_jira_issue.sh
#
# Reads a vulnerability file produced by snyk_jira_check.sh, builds a
# Jira issue body from jira-issue-template.json, shows a
# draft for review, then creates the issue in the SECURITY
# project on folio-org.atlassian.net.
#
# Usage: ./create_jira_issue.sh <VULN-ID>
#   e.g. ./create_jira_issue.sh CVE-2024-12345
# ============================================================

JIRA_BASE_URL="https://api.atlassian.com"
JIRA_CLOUD_ID="${JIRA_CLOUD_ID:-11f731c9-c476-4b99-a086-9ad1c7425130}"
VULN_DIR="${VULN_DIR:-/tmp/snyk_cve_files}"
TEMPLATE_FILE="${TEMPLATE_FILE:-$(dirname "$0")/jira-issue-template.json}"

# ------------------------------------------------------------
# Validate arguments
# ------------------------------------------------------------
if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <VULN-ID>" >&2
  echo "  e.g. $0 CVE-2024-12345" >&2
  echo "  e.g. $0 GHSA-aaaa-bbbb-cccc" >&2
  exit 1
fi

VULN="$1"
VULN_FILE="${VULN_DIR}/${VULN}.json"

if [[ ! -f "${VULN_FILE}" ]]; then
  echo "Error: Vulnerability file not found: ${VULN_FILE}" >&2
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
FIRST_DOC=$(jq '.[0]' "${VULN_FILE}")

SNYK_ID=$(echo "${FIRST_DOC}"   | jq -r '.identifiers.id // .identifiers.ID // "" | if type == "array" then .[0] else . end // ""')
CVE=$(echo "${FIRST_DOC}"       | jq -r '.identifiers.CVE // "" | if type == "array" then .[0] else . end // ""')
GHSA=$(echo "${FIRST_DOC}"      | jq -r '.identifiers.GHSA // "" | if type == "array" then .[0] else . end // ""')
SEVERITY=$(echo "${FIRST_DOC}"  | jq -r '.severity // "unknown"')
AFFECTING=$(echo "${FIRST_DOC}" | jq -r '.name // ""')
TITLE=$(echo "${FIRST_DOC}"     | jq -r '.title // ""')
OVERVIEW=$(echo "${FIRST_DOC}"  | jq -r '.overview // ""' | sed 's/^## Overview$//' | sed '/^$/d')

if [[ "${OVERVIEW}" == "" && "${CVE}" != "" ]]; then
  echo "No overview found, retrieving one from nvd.nist.gov..."
  OVERVIEW=$(curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?cveIds=${CVE}" | jq -r '.vulnerabilities[0].cve.descriptions[0].value // ""' | sed '/^$/d')
fi

if [[ "${OVERVIEW}" == "" && "${GHSA}" != "" ]]; then
  echo "No overview found, retrieving one from GitHub..."
  DESCRIPTION=$(curl -s "https://api.github.com/advisories/${GHSA}" -H "Accept: application/vnd.github+json" -H "X-GitHub-Api-Version: 2026-03-10" | jq -r '.[0].description // ""')
  DELIM="## Impact"
  OVERVIEW=$(echo "${DESCRIPTION%%$DELIM*}" | sed 's/^## Summary//' | sed '/^$/d')
fi

# ------------------------------------------------------------
# Build LINKS bullet list
# ------------------------------------------------------------
LINKS="* https://security.snyk.io/vuln/${SNYK_ID}"
if [[ -n "${CVE}" ]]; then 
  LINKS+=$'\n'"* https://nvd.nist.gov/vuln/detail/${CVE}"
fi

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
done < <(jq -r '.[].project.name // "" | select(. != "")' "${VULN_FILE}" | sort -u)

if [[ -z "${MODULES_IMPACTED}" ]]; then
  MODULES_IMPACTED="| (none) |"$'\n'
fi

# ------------------------------------------------------------
# Build summary and description using jq for safe JSON encoding
# ------------------------------------------------------------
SUMMARY=`jq -rn \
  --arg vuln      "${VULN}" \
  --arg affecting "${AFFECTING}" \
  --arg title     "${TITLE}" \
  '"{{VULN}} - {{AFFECTING}} - {{TITLE}}"
   | gsub("{{VULN}}";       $vuln)
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

RESPONSE=`curl -XPOST "${JIRA_BASE_URL}/ex/jira/${JIRA_CLOUD_ID}/rest/api/2/issue" \
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
