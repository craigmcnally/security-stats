#!/bin/bash -ex

## Cookies
CSRF=
SNYK_ID=

## Headers
X_CSRF_TOKEN=

## Params

# the vulnerability id... used to read a file: $VULN_ID.json which contains 
# info about exactly what should be ignored (records the from 
# snyk_vulnerabilities index in ES).
VULN_ID=$1

# the ignore message... hint: use quotes.
MESSAGE=$2

#================================================================

rm -f ignore_report.$VULN_ID

for PROJECT_ID in `cat $VULN_ID.json | jq '.[].fields."project.id"'[0] -r`; do 
  curl "https://app.snyk.io/org/folio-org/project/$PROJECT_ID/ignore/$VULN_ID" \
    -XPOST \
    -H 'accept: application/json' \
    -H 'content-type: application/json' \
    -b "_csrf=${CSRF}; snyk.id=${SNYK_ID}" \
    -H "x-csrf-token: ${X_CSRF_TOKEN}" \
    -H "x-requested-with: XMLHttpRequest" \
    --data-raw "
{
  \"reasonType\": \"not-vulnerable\",
  \"reason\": \"$MESSAGE\",
  \"expires\": null,
  \"disregardIfFixable\": false
}" -w'\n' -D - >> ignore_report.$VULN_ID

  echo "https://app.snyk.io/org/folio-org/project/$PROJECT_ID/ignore/$VULN_ID"
done
