#! /bin/bash -xe

## Elasticsearch
INDEX=snyk_targets
HOST=localhost
PORT=9200

## Cookies
CSRF=
SNYK_ID=

## Headers
X_CSRF_TOKEN=

#================================================================

DATESTAMP=`date +%Y-%m-%dT%H%M`
OUT=./snyk-project-stats.$DATESTAMP.tsv
OUT_ES=./snyk-project-stats.$DATESTAMP.es
NEXT=null
PAGE=0

rm -f /tmp/snyk-project-stats.*
echo "" > $OUT
echo "" > $OUT_ES

while [[ $PAGE -lt 1 || $NEXT != null ]]; do
  curl 'https://app.snyk.io/registry/org/folio-org/targets' \
    -H 'accept: application/json' \
    -H 'content-type: application/json' \
    -b "_csrf=${CSRF}; snyk.id=${SNYK_ID}" \
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
  }" -s -o /tmp/snyk-project-stats.$PAGE
  
  cat /tmp/snyk-project-stats.$PAGE | jq '.paginatedCollection.collection[] | "\(.name)\t\(.issueCounts.critical)\t\(.issueCounts.high)\t\(.issueCounts.medium)\t\(.issueCounts.low)"' -r >> $OUT
  
  for i in `cat /tmp/snyk-project-stats.$PAGE | jq -c ".paginatedCollection.collection[] | {id,name,targetData,issueCounts} + {\"date\": \"$DATESTAMP\"}"`; do
    printf '{ "index" : { "_index" : "%s" } }\n%s\n' $INDEX $i >> $OUT_ES
  done

  NEXT=`cat /tmp/snyk-project-stats.$PAGE | jq .paginatedCollection.cursors.last`
  PAGE=$((PAGE+1))
done;

ln -sf `readlink latest` prev
ln -sf $OUT latest
ln -sf $OUT_ES es

#ls -l prev latest
PROJ_PREV=`wc -l prev | cut -d\  -f1`
PROJ_LATEST=`wc -l latest | cut -d\  -f1`

echo "========================================="
echo "Comparing: "
readlink prev latest
echo -e "#name\tc\th\tm\tl"
echo "========================================="
# diff will use exit code 1 if there are differences, which doesn't play well with the -e bash switch
# so OR with true
diff -y --suppress-common-lines -W150 prev latest || true

read -p "Press any key to push to ES..."
curl -X POST http://$HOST:$PORT/_bulk?pretty -H "Authorization: ApiKey $APIKEY" -H "Content-Type: application/x-ndjson" --data-binary @es
