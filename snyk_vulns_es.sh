#!/bin/bash -e

## Elasticsearch
INDEX=snyk_vulnerabilities
HOST=localhost
PORT=9200

## Cookies
CSRF=
SNYK_ID=

## Headers
X_CSRF_TOKEN=

#================================================================

DATESTAMP=`date +%Y-%m-%dT%H%M`
DATESTAMP_W_COLON=`date +%Y-%m-%dT%H:%M`
OUT_ES=./snyk-vulns.$DATESTAMP.es
PARTS_PREFIX=./snyk-vulns.$DATESTAMP.part_
NEXT=null
PAGE=0

rm -f /tmp/snyk-*
rm -f /tmp/scratch.*
touch $OUT_ES

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
  
  for TARGET_ID in `cat /tmp/snyk-project-stats.$PAGE | jq '.paginatedCollection.collection[].id' -r`; do
    ### Get the projects for a target
    #TARGET_ID=73aaa38e-6b29-4980-80cd-b7d154293a22
	TARGET_NAME=`cat /tmp/snyk-project-stats.$PAGE | jq ".paginatedCollection.collection[] | select(.id == \"$TARGET_ID\") | .name" -r`

    echo $TARGET_NAME

    curl 'https://app.snyk.io/registry/org/folio-org/projects/projects-by-target' \
      -H 'accept: application/json' \
      -H 'content-type: application/json' \
      -b "_csrf=${CSRF}; snyk.id=${SNYK_ID}" \
      -H "x-csrf-token: ${X_CSRF_TOKEN}" \
	  -H "x-requested-with: XMLHttpRequest" \
    --data-raw "{
    \"targetPublicId\":\"$TARGET_ID\",
    \"filters\":{
      \"Show\":[], 
	  \"Integrations\":[],
	  \"CollectionIds\":[]
  	  }
    }" -s -o /tmp/snyk-projects.$TARGET_ID
  
    for PROJECT_ID in `cat /tmp/snyk-projects.$TARGET_ID | jq .projects[].id -r`; do
	
	  PROJECT_JSON=`cat /tmp/snyk-projects.$TARGET_ID | jq ".projects[] | select(.id == \"$PROJECT_ID\") | {id, name, targetFile, type, origin, url: \"https://app.snyk.io/org/folio-org/project/$PROJECT_ID\"}" -c`
	
      curl "https://app.snyk.io/org/folio-org/project/$PROJECT_ID/snapshots" \
	    -H 'accept: application/json' \
        -H 'content-type: application/json' \
        -b "_csrf=${CSRF}; snyk.id=${SNYK_ID}" \
        -H "x-csrf-token: ${X_CSRF_TOKEN}" \
	    -H "x-requested-with: XMLHttpRequest" -s -o /tmp/snyk-snapshots.$TARGET_ID.$PROJECT_ID
	
	  SNAPSHOT_ID=`cat /tmp/snyk-snapshots.$TARGET_ID.$PROJECT_ID | jq .snapshots[0].publicId -r`
	
	  curl "https://app.snyk.io/org/folio-org/project/$PROJECT_ID/vulns/$SNAPSHOT_ID?latest=true" \
        -H 'accept: application/json' \
        -H 'content-type: application/json' \
        -b "_csrf=${CSRF}; snyk.id=${SNYK_ID}" \
        -H "x-csrf-token: ${X_CSRF_TOKEN}" \
	    -H "x-requested-with: XMLHttpRequest" \
		-s | jq '.vulnData |= map(select(.isIgnored != true ))' > /tmp/snyk-vulns.$TARGET_ID.$PROJECT_ID.$SNAPSHOT_ID
		
	  cat /tmp/snyk-vulns.$TARGET_ID.$PROJECT_ID.$SNAPSHOT_ID | jq -c ".vulnData[] | {identifiers} * { identifiers: { id: [.metadata.id] }} * {title: .metadata.title, severity: .metadata.severity, published: .metadata.publicationTime, isNew: .metadata.isNew, name: .metadata.name, overview: .overview, target: { name:\"$TARGET_NAME\", id: \"$TARGET_ID\"}} * {project: $PROJECT_JSON, date: \"$DATESTAMP_W_COLON\"}" > /tmp/scratch.$TARGET_ID.$PROJECT_ID.$SNAPSHOT_ID
	  
	  while IFS= read -r line; do
	    echo "{ \"index\" : { \"_index\" : \"$INDEX\" } }" >> $OUT_ES
		echo $line  >> $OUT_ES
      done < /tmp/scratch.$TARGET_ID.$PROJECT_ID.$SNAPSHOT_ID

    done
  done
  NEXT=`cat /tmp/snyk-project-stats.$PAGE | jq .paginatedCollection.cursors.last`
  PAGE=$((PAGE+1))
done;

split -l 1000 $OUT_ES $PARTS_PREFIX

read -p "Press any key to push to ES..."
for i in `ls $PARTS_PREFIX*`; do
  curl -X POST http://$HOST:$PORT/_bulk?pretty -H "Authorization: ApiKey $APIKEY" -H "Content-Type: application/x-ndjson" --data-binary @$i
done
