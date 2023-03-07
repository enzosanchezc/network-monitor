#!/bin/bash

if [ -f .env ]; then
  export $(echo $(cat .env | sed 's/#.*//g'| xargs) | envsubst)
fi

FILENAME=last_speedtest.log

speedtest > $FILENAME

PROVIDER=$(grep "Testing from" $FILENAME | cut -d" " -f3- | cut -d"(" -f1 | xargs)
PUBLIC_IP=$(grep "Testing from" $FILENAME | cut -d"(" -f2 | cut -d")" -f1 | xargs)
SPEEDTEST_SERVER=$(grep "Hosted by" $FILENAME | cut -d" " -f3- | cut -d"[" -f1 | xargs)
SERVER_DISTANCE=$(grep "Hosted by" $FILENAME | cut -d"[" -f2 | cut -d" " -f1 | xargs)
PING=$(grep "Hosted by" $FILENAME | cut -d":" -f2 | cut -d" " -f2 | xargs)
DOWNLOAD=$(grep "Download" $FILENAME | cut -d" " -f2 | xargs)
UPLOAD=$(grep "Upload" $FILENAME | cut -d" " -f2 | xargs)

if ! curl -s "http://$INFLUX_HOST:$INFLUX_PORT/query?q=SHOW+DATABASES" | jq '.results[0].series[0].values[][]' | grep $INFLUX_DB > /dev/null; then
	curl -s "http://$INFLUX_HOST:$INFLUX_PORT/query?q=CREATE+DATABASE+$INFLUX_DB"
	echo "Influx DB created"
fi

if [ -z "$SPEEDTEST_SERVER" ]; then
	curl -s -XPOST "http://$INFLUX_HOST:$INFLUX_PORT/write?db=$INFLUX_DB" --data-binary "speedtest provider=\"$PROVIDER\",ip=\"$PUBLIC_IP\",server=\"Unrechable\",distance=0,latency=0,download=0,upload=0"
else
	curl -s -XPOST "http://$INFLUX_HOST:$INFLUX_PORT/write?db=$INFLUX_DB" --data-binary "speedtest provider=\"$PROVIDER\",ip=\"$PUBLIC_IP\",server=\"$SPEEDTEST_SERVER\",distance=$SERVER_DISTANCE,latency=$PING,download=$DOWNLOAD,upload=$UPLOAD"
fi

echo "Point inserted:"
echo "PROVIDER=$PROVIDER"
echo "PUBLIC_IP=$PUBLIC_IP"
echo "SPEEDTEST_SERVER=$SPEEDTEST_SERVER"
echo "SERVER_DISTANCE=$SERVER_DISTANCE"
echo "PING=$PING"
echo "DOWNLOAD=$DOWNLOAD"
echo "UPLOAD=$UPLOAD"
