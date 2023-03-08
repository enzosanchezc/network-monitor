#!/bin/bash

if [ -f .env ]; then
  export $(echo $(cat .env | sed 's/#.*//g'| xargs) | envsubst)
fi

FILENAME=last_speedtest.json

speedtest --json > $FILENAME

ISP=$(jq .client.isp $FILENAME)
CLIENT_IP=$(jq .client.ip $FILENAME)
CLIENT_LAT=$(jq .client.lat $FILENAME)
CLIENT_LON=$(jq .client.lon $FILENAME)
CLIENT_CC=$(jq .client.country $FILENAME)
SERVER=$(jq .server.sponsor $FILENAME)
SERVER_LAT=$(jq .server.lat $FILENAME)
SERVER_LON=$(jq .server.lon $FILENAME)
SERVER_CC=$(jq .server.cc $FILENAME)
SERVER_DISTANCE=$(jq .server.d $FILENAME)
PING=$(jq .ping $FILENAME)
DOWNLOAD=$(jq .download $FILENAME)
UPLOAD=$(jq .upload $FILENAME)

if ! curl -s "http://$INFLUX_HOST:$INFLUX_PORT/query?q=SHOW+DATABASES" | jq '.results[0].series[0].values[][]' | grep $INFLUX_DB > /dev/null; then
	curl -s "http://$INFLUX_HOST:$INFLUX_PORT/query?q=CREATE+DATABASE+$INFLUX_DB"
	echo "Influx DB created"
fi

if [ -z "$SERVER" ]; then
	curl -s -XPOST "http://$INFLUX_HOST:$INFLUX_PORT/write?db=$INFLUX_DB" --data-binary "speedtest isp=$ISP,client_ip=$CLIENT_IP,client_lat=$CLIENT_LAT,client_lon=$CLIENT_LON,client_cc=$CLIENT_CC,server=Unrechable,server_lat=$CLIENT_LAT,server_lon=$CLIENT_LON,server_cc=$CLIENT_CC,server_distance=0,latency=0,download=0,upload=0"
else
	curl -s -XPOST "http://$INFLUX_HOST:$INFLUX_PORT/write?db=$INFLUX_DB" --data-binary "speedtest isp=$ISP,client_ip=$CLIENT_IP,client_lat=$CLIENT_LAT,client_lon=$CLIENT_LON,client_cc=$CLIENT_CC,server=$SERVER,server_lat=$SERVER_LAT,server_lon=$SERVER_LON,server_cc=$SERVER_CC,server_distance=$SERVER_DISTANCE,latency=$PING,download=$DOWNLOAD,upload=$UPLOAD"
fi

echo "Point inserted:"
echo "ISP=$ISP"
echo "CLIENT_IP=$CLIENT_IP"
echo "CLIENT_LAT=$CLIENT_LAT"
echo "CLIENT_LON=$CLIENT_LON"
echo "CLIENT_CC=$CLIENT_CC"
echo "SERVER=$SERVER"
echo "SERVER_LAT=$SERVER_LAT"
echo "SERVER_LON=$SERVER_LON"
echo "SERVER_CC=$SERVER_CC"
echo "SERVER_DISTANCE=$SERVER_DISTANCE"
echo "PING=$PING"
echo "DOWNLOAD=$DOWNLOAD"
echo "UPLOAD=$UPLOAD"
