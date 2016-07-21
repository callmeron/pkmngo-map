#!/usr/bin/env bash

cd /app;
while true; do
    echo "starting web service...";
    sed -i "s/\"GOOGLE_MAPS_API_KEY\".*/\"GOOGLE_MAPS_API_KEY\": \"$GOOGLE_MAPS_KEY\"/g" /app/config.json
    python -m SimpleHTTPServer 8000
done