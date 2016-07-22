#!/usr/bin/env bash

cd /app;
while true; do
    echo "starting web service...";
    sed -i "s/\"GOOGLE_MAPS_API_KEY\".*/\"GOOGLE_MAPS_API_KEY\": \"$GOOGLE_MAPS_KEY\"/g" /app/pkmn_api/config.json
    cd /app/web
    python -m SimpleHTTPServer 8000
done
