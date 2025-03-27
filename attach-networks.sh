#!/bin/bash

PROXY_SERVICE="proxy_proxy"

echo "Waiting for $PROXY_SERVICE to be deployed..."
sleep 5  # Give Swarm time to initialize

# Get all org_* networks
ORG_NETWORKS=$(docker network ls --format '{{.Name}}' | grep '^org_')

if [ -z "$ORG_NETWORKS" ]; then
    echo "No org_* networks found. Exiting."
    exit 0
fi

# Construct the update command with all networks
UPDATE_CMD="docker service update $PROXY_SERVICE"
for NET in $ORG_NETWORKS; do
    UPDATE_CMD+=" --network-add $NET"
done

echo "Executing: $UPDATE_CMD"
eval "$UPDATE_CMD"

echo "✅ All org networks attached in one update!"
