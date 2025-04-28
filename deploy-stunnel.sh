#!/bin/bash

# Deploy the stunnel service
docker stack deploy -c stunnel-mongodb.yml mongodb-stunnel

# Check the status
echo "Checking service status..."
sleep 5
docker service ls | grep stunnel

echo "Checking logs..."
docker service logs mongodb-stunnel_stunnel -f
