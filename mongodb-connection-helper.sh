#!/bin/bash

# This script helps generate MongoDB connection strings for use with stunnel

echo "MongoDB Connection String Helper"
echo "================================"
echo ""

# Weteka MongoDB
echo "For Weteka MongoDB:"
echo "mongodb://admin:YOUR_PASSWORD@weteka-mongodb-67f532-9fac8609-0c996391.koompi.cloud:27017/?ssl=true&tlsAllowInvalidCertificates=true"
echo ""

# Riverbase MongoDB
echo "For Riverbase MongoDB:"
echo "mongodb://admin:YOUR_PASSWORD@riverbase-mongodb-67f532-b404d4af-a211fcb5.koompi.cloud:27018/?ssl=true&tlsAllowInvalidCertificates=true"
echo ""

echo "Note: Replace YOUR_PASSWORD with the actual password for each MongoDB instance."
echo "The tlsAllowInvalidCertificates=true parameter is needed if your certificates are not trusted by the client."
