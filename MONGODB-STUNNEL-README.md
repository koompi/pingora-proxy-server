# MongoDB TLS Proxy with stunnel

This setup uses stunnel to provide TLS termination for MongoDB connections. It allows MongoDB clients to connect securely using TLS, while the backend MongoDB servers don't need to be configured for TLS.

## How It Works

```
[MongoDB Client] <-- TLS --> [stunnel] <-- Plain TCP --> [MongoDB Server]
```

1. The client connects to stunnel using TLS
2. stunnel terminates the TLS connection and extracts the SNI hostname
3. Based on the SNI hostname, stunnel forwards the connection to the appropriate MongoDB server
4. The MongoDB server receives plain TCP traffic

## Deployment

1. Make sure you have the necessary certificates in `/certbot/letsencrypt/live/`
2. Deploy the stunnel service:
   ```
   ./deploy-stunnel.sh
   ```

## Connection Strings

Run the helper script to get connection strings for your MongoDB instances:
```
./mongodb-connection-helper.sh
```

Example connection string:
```
mongodb://admin:YOUR_PASSWORD@weteka-mongodb-67f532-9fac8609-0c996391.koompi.cloud:27017/?ssl=true&tlsAllowInvalidCertificates=true
```

## Troubleshooting

If you encounter issues:

1. Check the stunnel logs:
   ```
   docker service logs mongodb-stunnel_stunnel
   ```

2. Verify that the certificates exist and are readable:
   ```
   ls -la /certbot/letsencrypt/live/weteka-mongodb-67f532-9fac8609-0c996391.koompi.cloud/
   ```

3. Make sure the MongoDB servers are running and accessible:
   ```
   docker service ls | grep mongodb
   ```

4. Test the connection using the MongoDB shell:
   ```
   mongosh "mongodb://admin:YOUR_PASSWORD@weteka-mongodb-67f532-9fac8609-0c996391.koompi.cloud:27017/?ssl=true&tlsAllowInvalidCertificates=true"
   ```
