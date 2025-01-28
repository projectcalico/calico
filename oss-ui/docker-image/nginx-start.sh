#!/bin/sh

# Updates the config options according to environment variables
# received via the configMap.

# Generate per-deployment config, from values in the ConfigMap (which
# have been passed to this script as environment variables).

sed -i 's!/var/run/nginx.pid!/tmp/nginx.pid!g' /etc/nginx/nginx.conf
sed -i '/user  nginx;/d' /etc/nginx/nginx.conf

# Start nginx
exec /usr/sbin/nginx -g "daemon off;"
