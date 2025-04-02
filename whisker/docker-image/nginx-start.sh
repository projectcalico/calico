#!/bin/sh

# Updates the config options according to environment variables
# received via the configMap.
mkdir -p /etc/config
cat > /etc/config/config.json <<EOF
{
  "config": {
    "cluster_id": "${CLUSTER_ID}",
    "cluster_type": "${CLUSTER_TYPE}",
    "calico_version": "${CALICO_VERSION}",
    "notifications": "${NOTIFICATIONS:-"Enabled"}"
  }
}
EOF

# Generate per-deployment config, from values in the ConfigMap (which
# have been passed to this script as environment variables).

sed -i 's!/var/run/nginx.pid!/tmp/nginx.pid!g' /etc/nginx/nginx.conf
sed -i '/user  nginx;/d' /etc/nginx/nginx.conf

# Start nginx
exec /usr/sbin/nginx -g "daemon off;"
