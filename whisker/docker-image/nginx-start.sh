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
    "notifications": "${NOTIFICATIONS:-"Enabled"}",
    "calico_cloud_url": "${CALICO_CLOUD_URL:-"https://www.calicocloud.io/api"}"
  }
}
EOF

# Generate per-deployment config, from values in the ConfigMap (which
# have been passed to this script as environment variables).

sed -i 's!/var/run/nginx.pid!/tmp/nginx.pid!g' /etc/nginx/nginx.conf
sed -i '/user  nginx;/d' /etc/nginx/nginx.conf

# Start nginx
case "$1" in
  ""|up)
    exec /usr/sbin/nginx -g "daemon off;"
    ;;
  test)
    exec /usr/sbin/nginx -T 2>&1
    ;;
  *)
    echo "Usage: $0 [up|test]"
    exit 1
    ;;
  esac
