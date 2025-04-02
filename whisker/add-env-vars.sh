#!/bin/sh

mkdir -p dist/public && cat > dist/public/config.json <<EOF
{
  "config": {
    "cluster_id": "${CLUSTER_ID}",
    "cluster_type": "${CLUSTER_TYPE}",
    "calico_version": "${CALICO_VERSION}",
    "notifications": "${NOTIFICATIONS:-"Enabled"}"
  }
}
EOF