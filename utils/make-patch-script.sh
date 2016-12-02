#!/bin/bash

set -e

url=$1
echo "URL: $url"
sha_sum=$(cd bin; sha256sum calico-felix)

echo
echo "Run the following script on the target server to patch the"
echo "/opt/calico-felix/calico-felix binary:"
echo
echo "curl -o calico-felix $url &&"
echo "    if echo '$sha_sum' | sha256sum --status --check; then \\"
echo "      sudo stop calico-felix || sudo systemctl stop calico-felix; "
echo "      sudo cp calico-felix /opt/calico-felix/calico-felix && \\"
echo "      sudo chmod +x /opt/calico-felix/calico-felix && \\"
echo "      sudo start calico-felix || sudo systemctl start calico-felix;"
echo "    else"
echo "      echo 'Incorrect hash, file may have been tampered with!'"
echo "    fi"
