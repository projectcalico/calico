#!/bin/bash

set -e

url=$1
echo "URL: $url"
sha_sum=$(cd bin; sha256sum calico-felix)

cat <<'EOF'

Run the following script as root on the target server to patch the
Calico Felix installation in /opt/calico-felix:

d=`mktemp -d /opt/calico-felix.XXXXXX`
cd $d
EOF

cat <<EOF
curl -o calico-felix.tgz $url && tar xf calico-felix.tgz && cd calico-felix &&
    if echo '$sha_sum' | sha256sum --status --check; then
      stop calico-felix || systemctl stop calico-felix
      cd /opt
EOF

cat <<'EOF'
      tar xf ${d}/calico-felix.tgz
      rm -rf $d
      start calico-felix || systemctl start calico-felix;
    else
      echo 'Incorrect hash, file may have been tampered with!'
    fi

EOF
