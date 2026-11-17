#!/bin/bash

# load-nft-rpms.sh: load-rpms-image.sh for the nftables RPMs image.

exec "$(dirname "$0")/load-rpms-image.sh" nftables "$@"
