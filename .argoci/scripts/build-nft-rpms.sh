#!/bin/bash

# build-nft-rpms.sh: build-rpms-image.sh for the nftables RPMs image.

exec "$(dirname "$0")/build-rpms-image.sh" nftables "$@"
