#!/bin/bash

set -x
set -e
date
pwd
git status

./build_node.sh
pushd ./build_calicoctl
./create_binary.sh
popd

# Run the FVs
sudo ./tests/fv/arg_parsing.sh
sudo ./tests/fv/mainline.sh
sudo ./tests/fv/add_container.sh
sudo ./tests/fv/unix_socket.sh
sudo ./tests/fv/add_ip.sh

echo "All tests have passed."
