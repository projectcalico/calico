#!/bin/bash

set -x
set -e
date
pwd
git status

./build_node.sh
./create_binary.sh

# Run the FVs
sudo ./tests/fv/mainline.sh
sudo ./tests/fv/no_powerstrip.sh
sudo ./tests/fv/arg_parsing.sh
sudo ./tests/fv/add_container.sh
sudo ./tests/fv/unix_socket.sh
sudo ./tests/fv/add_ip.sh
sudo ./tests/fv/profile_commands.sh
sudo ./tests/fv/diags.sh

echo "All tests have passed."
