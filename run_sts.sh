#!/bin/bash
# Ensure the host image is up to date
./build_host.sh

# Create the calicoctl binary here so it will be in the volume mounted on the hosts.
./create_binary.sh
nosetests calico_containers/tests/st --nocapture
