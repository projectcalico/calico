#!/bin/bash

set -x
set -e
date
pwd
git status

nosetests calico_containers/tests/fv

# Run the FVs. Need to run from the /code directory since the tests expect
# to be run from the root of the codebase.
docker exec -t host1 bash -c 'cd /code && sudo ./calico_containers/tests/fv/mainline.sh'
docker exec -t host1 bash -c 'cd /code && sudo ./calico_containers/tests/fv/add_container.sh'
docker exec -t host1 bash -c 'cd /code && sudo ./calico_containers/tests/fv/add_ip.sh'
docker exec -t host1 bash -c 'cd /code && sudo ./calico_containers/tests/fv/arg_parsing.sh'
docker exec -t host1 bash -c 'cd /code && sudo ./calico_containers/tests/fv/profile_commands.sh'
docker exec -t host1 bash -c 'cd /code && sudo ./calico_containers/tests/fv/no_powerstrip.sh'

docker exec -t host1 bash -c 'docker rm -f $(docker ps -qa) ; \
                              docker rmi $(docker images -qa)' || true
docker rm -f host1 || true

echo "All tests have passed."
