#!/bin/bash

set -x
set -e
date
pwd
git status

docker run --privileged -v `pwd`:/code --name host1 -tid jpetazzo/dind

docker exec -ti host1 bash -c \
 'docker -d & \
 cd /code && \
 ./build_node.sh && \
 ./create_binary.sh'
# docker run --privileged -v `pwd`:/code --name host2 -tid jpetazzo/dind bash -c \
#  'docker -d -D && \
#  cd /code && \
#  ./build_node.sh && \
#  ./create_binary.sh'
# docker run --privileged -v `pwd`:/code --name host3 -tid jpetazzo/dind bash -c \
#  'docker -d -D && \
#  cd /code && \
#  ./build_node.sh && \
#  ./create_binary.sh'

# Run the FVs
docker exec -ti host1 bash -c 'cd /code && sudo ./tests/fv/mainline.sh'
docker exec -ti host1 bash -c 'cd /code && sudo ./tests/fv/add_container.sh'
docker exec -ti host1 bash -c 'cd /code && sudo ./tests/fv/add_ip.sh'
docker exec -ti host1 bash -c 'cd /code && sudo ./tests/fv/arg_parsing.sh'
docker exec -ti host1 bash -c 'cd /code && sudo ./tests/fv/profile_commands.sh'
docker exec -ti host1 bash -c 'cd /code && sudo ./tests/fv/no_powerstrip.sh'
docker exec -ti host1 bash -c 'cd /code && sudo ./tests/fv/diags.sh'

echo "All tests have passed."
