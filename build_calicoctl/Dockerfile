# Copyright 2015 Metaswitch Networks
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# This image is based on the "main" calico/node image. It shares many of the
# dependencies which makes it a good base for an image used for building and
# unit testing
FROM ubuntu:14.04

WORKDIR /code/

RUN apt-get update && \
    apt-get install -qy curl python-dev python-pip git libffi-dev libssl-dev

# Make an etcd available as some UTs rely on it.
RUN curl -L  https://www.github.com/coreos/etcd/releases/download/v2.0.10/etcd-v2.0.10-linux-amd64.tar.gz -o /tmp/etcd.tar.gz
RUN tar -zxvf /tmp/etcd.tar.gz -C /tmp --strip-components=1

# Install the python packages needed for running UTs and building calicoctl.
# Git is installed to allow pip installation from a github repo and also so
# that the right branch can be included if uploading coverage.
ADD requirements.txt /code/
RUN pip install -r requirements.txt
RUN pip install git+https://github.com/Metaswitch/python-etcd.git

# Can't run pyinstaller as root so add a user - https://github.com/pyinstaller/pyinstaller/issues/1081
RUN useradd -d /home/user -m -s /bin/bash user
RUN chown -R user:user /code/
USER user
