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

FROM ubuntu:14.04

WORKDIR /code/

RUN apt-get update && \
    apt-get install -qy curl python-dev python-pip git libffi-dev libssl-dev

# Install the python packages needed for running UTs and building calico_mesos.
# Git is installed to allow pip installation from a github repo and also so
# that the right branch can be included if uploading coverage.
ADD requirements.txt /code/
RUN pip install -r requirements.txt

# Can't run pyinstaller as root so add a user - https://github.com/pyinstaller/pyinstaller/issues/1081
RUN useradd -d /home/user -m -s /bin/bash user
RUN chown -R user:user /code/
USER user