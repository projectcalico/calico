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
import os
import sys
import docker
import docker.errors

from pycalico.ipam import IPAMClient
from pycalico.datastore import ETCD_AUTHORITY_ENV

from utils import DOCKER_VERSION
from utils import print_paragraph
from utils import validate_hostname_port

# If an ETCD_AUTHORITY is specified in the environment variables, validate
# it.
etcd_authority = os.getenv(ETCD_AUTHORITY_ENV, None)
if etcd_authority and not validate_hostname_port(etcd_authority):
    print_paragraph("Invalid %s. It must take the form <address>:<port>. "
                    "Value provided is '%s'" % (ETCD_AUTHORITY_ENV,
                                                etcd_authority))
    sys.exit(1)

client = IPAMClient()

_base_url=os.getenv("DOCKER_HOST", "unix://var/run/docker.sock")
docker_client = docker.Client(version=DOCKER_VERSION,
                               base_url=_base_url)
