# Copyright 2015 Metaswitch Networks
#
# Licensed under the Apache License, Version 2.0 (the 'License');
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import re
import socket


# Calico Configuration Constants
ETCD_AUTHORITY_ENV = "ETCD_AUTHORITY"

# System Specific Constants
ORCHESTRATOR_ID = "cni"
HOSTNAME = socket.gethostname()

# Regex to parse CNI_ARGS.
CNI_ARGS_RE = re.compile("([a-zA-Z0-9/\.\-\_ ]+)=([a-zA-Z0-9/\.\-\_ ]+)(?:;|$)")

# Constants for accessing environment variables. The following
# set of variables are required by the CNI spec.
CNI_COMMAND_ENV = "CNI_COMMAND"
CNI_CONTAINERID_ENV = "CNI_CONTAINERID"
CNI_NETNS_ENV = "CNI_NETNS"
CNI_IFNAME_ENV = "CNI_IFNAME"
CNI_ARGS_ENV = "CNI_ARGS"
CNI_PATH_ENV = "CNI_PATH"

# CNI Constants
CNI_CMD_ADD = "ADD"
CNI_CMD_DELETE = "DEL"

# Kubernetes Constants
K8S_POD_NAME = "K8S_POD_NAME"
K8S_POD_NAMESPACE = "K8S_POD_NAMESPACE"
K8S_POD_INFRA_CONTAINER_ID = "K8S_POD_INFRA_CONTAINER_ID"

# Constants for getting Calico configuration from the network
# configuration file.
ETCD_AUTHORITY_KEY = "etcd_authority"
LOG_LEVEL_KEY = "log_level"

# Default ETCD_AUTHORITY.
DEFAULT_ETCD_AUTHORITY="127.0.0.1:2379"

# CNI Error Codes
ERR_CODE_GENERIC = 100
ERR_CODE_UNHANDLED = 101
ERR_CODE_FAILED_ASSIGNMENT = 102
ERR_CODE_INVALID_ARGUMENT = 103
ERR_CODE_ETCD_UNAVAILABLE = 104

# Logging Configuration
LOG_DIR = "/var/log/calico/cni"
LOG_FORMAT = '%(asctime)s %(process)d [%(identity)s] %(levelname)s %(message)s'

