# -*- coding: utf-8 -*-
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
"""
calico.etcddriver.protocol
~~~~~~~~~~~~~~~~~~~~~~~~~~

Protocol constants for Felix <-> Driver protocol.
"""

MSG_KEY_TYPE = "type"

# Init message Felix -> Driver.
MSG_TYPE_INIT = "init"
MSG_KEY_ETCD_URL = "etcd_url"
MSG_KEY_HOSTNAME = "hostname"

# Config loaded message Driver -> Felix.
MSG_TYPE_CONFIG_LOADED = "config_loaded"
MSG_KEY_GLOBAL_CONFIG = "global"
MSG_KEY_HOST_CONFIG = "host"

# Config message Felix -> Driver.
MSG_TYPE_CONFIG = "conf"
MSG_KEY_LOG_FILE = "log_file"
MSG_KEY_SEV_FILE = "sev_file"
MSG_KEY_SEV_SCREEN = "sev_screen"
MSG_KEY_SEV_SYSLOG = "sev_syslog"

# Status message Driver -> Felix.
MSG_TYPE_STATUS = "stat"
MSG_KEY_STATUS = "status"
STATUS_WAIT_FOR_READY = "wait-for-ready"
STATUS_RESYNC = "resync"
STATUS_IN_SYNC = "in-sync"

# Update message Driver -> Felix.
MSG_TYPE_UPDATE = "u"
MSG_KEY_KEY = "k"
MSG_KEY_VALUE = "v"
