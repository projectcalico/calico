# Copyright (c) 2015-2016 Tigera, Inc. All rights reserved.
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

try:
    from neutron_lib import constants
    from neutron_lib import exceptions as n_exc
except ImportError:
    from neutron.common import constants
    from neutron.common import exceptions as n_exc

try:
    from oslo_log import log
except ImportError:  # Icehouse, Juno
    from neutron.openstack.common import log

try:
    from oslo_config import cfg
except ImportError:
    # Icehouse, Juno
    from oslo.config import cfg

try:
    from oslo_db import exception as db_exc
except ImportError:
    try:
        # Juno
        from oslo.db import exception as db_exc
    except ImportError:
        # Icehouse
        from neutron.openstack.common.db import exception as db_exc

try:
    from oslo_concurrency import lockutils
except ImportError:
    # Icehouse, Juno
    from neutron.openstack.common import lockutils

try:
    from neutron_lib.constants import DHCPV6_STATEFUL
except ImportError:
    # Mitaka and earlier
    from neutron.common.constants import DHCPV6_STATEFUL

try:
    # Introduced during Ocata development cycle.
    from neutron_lib.plugins import directory as plugin_dir
except ImportError:
    # Pre-Ocata.
    from neutron.manager import NeutronManager as plugin_dir

try:
    # Present here since January 2016 (commit c8be1a1be91).
    from neutron_lib.constants import IP_PROTOCOL_MAP
except ImportError:
    # We probably don't need to support IP protocol names for older
    # OpenStack versions.  But if such a need arises, we can add code
    # here to get IP_PROTOCOL_MAP in the appropriate way from those
    # old versions.
    IP_PROTOCOL_MAP = {}
