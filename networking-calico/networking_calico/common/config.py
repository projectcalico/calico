#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import re

from networking_calico.compat import cfg
from networking_calico import datamodel_v2
from networking_calico import datamodel_v3


SHARED_OPTS = [
    # etcd connection information.
    cfg.StrOpt('etcd_host', default='127.0.0.1',
               help="The hostname or IP of the etcd node/proxy"),
    cfg.IntOpt('etcd_port', default=2379,
               help="The port to use for the etcd node/proxy"),
    cfg.StrOpt('etcd_scheme', default='http',
               help='The protocol scheme to be used for connections to etcd'),
    # etcd TLS-related options.
    cfg.StrOpt('etcd_key_file',
               help="The path to the TLS key file to use with etcd."),
    cfg.StrOpt('etcd_cert_file',
               help="The path to the TLS client certificate file to use with "
                    "etcd."),
    cfg.StrOpt('etcd_ca_cert_file',
               help="The path to the TLS CA certificate file to use with "
                    "etcd."),
    cfg.StrOpt('etcd_username',
               help="User name for accessing an etcd cluster with "
                    "authentication enabled."),
    cfg.StrOpt('etcd_password',
               help="Password for accessing an etcd cluster with "
                    "authentication enabled."),
    # Large etcd subtree snapshot reads can take time, hence the
    # default of 60 seconds here as opposed to something much shorter.
    cfg.IntOpt('etcd_timeout', default=60,
               help="Timeout (in seconds) for etcd requests."),
    cfg.StrOpt('openstack_region',
               help="When in a multi-region OpenStack deployment, a unique "
                    "name for the region that this node (controller or "
                    "compute) belongs to."),
    # Max connection options, in advance of max connection support being added
    # properly to the Neutron API.
    cfg.IntOpt('max_ingress_connections_per_port', default=0,
               help="If non-zero, a maximum number of ingress connections to impose on each port."),
    cfg.IntOpt('max_egress_connections_per_port', default=0,
               help="If non-zero, a maximum number of egress connections to impose on each port."),
]


def register_options(conf, additional_options=None):
    options_to_register = (
        SHARED_OPTS if additional_options is None
        else SHARED_OPTS + additional_options)
    conf.register_opts(options_to_register, 'calico')


_cached_region_string = None
MAX_DNS_LABEL_LEN = 63
MAX_REGION_LEN = MAX_DNS_LABEL_LEN - len(datamodel_v3.REGION_NAMESPACE_PREFIX +
                                         datamodel_v2.REGION_PREFIX)
DNS_LABEL_REGEXP = "^[a-z0-9]([-a-z0-9]*[a-z0-9])?$"


def _validate_region(region):
    assert len(region) <= MAX_REGION_LEN, \
        ("The value of openstack_region must be must be %d chars or fewer" %
         MAX_REGION_LEN)
    assert re.compile(DNS_LABEL_REGEXP).match(region), \
        ("The value of openstack_region must be must be a valid DNS label;"
         " comprising lower case alphanumeric characters or '-',"
         " and starting and ending with an alphanumeric character")


def get_region_string():
    """Return a per-region string for insertion into etcd key paths.

    Some etcd key paths that are only used with OpenStack need to be
    made unique per-region.  Previously these were:

    - /calico/felix/v1/..., for reporting Felix agent and endpoint
      status

    - /calico/openstack/v1/..., for electing a leader among the
      possibly multiple Neutron driver instances within a region

    - /calico/dhcp/v1/..., for passing Neutron subnet information from
      the Neutron driver to the Calico DHCP agent.

    With the introduction of multi-region support, these become:

    - /calico/felix/v2/<region_string>/...

    - /calico/openstack/v2/<region_string>/...

    - /calico/dhcp/v2/<region_string>/...

    where <region_string> is as returned by this function.
    """
    global _cached_region_string
    if _cached_region_string is None:
        # Use [calico] openstack_region if configured.
        if cfg.CONF.calico.openstack_region:
            _validate_region(cfg.CONF.calico.openstack_region)
            _cached_region_string = "%s%s" % (datamodel_v2.REGION_PREFIX,
                                              cfg.CONF.calico.openstack_region)
        else:
            _cached_region_string = datamodel_v2.NO_REGION
    return _cached_region_string


def _reset_globals():
    global _cached_region_string
    _cached_region_string = None
