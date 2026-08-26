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

from oslo_config import cfg

from networking_calico import datamodel_v2
from networking_calico import datamodel_v3


DEFAULT_BW_BURST = 4294967296
DEFAULT_PR_BURST = 5

SHARED_OPTS = [
    # etcd connection information.
    cfg.StrOpt(
        "etcd_host",
        default="127.0.0.1",
        help="The hostname or IP of the etcd node/proxy",
    ),
    cfg.IntOpt(
        "etcd_port", default=2379, help="The port to use for the etcd node/proxy"
    ),
    cfg.StrOpt(
        "etcd_scheme",
        default="http",
        help="The protocol scheme to be used for connections to etcd",
    ),
    # etcd TLS-related options.
    cfg.StrOpt("etcd_key_file", help="The path to the TLS key file to use with etcd."),
    cfg.StrOpt(
        "etcd_cert_file",
        help="The path to the TLS client certificate file to use with etcd.",
    ),
    cfg.StrOpt(
        "etcd_ca_cert_file",
        help="The path to the TLS CA certificate file to use with etcd.",
    ),
    cfg.StrOpt(
        "etcd_username",
        help="User name for accessing an etcd cluster with authentication enabled.",
    ),
    cfg.StrOpt(
        "etcd_password",
        help="Password for accessing an etcd cluster with authentication enabled.",
    ),
    # Large etcd subtree snapshot reads can take time, hence the
    # default of 60 seconds here as opposed to something much shorter.
    cfg.IntOpt(
        "etcd_timeout", default=60, help="Timeout (in seconds) for etcd requests."
    ),
    cfg.StrOpt(
        "openstack_region",
        help=(
            "When in a multi-region OpenStack deployment, a unique "
            "name for the region that this node (controller or "
            "compute) belongs to."
        ),
    ),
    # Options for QoS parameters that are supported on the Calico
    # WorkloadEndpoint resource but not (yet) represented on the Neutron API.
    #
    # The complete mapping between OpenStack-level config/API and the Calico
    # WorkloadEndpoint.QoSControls is as follows.
    #
    #  QoSControls field     | Neutron API field     | Config field
    # -----------------------+-----------------------+----------------------------------
    #  IngressBandwidth      | max_kbps * 1000       |
    #  EgressBandwidth       | max_kbps * 1000       |
    #  IngressBurst          |                       | ingress_burst_bits
    #  EgressBurst           |                       | egress_burst_bits
    #  IngressPeakrate       | max_burst_kbps * 1000 |
    #  EgressPeakrate        | max_burst_kbps * 1000 |
    #  IngressMinburst       |                       | ingress_minburst_bytes
    #  EgressMinburst        |                       | egress_minburst_bytes
    #  IngressPacketRate     | max_kpps * 1000       |
    #  EgressPacketRate      | max_kpps * 1000       |
    #  IngressPacketBurst    |                       | ingress_burst_packets
    #  EgressPacketBurst     |                       | egress_burst_packets
    #   (not implemented)    | max_burst_kpps        |
    #  IngressMaxConnections |                       | max_ingress_connections_per_port
    #  EgressMaxConnections  |                       | max_egress_connections_per_port
    #
    # Note, max_burst_kpps is not currently implemented, because we have not
    # yet found a reasonable way to do that.
    cfg.IntOpt(
        "max_ingress_connections_per_port",
        default=0,
        help=(
            "If non-zero, a maximum number of ingress connections to impose on each"
            " port."
        ),
    ),
    cfg.IntOpt(
        "max_egress_connections_per_port",
        default=0,
        help=(
            "If non-zero, a maximum number of egress connections to impose on each"
            " port."
        ),
    ),
    cfg.IntOpt(
        "ingress_burst_bits",
        default=DEFAULT_BW_BURST,
        help=(
            "If non-zero, configures the maximum allowed burst at peakrate, in the"
            " ingress direction."
        ),
    ),
    cfg.IntOpt(
        "egress_burst_bits",
        default=DEFAULT_BW_BURST,
        help=(
            "If non-zero, configures the maximum allowed burst at peakrate, in the"
            " egress direction."
        ),
    ),
    cfg.IntOpt(
        "ingress_minburst_bytes",
        default=0,
        help=(
            "If non-zero, configures the minimum burst size for peakrate data, in the"
            " ingress direction."
        ),
    ),
    cfg.IntOpt(
        "egress_minburst_bytes",
        default=0,
        help=(
            "If non-zero, configures the minimum burst size for peakrate data, in the"
            " egress direction."
        ),
    ),
    cfg.IntOpt(
        "ingress_burst_packets",
        default=DEFAULT_PR_BURST,
        help=(
            "If non-zero, configures the maximum allowed packet rule burst, in the"
            " ingress direction."
        ),
    ),
    cfg.IntOpt(
        "egress_burst_packets",
        default=DEFAULT_PR_BURST,
        help=(
            "If non-zero, configures the maximum allowed packet rule burst, in the"
            " egress direction."
        ),
    ),
]


def register_options(conf, additional_options=None):
    options_to_register = (
        SHARED_OPTS if additional_options is None else SHARED_OPTS + additional_options
    )
    conf.register_opts(options_to_register, "calico")


def read_deprecated_options(conf, opts, group="calico"):
    """Read the deprecated-for-removal options in OPTS, for the warning side effect.

    oslo.config emits its "deprecated for removal" warning when such an
    option's value is *read*, and only when the operator actually set that
    option in a config file or on the command line.  Parsing alone emits
    nothing, and an option that nobody has set stays silent however often it is
    read.  Arranging that read, at start of day, for every option we have
    marked ``deprecated_for_removal``, is what this function is for.

    Options carrying only a ``deprecated_name`` or ``deprecated_group`` are
    skipped.  Those have a deprecated *name*, rather than being deprecated
    themselves; they are live options that the driver reads in the normal
    course of its work, so oslo.config warns about the old name without our
    help.

    We mark an option deprecated for removal in two rather different
    situations, and the read is worth doing in both:

    - The option still works exactly as it always has, and we intend to remove
      it in some future release.  The driver goes on reading it as part of its
      normal work, so the warning does come out by itself -- but only when the
      reading code path first runs, which may be a long way into the log, or
      not at all if that path is conditional.  Reading here brings the warning
      forward to a predictable place, and makes it unconditional.

    - The option has already been made moot by a change elsewhere, and now
      survives only so that an existing neutron.conf continues to parse.
      Nothing reads it any more, so without this call there is no warning at
      all, and an operator who still sets it gets no signal that it is being
      ignored.  This is the case that prompted the function; ``[calico]
      resync_interval_secs`` in mech_calico.py is a worked example.

    Either way the operator wants to know, and what they are told is defined by
    the option rather than by us: the warning quotes that option's
    ``deprecated_reason``, so that is the place to explain what has changed and
    what, if anything, to do instead.

    The reads below look pointless, and are not: the value is discarded and the
    read performed solely to provoke oslo.config into warning.  Please don't
    tidy them away.

    One consequence to be aware of: under [DEFAULT] fatal_deprecations = true,
    oslo.log turns the warning into a DeprecatedConfig exception rather than a
    log line, so a deployment that sets both that and one of these options will
    now fail to start.  That is the semantics the operator asked for -- they
    are indeed still configuring a deprecated option -- and fatal_deprecations
    defaults to false.
    """
    for opt in opts:
        if opt.deprecated_for_removal:
            conf[group][opt.name]


_cached_region_string = None
MAX_DNS_LABEL_LEN = 63
MAX_REGION_LEN = MAX_DNS_LABEL_LEN - len(
    datamodel_v3.REGION_NAMESPACE_PREFIX + datamodel_v2.REGION_PREFIX
)
DNS_LABEL_REGEXP = "^[a-z0-9]([-a-z0-9]*[a-z0-9])?$"


def _validate_region(region):
    assert len(region) <= MAX_REGION_LEN, (
        "The value of openstack_region must be must be %d chars or fewer"
        % MAX_REGION_LEN
    )
    assert re.compile(DNS_LABEL_REGEXP).match(region), (
        "The value of openstack_region must be must be a valid DNS label;"
        " comprising lower case alphanumeric characters or '-',"
        " and starting and ending with an alphanumeric character"
    )


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
            _cached_region_string = "%s%s" % (
                datamodel_v2.REGION_PREFIX,
                cfg.CONF.calico.openstack_region,
            )
        else:
            _cached_region_string = datamodel_v2.NO_REGION
    return _cached_region_string


def _reset_globals():
    global _cached_region_string
    _cached_region_string = None
