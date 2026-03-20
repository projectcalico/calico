# -*- coding: utf-8 -*-
# Copyright (c) 2018 Tigera, Inc. All rights reserved.
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

from neutron.db import models_v2
from neutron.db.models.l3 import FloatingIP
from neutron.db.qos import models as qos_models

from neutron_lib import exceptions as n_exc

from oslo_config import cfg

from oslo_log import log

from networking_calico import datamodel_v3
from networking_calico import etcdv3
from networking_calico.common import config as calico_config
from networking_calico.plugins.ml2.drivers.calico.policy import SG_LABEL_PREFIX
from networking_calico.plugins.ml2.drivers.calico.policy import SG_NAME_LABEL_PREFIX
from networking_calico.plugins.ml2.drivers.calico.policy import SG_NAME_MAX_LENGTH
from networking_calico.plugins.ml2.drivers.calico.syncer import ResourceGone
from networking_calico.plugins.ml2.drivers.calico.syncer import ResourceSyncer


LOG = log.getLogger(__name__)


# A lightweight class to hold all of the additional information that we gather
# when translating from a Neutron port to a Calico WorkloadEndpoint.
class PortExtra(object):
    def __init__(self):
        self.fixed_ips = None
        self.floating_ips = None
        self.interface_name = None
        self.network_name = None
        self.project_data = None
        self.qos = None
        self.security_groups = None
        self.security_group_names = {}


# The Calico WorkloadEndpoint that represents an OpenStack VM gets a pair of
# labels to indicate the project (aka tenant) that the VM belongs to.  The
# label names are as follows, and the label values are the actual project ID
# and name at the time of VM creation.
#
# (OpenStack allows a project's name to be updated subsequently; if that
# happens, it is unspecified whether or not we reflect that by updating labels
# of existing WorkloadEndpoints.  In practice the project name label will
# probably change when the WorkloadEndpoint is next rewritten for some other
# reason.  Deployments that use these labels are recommended not to change
# project names post-creation.)
PROJECT_ID_LABEL_NAME = "projectcalico.org/openstack-project-id"
PROJECT_NAME_LABEL_NAME = "projectcalico.org/openstack-project-name"
PROJECT_NAME_MAX_LENGTH = datamodel_v3.SANITIZE_LABEL_MAX_LENGTH
PROJECT_PARENT_ID_LABEL_NAME = "projectcalico.org/openstack-project-parent-id"
NETWORK_NAME_LABEL_NAME = "projectcalico.org/openstack-network-name"
NETWORK_NAME_MAX_LENGTH = datamodel_v3.SANITIZE_LABEL_MAX_LENGTH

# Note: Calico requires a label value to be an empty string, or to consist of
# alphanumeric characters, '-', '_' or '.', starting and ending with an
# alphanumeric character.  If a project name does not already meet that, we
# substitute problem characters so that it does.


class WorkloadEndpointSyncer(ResourceSyncer):

    def __init__(self, db, txn_from_context, policy_syncer, keystone_client):
        super(WorkloadEndpointSyncer, self).__init__(
            db, txn_from_context, "WorkloadEndpoint"
        )
        self.policy_syncer = policy_syncer
        self.keystone = keystone_client
        self.proj_data_cache = {}
        self.region_string = calico_config.get_region_string()
        self.namespace = datamodel_v3.get_namespace(self.region_string)

        # Prime the project data cache now so that we do not pay a fill
        # penalty the first time we need to annotate a port on a cold start.
        self.cache_port_project_data()

    def resync(self, context):
        super(WorkloadEndpointSyncer, self).resync(context)
        self._resync_live_migrations(context)

    def _resync_live_migrations(self, context):
        """Ensure LiveMigration resources and destination WEPs are consistent.

        For each Neutron port with migrating_to set, ensure a destination WEP
        and LiveMigration resource exist.  For each LiveMigration in etcd that
        doesn't correspond to a migrating port, delete it.
        """
        LOG.info("Starting LiveMigration resync")
        namespace = self.namespace

        # Build the set of LiveMigration names that should exist, based on
        # Neutron ports with migrating_to set.
        expected_lm_names = set()
        with self.txn_from_context(context, "resync-live-migrations"):
            for port in self.db.get_ports(context):
                if not _port_is_endpoint_port(port):
                    continue
                dest_host = port.get("binding:profile", {}).get("migrating_to")
                if dest_host is None:
                    continue

                dest_port = port.copy()
                dest_port["binding:host_id"] = dest_host
                dest_wep_name = endpoint_name(dest_port)
                expected_lm_names.add(dest_wep_name)

                # Ensure LiveMigration and destination WEP exist.
                self.write_live_migration(port, dest_port)
                self.write_endpoint(dest_port, context, reread=False)
                LOG.info(
                    "LiveMigration resync: ensured LM and dest WEP for %s",
                    dest_wep_name,
                )

        # Delete orphaned LiveMigration resources.
        for name, _, mod_revision in datamodel_v3.get_all("LiveMigration", namespace):
            if name not in expected_lm_names:
                LOG.warning("LiveMigration resync: deleting orphaned LM %s", name)
                self.delete_live_migration(name, mod_revision=mod_revision)

        LOG.info("LiveMigration resync done")

    def delete_legacy_etcd_data(self):
        if self.namespace != datamodel_v3.NO_REGION_NAMESPACE:
            datamodel_v3.delete_legacy(self.resource_kind, "")

    # The following methods differ from those for other resources because for
    # endpoints we need to read, compare and write labels and annotations as
    # well as spec.

    def get_all_from_etcd(self):
        return datamodel_v3.get_all(
            self.resource_kind, self.namespace, with_labels_and_annotations=True
        )

    def etcd_write_data_matches_existing(self, write_data, existing):
        rspec, rlabels, rannotations = existing
        wspec, wlabels, wannotations = write_data
        return rspec == wspec and rlabels == wlabels and rannotations == wannotations

    def create_in_etcd(self, name, write_data):
        spec, labels, annotations = write_data
        return datamodel_v3.put(
            self.resource_kind,
            self.namespace,
            name,
            spec,
            labels=labels,
            annotations=annotations,
            mod_revision=0,
        )

    def update_in_etcd(self, name, write_data, mod_revision=etcdv3.MUST_UPDATE):
        spec, labels, annotations = write_data
        return datamodel_v3.put(
            self.resource_kind,
            self.namespace,
            name,
            spec,
            labels=labels,
            annotations=annotations,
            mod_revision=mod_revision,
        )

    def delete_from_etcd(self, name, mod_revision):
        return datamodel_v3.delete(
            self.resource_kind, self.namespace, name, mod_revision=mod_revision
        )

    def get_all_from_neutron(self, context):
        # TODO(lukasa): We could reduce the amount of data we load from Neutron
        # here by filtering in the get_ports call.
        return dict(
            (endpoint_name(port), port)
            for port in self.db.get_ports(context)
            if _port_is_endpoint_port(port)
        )

    def neutron_to_etcd_write_data(self, port, context, reread=False):
        if reread:
            try:
                port = self.db.get_port(context, port["id"])
            except n_exc.PortNotFound:
                raise ResourceGone()
        port_extra = self.get_extra_port_information(context, port)
        return (
            endpoint_spec(port, port_extra),
            endpoint_labels(port, self.namespace, port_extra),
            endpoint_annotations(port),
        )

    def write_endpoint(self, port, context, must_update=False, reread=True):
        if reread:
            # Reread the current port. This protects against concurrent writes
            # breaking our state.
            port = self.db.get_port(context, port["id"])

        # Fill out other information we need on the port.
        port_extra = self.get_extra_port_information(context, port)

        # Write the security policies for this port.
        self.policy_syncer.write_sgs_to_etcd(port_extra.security_groups, context)

        # Implementation note: we could arguably avoid holding the transaction
        # for this length and instead release it here, then use atomic CAS. The
        # problem there is that we potentially have to repeatedly respin and
        # regain the transaction. Let's not do that for now, and performance
        # test to see if it's a problem later.
        mod_revision = etcdv3.MUST_UPDATE if must_update else None
        datamodel_v3.put(
            "WorkloadEndpoint",
            self.namespace,
            endpoint_name(port),
            endpoint_spec(port, port_extra),
            labels=endpoint_labels(port, self.namespace, port_extra),
            annotations=endpoint_annotations(port),
            mod_revision=mod_revision,
        )

    def delete_endpoint(self, port):
        return datamodel_v3.delete(
            "WorkloadEndpoint", self.namespace, endpoint_name(port)
        )

    def write_live_migration(self, source_port, dest_port):
        """Write a LiveMigration resource for a migrating port.

        The LiveMigration name is derived from the destination WEP name.
        Returns the UID assigned by etcd (or the existing UID if already
        present).
        """
        namespace = self.namespace
        wep_id_fields = {
            "orchestratorID": "openstack",
            "workloadID": namespace + "/" + source_port["device_id"],
            "endpointID": source_port["id"],
        }
        return datamodel_v3.put(
            "LiveMigration",
            namespace,
            endpoint_name(dest_port),
            {
                "source": {
                    "workloadEndpoint": dict(
                        hostname=source_port["binding:host_id"],
                        **wep_id_fields,
                    ),
                },
                "target": {
                    "workloadEndpoint": dict(
                        hostname=dest_port["binding:host_id"],
                        **wep_id_fields,
                    ),
                },
            },
        )

    def delete_live_migration(self, name, mod_revision=None):
        """Delete a LiveMigration resource by name."""
        return datamodel_v3.delete(
            "LiveMigration", self.namespace, name, mod_revision=mod_revision
        )

    def add_port_interface_name(self, port, port_extra):
        port_extra.interface_name = "tap" + port["id"][:11]

    def get_security_groups_for_port(self, context, port):
        """Checks which security groups apply for a given port.

        Frustratingly, the port dict provided to us when we call get_port may
        actually be out of date, and I don't know why. This change ensures that
        we get the most recent information.
        """
        filters = {"port_id": [port["id"]]}
        bindings = self.db._get_port_security_group_bindings(context, filters=filters)
        return [binding["security_group_id"] for binding in bindings]

    def get_fixed_ips_for_port(self, context, port):
        """Obtains a complete list of fixed IPs for a port.

        Much like with security groups, for some insane reason we're given an
        out of date port dictionary when we call get_port. This forces an
        explicit query of the IPAllocation table to get the right data out of
        Neutron.
        """
        return [
            {"subnet_id": ip["subnet_id"], "ip_address": ip["ip_address"]}
            for ip in context.session.query(models_v2.IPAllocation).filter_by(
                port_id=port["id"]
            )
        ]

    def get_floating_ips_for_port(self, context, port):
        """Obtains a list of floating IPs for a port."""
        return [
            {"int_ip": ip["fixed_ip_address"], "ext_ip": ip["floating_ip_address"]}
            for ip in context.session.query(FloatingIP).filter_by(
                fixed_port_id=port["id"]
            )
        ]

    def get_network_properties_for_port(self, context, port, port_extra):
        network = (
            context.session.query(models_v2.Network)
            .filter_by(id=port["network_id"])
            .first()
        )

        try:
            port_extra.network_name = datamodel_v3.sanitize_label_name_value(
                network["name"],
                NETWORK_NAME_MAX_LENGTH,
            )
        except Exception:
            LOG.warning(f"Failed to find network name for port {port['id']}")

    def get_extra_port_information(self, context, port):
        """get_extra_port_information

        Gets extra information for a port that is needed before sending it to
        etcd.
        """
        LOG.debug("port = %r", port)
        port_extra = PortExtra()
        port_extra.fixed_ips = self.get_fixed_ips_for_port(context, port)
        port_extra.floating_ips = self.get_floating_ips_for_port(context, port)
        port_extra.security_groups = self.get_security_groups_for_port(context, port)
        self.get_network_properties_for_port(context, port, port_extra)

        self.add_port_gateways(context, port_extra)
        self.add_port_interface_name(port, port_extra)
        self.add_port_project_data(port, context, port_extra)
        self.add_port_sg_names(context, port_extra)
        self.add_port_qos(port, context, port_extra)

        return port_extra

    def add_port_gateways(self, context, port_extra):
        """add_port_gateways

        Determine the gateway IP addresses for a given port's IP addresses, and
        adds them to the port dict.

        This method assumes it's being called from within a database
        transaction and does not take out another one.
        """
        for ip in port_extra.fixed_ips:
            subnet = self.db.get_subnet(context, ip["subnet_id"])
            ip["gateway"] = subnet["gateway_ip"]

    def add_port_sg_names(self, context, port_extra):
        """add_port_sg_names

        Determine and store the name of each security group that a port uses.

        This method assumes it's being called from within a database
        transaction and does not take out another one.
        """
        # Oddly, get_security_groups normally tries to create the default SG
        # for the current tenant, and that can hit a
        # NeutronDbObjectDuplicateEntry exception - presumably if there's a
        # race with multiple servers or threads trying to do this at the same
        # time.  Adding "default_sg=True" here suppresses that creation
        # attempt.
        filters = {"id": port_extra.security_groups}
        for sg in self.db.get_security_groups(
            context, filters=filters, default_sg=True
        ):
            sg_name = datamodel_v3.sanitize_label_name_value(
                sg["name"], SG_NAME_MAX_LENGTH
            )
            port_extra.security_group_names[sg["id"]] = sg_name

    def add_port_qos(self, port, context, port_extra):
        """add_port_qos

        Determine and store QoS parameters for a port.

        This method assumes it's being called from within a database
        transaction and does not take out another one.
        """
        qos = {}

        # Minima, maxima and defaults as specified in the WorkloadEndpoint API,
        # and implemented for the Kubernetes case in
        # libcalico-go/lib/backend/k8s/conversion/workload_endpoint_default.go.
        MINMAX_BANDWIDTH = (1000, 10**15)
        MINMAX_BW_BURST = (1000, 34359738360)
        MINMAX_BW_PEAKRATE = (1010, 10**15 + 10**13)
        MINMAX_BW_MINBURST = (1000, 10**8)

        MINMAX_PACKET_RATE = (1, 10**4)
        MINMAX_PR_BURST = (1, 10**4)

        MINMAX_CONNECTIONS = (1, 4294967295)

        def cap(setting, minmax):
            (min, max) = minmax
            if setting < min:
                setting = min
            elif setting > max:
                setting = max
            return setting

        qos_policy_id = port.get("qos_policy_id") or port.get("qos_network_policy_id")
        LOG.debug("QoS Policy ID = %r", qos_policy_id)
        if qos_policy_id:
            rules = context.session.query(qos_models.QosBandwidthLimitRule).filter_by(
                qos_policy_id=qos_policy_id
            )
            for r in rules:
                LOG.debug("BW rule = %r", r)
                direction = r.get("direction", "egress")
                if r["max_kbps"] != 0:
                    qos[direction + "Bandwidth"] = cap(
                        r["max_kbps"] * 1000, MINMAX_BANDWIDTH
                    )
                if r["max_burst_kbps"] != 0:
                    qos[direction + "Peakrate"] = cap(
                        r["max_burst_kbps"] * 1000, MINMAX_BW_PEAKRATE
                    )

            rules = context.session.query(qos_models.QosPacketRateLimitRule).filter_by(
                qos_policy_id=qos_policy_id
            )
            for r in rules:
                LOG.debug("PR rule = %r", r)
                direction = r.get("direction", "egress")
                if r["max_kpps"] != 0:
                    qos[direction + "PacketRate"] = cap(
                        r["max_kpps"] * 1000, MINMAX_PACKET_RATE
                    )

        if cfg.CONF.calico.max_ingress_connections_per_port != 0:
            qos["ingressMaxConnections"] = cap(
                cfg.CONF.calico.max_ingress_connections_per_port, MINMAX_CONNECTIONS
            )
        if cfg.CONF.calico.max_egress_connections_per_port != 0:
            qos["egressMaxConnections"] = cap(
                cfg.CONF.calico.max_egress_connections_per_port, MINMAX_CONNECTIONS
            )

        if "ingressBandwidth" in qos:
            if cfg.CONF.calico.ingress_burst_bits != 0:
                qos["ingressBurst"] = cap(
                    cfg.CONF.calico.ingress_burst_bits, MINMAX_BW_BURST
                )
            else:
                qos["ingressBurst"] = calico_config.DEFAULT_BW_BURST
            if cfg.CONF.calico.ingress_minburst_bytes != 0 and "ingressPeakrate" in qos:
                qos["ingressMinburst"] = cap(
                    cfg.CONF.calico.ingress_minburst_bytes, MINMAX_BW_MINBURST
                )

        if "egressBandwidth" in qos:
            if cfg.CONF.calico.egress_burst_bits != 0:
                qos["egressBurst"] = cap(
                    cfg.CONF.calico.egress_burst_bits, MINMAX_BW_BURST
                )
            else:
                qos["egressBurst"] = calico_config.DEFAULT_BW_BURST
            if cfg.CONF.calico.egress_minburst_bytes != 0 and "egressPeakrate" in qos:
                qos["egressMinburst"] = cap(
                    cfg.CONF.calico.egress_minburst_bytes, MINMAX_BW_MINBURST
                )

        if "ingressPacketRate" in qos:
            if cfg.CONF.calico.ingress_burst_packets != 0:
                qos["ingressPacketBurst"] = cap(
                    cfg.CONF.calico.ingress_burst_packets, MINMAX_PR_BURST
                )
            else:
                qos["ingressPacketBurst"] = calico_config.DEFAULT_PR_BURST

        if "egressPacketRate" in qos:
            if cfg.CONF.calico.egress_burst_packets != 0:
                qos["egressPacketBurst"] = cap(
                    cfg.CONF.calico.egress_burst_packets, MINMAX_PR_BURST
                )
            else:
                qos["egressPacketBurst"] = calico_config.DEFAULT_PR_BURST

        port_extra.qos = qos

    def add_port_project_data(self, port, context, port_extra):
        """add_port_project_data

        Determine the OpenStack project name and parent ID for a given
        port's project/tenant ID, and add it as port_extra.project_data.
        """
        proj_id = port.get("project_id", port.get("tenant_id"))
        if proj_id is None:
            LOG.warning("Port with no project ID: %r", port)
            return

        # If we've already cached the corresponding project data, we're done.
        proj_data = self.proj_data_cache.get(proj_id)
        if proj_data is not None:
            LOG.debug("Project data %r was cached", proj_data)
            port_extra.project_data = proj_data
            return

        # Not cached, so look up the port's project in the Keystone DB.
        self.cache_port_project_data()
        proj_data = self.proj_data_cache.get(proj_id)
        if proj_data is None:
            LOG.warning("Unable to find project data for port: %r", port)
            return

        port_extra.project_data = proj_data

    def cache_port_project_data(self):
        """cache_port_project_data

        Invoked when should populate the project cache for port annotations.
        """
        # Flush the cache if it has reached its maximum allowed size.
        if len(self.proj_data_cache) >= cfg.CONF.calico.project_name_cache_max:
            self.proj_data_cache = {}
        try:
            for proj in self.keystone.projects.list():
                if proj.id not in self.proj_data_cache:
                    LOG.info("Got project name %r from Keystone", proj.name)
                    proj_name = datamodel_v3.sanitize_label_name_value(
                        proj.name, PROJECT_NAME_MAX_LENGTH
                    )
                    self.proj_data_cache[proj.id] = (proj_name, proj.parent_id)
        except Exception:
            # Probably don't have right credentials for that lookup.
            LOG.exception("Failed to query Keystone DB")


def endpoint_name(port):
    def escape_dashes(s):
        return s.replace("-", "--")

    return "%s-openstack-%s-%s" % (
        escape_dashes(port["binding:host_id"]),
        escape_dashes(port["device_id"]),
        escape_dashes(port["id"]),
    )


def endpoint_labels(port, namespace, port_extra):
    labels = {}
    for sg_id in port_extra.security_groups:
        sg_name = port_extra.security_group_names.get(sg_id, "")
        labels[SG_LABEL_PREFIX + sg_id] = sg_name
        if sg_name:
            labels[SG_NAME_LABEL_PREFIX + sg_name] = sg_id
    labels["projectcalico.org/namespace"] = namespace
    labels["projectcalico.org/orchestrator"] = "openstack"

    proj_id = port.get("project_id", port.get("tenant_id"))
    if proj_id is not None:
        labels[PROJECT_ID_LABEL_NAME] = proj_id
    if port_extra.project_data:
        name, parent_id = port_extra.project_data
        labels[PROJECT_NAME_LABEL_NAME] = name
        labels[PROJECT_PARENT_ID_LABEL_NAME] = parent_id

    network_name = port_extra.network_name
    if network_name is not None:
        labels[NETWORK_NAME_LABEL_NAME] = network_name
    return labels


# Represent a Neutron port as a Calico v3 WorkloadEndpoint spec.
def endpoint_spec(port, port_extra):
    """endpoint_spec

    Generate JSON WorkloadEndpointSpec for the given Neutron port.
    """

    # Construct the simpler spec data.
    data = {
        "orchestrator": "openstack",
        "workload": port["device_id"],
        "node": port["binding:host_id"],
        "endpoint": port["id"],
        "interfaceName": port_extra.interface_name,
        "mac": port["mac_address"],
    }

    # Collect IPv4 and IPv6 addresses.  On the way, also set the corresponding
    # gateway fields.  If there is more than one IPv4 or IPv6 gateway, the last
    # one (in port_extra.fixed_ips) wins.
    ip_nets = []
    for ip in port_extra.fixed_ips:
        if ":" in ip["ip_address"]:
            ip_nets.append(ip["ip_address"] + "/128")
            if ip["gateway"] is not None:
                data["ipv6Gateway"] = ip["gateway"]
        else:
            ip_nets.append(ip["ip_address"] + "/32")
            if ip["gateway"] is not None:
                data["ipv4Gateway"] = ip["gateway"]

    # we need to store allowedIPs twice, because
    # dhcp agent creates dhcp record only for fixed IP
    # but felix have to create route for both (fixed and allowed ips)
    allowed_ips = []
    for aap in port.get("allowed_address_pairs", []):
        ip_addr = str(aap["ip_address"])
        if ":" in ip_addr:
            ip_nets.append(ip_addr + "/128")
            allowed_ips.append(ip_addr + "/128")
        else:
            ip_nets.append(ip_addr + "/32")
            allowed_ips.append(ip_addr + "/32")

    data["ipNetworks"] = ip_nets
    data["allowedIps"] = allowed_ips

    ip_nats = []
    for ip in port_extra.floating_ips:
        ip_nats.append(
            {
                "internalIP": ip["int_ip"],
                "externalIP": ip["ext_ip"],
            }
        )
    if ip_nats:
        data["ipNATs"] = ip_nats

    if port_extra.qos:
        data["qosControls"] = port_extra.qos

    # Return that data.
    return data


def endpoint_annotations(port):
    annotations = {datamodel_v3.ANN_KEY_NETWORK_ID: port["network_id"]}

    # If the port has a DNS assignment, represent that as an FQDN annotation.
    dns_assignment = port.get("dns_assignment")
    if dns_assignment:
        # Note: the Neutron server generates a list of assignment entries, one
        # for each fixed IP, but all with the same FQDN, for slightly
        # historical reasons.  We're fine getting the FQDN from the first
        # entry.
        annotations[datamodel_v3.ANN_KEY_FQDN] = dns_assignment[0]["fqdn"]

    return annotations


def _port_is_endpoint_port(port):
    # Return True if port is a VM port.
    if port["device_owner"].startswith("compute:"):
        return True

    # Also return True if port is for a Kuryr container.
    if port["device_owner"].startswith("kuryr:container"):
        return True

    # Otherwise log and return False.
    LOG.debug("Not a VM port: %s" % port)
    return False
