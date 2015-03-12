# -*- coding: utf-8 -*-
#
# Copyright (c) 2015 Metaswitch Networks
# All Rights Reserved.
#
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

# Etcd-based transport for the Calico/OpenStack Plugin.

# Standard Python library imports.
import etcd
import eventlet
import json
import re
import time

# Calico imports.
from calico.openstack.transport import CalicoTransport

LOG = None


class CalicoTransportEtcd(CalicoTransport):
    """Calico transport implementation based on etcd."""

    OPENSTACK_ENDPOINT_RE = re.compile(
    r'^/calico/host/(?P<hostname>[^/]+)/.*openstack.*/endpoint/(?P<endpoint_id>[^/]+)')

    def __init__(self, driver, logger):
        super(CalicoTransportEtcd, self).__init__(driver)

        # Initialize logger.
        global LOG
        LOG = logger

    def initialize(self):
        # Prepare client for accessing etcd data.
        self.client = etcd.Client()

        # Spawn a green thread for periodically resynchronizing etcd against
        # the OpenStack database.
        eventlet.spawn(self.periodic_resync_thread)

    def periodic_resync_thread(self):
        while True:
            try:
                # Resynchronize endpoint data.
                self.resync_endpoints()

                # Resynchronize security group data.
                self.resync_security_groups()

                # Sleep until time for next resync.
                eventlet.sleep(PERIODIC_RESYNC_INTERVAL_SECS)

            except:
                LOG.exception("Exception in periodic resync thread")

    def resync_endpoints(self):
        # Get all current endpoints from the OpenStack database and key them on
        # endpoint ID.
        ports = {}
        for port in self.driver.get_endpoints():
            ports[port['id']] = port

        # Read all etcd keys under /calico/host.
        r = client.read('/calico/host', recursive=True)
        for child in r.children:
            m = OPENSTACK_ENDPOINT_RE.match(child.key)
            if m:
                # We have a key/value pair for an OpenStack endpoint.  Extract
                # the endpoint ID and hostname from the key, and read the JSON
                # data as a dict.
                endpoint_id = m.group("endpoint_id")
                hostname = m.group("hostname")
                data = json_decoder.decode(child.value)

                if (endpoint_id in ports and
                    hostname == ports[endpoint_id]['binding:host_id'] and
                    data == self.port_etcd_data(ports[endpoint_id])):
                    # OpenStack still has an endpoint that exactly matches this
                    # etcd key/value.  No change is needed to the etcd data,
                    # and we can delete the port from the ports dict so as not
                    # to unnecessarily write out its (unchanged) value again
                    # below.
                    del ports[endpoint_id]
                elif (endpoint_id not in ports or
                      hostname != ports[endpoint_id]['binding:host_id']):
                    # OpenStack no longer has an endpoint with the ID in the
                    # etcd key; or it does, but the endpoint has migrated to a
                    # different host than the one in the etcd key.  In both
                    # cases the etcd key is no longer valid and should be
                    # deleted.  In the migration case, data will be written
                    # below to an etcd key that incorporates the new hostname.
                    client.delete(child.key)

        # Now write etcd data for any endpoints remaining in the ports dict;
        # these are new endpoints - i.e. never previously represented in etcd
        # data - or endpoints that have migrated or whose data has changed.
        for port in ports.values:
            client.write(self.port_etcd_key(port), self.port_etcd_data(port))

    def port_etcd_key(self, port):
        return "/calico/host/%s/workload/openstack/endpoint/%s" % (
            port['binding:host_id'],
            port['id']
        )

    def port_etcd_data(self, port):
        # Construct the simpler port data.
        data = {'state': 'active' if port['admin_state_up'] else 'inactive',
                'name': port['interface_name'],
                'mac': port['mac_address'],
                'profile_id': self.port_profile_id(port)}

        # Collect IPv6 and IPv6 addresses.  On the way, also set the
        # corresponding gateway fields.  If there is more than one IPv4 or IPv6
        # gateway, the last one (in port['fixed_ips']) wins.
        ipv4_nets = []
        ipv6_nets = []
        for ip in port['fixed_ips']:
            if ':' in ip['ip_address']:
                ipv6_nets.append(ip['ip_address'] + '/128')
                if ip['gateway'] is not None:
                    data['ipv6_gateway'] = ip['gateway']
            else:
                ipv4_nets.append(ip['ip_address'] + '/32')
                if ip['gateway'] is not None:
                    data['ipv4_gateway'] = ip['gateway']
        data['ipv4_nets'] = ipv4_nets
        data['ipv6_nets'] = ipv6_nets

        # Return that data.
        return data

    def port_profile_id(self, port):
        return '_'.join(port['security_groups'])

    def resync_security_groups(self):

    def endpoint_created(self, port):
        pass

    def endpoint_updated(self, port):
        pass

    def endpoint_deleted(self, port):
        pass

    def security_group_updated(self, sg):
        pass
