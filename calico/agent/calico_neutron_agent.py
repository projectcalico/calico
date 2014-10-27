#!/usr/bin/env python
# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2014 Metaswitch Networks.
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
#
#
# Performs per host Calico configuration for Neutron.
# Based on the structure of the Linux Bridge agent in the
# Linux Bridge ML2 Plugin.
# @author: Metaswitch Networks

import sys
import time
import uuid

import eventlet
from oslo.config import cfg

from neutron.agent.common import config as common_config
from neutron.agent.linux import external_process
from neutron.common import config as logging_config
from neutron.openstack.common import log as logging

LOG = logging.getLogger(__name__)

OPTS = [
    cfg.IntOpt('metadata_port',
               default=9697,
               help=_("TCP Port used by Neutron metadata namespace proxy.")),
    cfg.BoolOpt('enable_metadata_proxy', default=True,
                help=_("Allow running metadata proxy.")),
    cfg.StrOpt('metadata_proxy_socket',
               default='$state_path/metadata_proxy',
               help=_('Location of Metadata Proxy UNIX domain '
                      'socket')),
    ]

AGENT_OPTS = [
    cfg.IntOpt('polling_interval', default=2,
               help=_("The number of seconds the agent will wait between "
                      "polling for local device changes.")),
    ]


class CalicoMetadataProxy(object):

    def __init__(self, root_helper):
        LOG.debug('CalicoMetadataProxy::__init__')
        self.root_helper = root_helper
        self.proxy_uuid = None
        if cfg.CONF.enable_metadata_proxy:
            self.enable_metadata_proxy()

    def enable_metadata_proxy(self):
        LOG.debug('CalicoMetadataProxy::enable_metadata_proxy')
        self.proxy_uuid = uuid.uuid4().hex
        self._launch_metadata_proxy()

    def _launch_metadata_proxy(self):
        LOG.debug('CalicoMetadataProxy::_launch_metadata_proxy')
        def callback(pid_file):
            proxy_socket = cfg.CONF.metadata_proxy_socket
            proxy_cmd = ['neutron-ns-metadata-proxy',
                         '--pid_file=%s' % pid_file,
                         '--metadata_proxy_socket=%s' % proxy_socket,
                         '--flat=%s' % self.proxy_uuid,
                         '--state_path=%s' % cfg.CONF.state_path,
                         '--metadata_port=%s' % cfg.CONF.metadata_port]
            proxy_cmd.extend(common_config.get_log_args(
                cfg.CONF,
                'neutron-ns-metadata-proxy-%s.log' % self.proxy_uuid))
            return proxy_cmd

        pm = external_process.ProcessManager(
            cfg.CONF,
            self.proxy_uuid,
            self.root_helper,
            namespace=None)
        pm.enable(callback)


def main():
    eventlet.monkey_patch()
    cfg.CONF.register_opts(OPTS)
    cfg.CONF.register_opts(AGENT_OPTS, "AGENT")
    cfg.CONF(project='neutron')

    common_config.register_agent_state_opts_helper(cfg.CONF)
    common_config.register_root_helper(cfg.CONF)
    logging_config.setup_logging(cfg.CONF)

    # Create a CalicoMetadataProxy.
    metadata_proxy = CalicoMetadataProxy(cfg.CONF.AGENT.root_helper)

    # Now just sleep.
    LOG.info(_("Agent initialized successfully, now running... "))
    while True:
        time.sleep(cfg.CONF.AGENT.polling_interval)

    sys.exit(0)


if __name__ == "__main__":
    main()
