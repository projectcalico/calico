# -*- coding: utf-8 -*-
# Copyright (c) Metaswitch Networks 2015. All rights reserved.
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

"""
felix.felix
~~~~~~~~~~~

The main logic for Felix.
"""

# Monkey-patch before we do anything else...
from gevent import monkey
monkey.patch_all()

import logging
import optparse
import os

import gevent

from calico import common
from calico.felix.fiptables import IptablesUpdater
from calico.felix.dispatch import DispatchChains
from calico.felix.profilerules import RulesManager
from calico.felix.frules import install_global_rules
from calico.felix.splitter import UpdateSplitter
from calico.felix.config import Config
from calico.felix.futils import IPV4, IPV6
from calico.felix.devices import InterfaceWatcher
from calico.felix.endpoint import EndpointManager
from calico.felix.fetcd import EtcdWatcher
from calico.felix.ipsets import IpsetManager

_log = logging.getLogger(__name__)


def _main_greenlet(config):
    """
    The root of our tree of greenlets.  Responsible for restarting
    its children if desired.
    """
    try:
        _log.info("Connecting to etcd to get our configuration.")
        etcd_watcher = EtcdWatcher(config)
        etcd_watcher.start()
        # Ask the EtcdWatcher to fill in the global config object before we
        # proceed.  We don't yet support config updates.
        etcd_watcher.load_config(async=False)

        _log.info("Main greenlet: Configuration loaded, starting remaining "
                  "actors...")
        v4_filter_updater = IptablesUpdater("filter", ip_version=4)
        v4_nat_updater = IptablesUpdater("nat", ip_version=4)
        v4_ipset_mgr = IpsetManager(IPV4)
        v4_rules_manager = RulesManager(4, v4_filter_updater, v4_ipset_mgr)
        v4_dispatch_chains = DispatchChains(config, 4, v4_filter_updater)
        v4_ep_manager = EndpointManager(config,
                                        IPV4,
                                        v4_filter_updater,
                                        v4_dispatch_chains,
                                        v4_rules_manager)

        v6_filter_updater = IptablesUpdater("filter", ip_version=6)
        v6_ipset_mgr = IpsetManager(IPV6)
        v6_rules_manager = RulesManager(6, v6_filter_updater, v6_ipset_mgr)
        v6_dispatch_chains = DispatchChains(config, 6, v6_filter_updater)
        v6_ep_manager = EndpointManager(config,
                                        IPV6,
                                        v6_filter_updater,
                                        v6_dispatch_chains,
                                        v6_rules_manager)

        update_splitter = UpdateSplitter(config,
                                         [v4_ipset_mgr, v6_ipset_mgr],
                                         [v4_rules_manager, v6_rules_manager],
                                         [v4_ep_manager, v6_ep_manager],
                                         [v4_filter_updater, v6_filter_updater])
        iface_watcher = InterfaceWatcher(update_splitter)

        _log.info("Starting actors.")
        update_splitter.start()

        v4_filter_updater.start()
        v4_nat_updater.start()
        v4_ipset_mgr.start()
        v4_rules_manager.start()
        v4_dispatch_chains.start()
        v4_ep_manager.start()

        v6_filter_updater.start()
        v6_ipset_mgr.start()
        v6_rules_manager.start()
        v6_dispatch_chains.start()
        v6_ep_manager.start()

        iface_watcher.start()

        monitored_items = [
            update_splitter.greenlet,

            v4_nat_updater.greenlet,
            v4_filter_updater.greenlet,
            v4_nat_updater.greenlet,
            v4_ipset_mgr.greenlet,
            v4_rules_manager.greenlet,
            v4_dispatch_chains.greenlet,
            v4_ep_manager.greenlet,

            v6_filter_updater.greenlet,
            v6_ipset_mgr.greenlet,
            v6_rules_manager.greenlet,
            v6_dispatch_chains.greenlet,
            v6_ep_manager.greenlet,

            iface_watcher.greenlet,
            etcd_watcher.greenlet
        ]

        # Install the global rules before we start polling for updates.
        _log.info("Installing global rules.")
        install_global_rules(config, v4_filter_updater, v6_filter_updater,
                             v4_nat_updater)

        # Start polling for updates. These kicks make the actors poll
        # indefinitely.
        _log.info("Starting polling for interface and etcd updates.")
        f = iface_watcher.watch_interfaces(async=True)
        monitored_items.append(f)
        f = etcd_watcher.watch_etcd(update_splitter, async=True)
        monitored_items.append(f)

        # Wait for something to fail.
        _log.info("All top-level actors started, waiting on failures...")
        stopped_greenlets_iter = gevent.iwait(monitored_items)

        stopped_greenlet = next(stopped_greenlets_iter)
        try:
            stopped_greenlet.get()
        except Exception:
            _log.exception("Greenlet failed: %s", stopped_greenlet)
            raise
        else:
            _log.error("Greenlet %s unexpectedly returned.", stopped_greenlet)
            raise AssertionError("Greenlet unexpectedly returned")
    except:
        _log.exception("Exception killing main greenlet")
        raise


def main():
    # Initialise the logging with default parameters.
    common.default_logging()

    # Create configuration, reading defaults from file if it exists.
    parser = optparse.OptionParser()
    parser.add_option('-c', '--config-file', dest='config_file',
                      help="configuration file to use",
                      default="/etc/calico/felix.cfg")
    options, args = parser.parse_args()

    try:
        config = Config(options.config_file)
    except Exception:
        # Config loading error, and not just invalid parameters (from optparse)
        # as they generate a SystemExit. Attempt to open a log file, ignoring
        # any errors it gets, before we raise the exception.
        try:
            common.complete_logging("/var/log/calico/felix.log",
                                    logging.DEBUG,
                                    logging.DEBUG,
                                    logging.DEBUG)
        except Exception:
            pass

        # Log the exception with logging in whatever state we managed to get it
        # to, then reraise it, taking Felix down.
        _log.exception("Exception loading configuration")
        raise

    _log.info("Felix initializing")

    try:
        gevent.spawn(_main_greenlet, config).join()  # Should never return
    except Exception:
        # Make absolutely sure that we exit by asking the OS to terminate our
        # process.  We don't want to let a stray background thread keep us
        # alive.
        _log.exception("Felix exiting due to exception")
        os._exit(1)
        raise  # Unreachable but keeps the linter happy about the broad except.
