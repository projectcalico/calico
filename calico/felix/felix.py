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
from calico.felix.devices import InterfaceWatcher
from calico.felix.endpoint import EndpointManager
from calico.felix.fetcd import EtcdWatcher
from calico.felix.ipsets import IpsetManager
from gevent import monkey
monkey.patch_all()

import os

import logging
import gevent

from calico import common
from calico.felix.fiptables import (IptablesUpdater, DispatchChains)
from calico.felix.profilerules import RulesManager
from calico.felix.frules import install_global_rules
from calico.felix.splitter import UpdateSplitter
from calico.felix.config import Config
from calico.felix.futils import IPV4, IPV6

_log = logging.getLogger(__name__)


def _main_greenlet(config):
    """
    The root of our tree of greenlets.  Responsible for restarting
    its children if desired.
    """
    try:
        _log.info("Creating actors.")
        v4_updater = IptablesUpdater(ip_version=4)
        v4_ipset_mgr = IpsetManager(IPV4)
        v4_rules_manager = RulesManager(4, v4_updater, v4_ipset_mgr)
        v4_dispatch_chains = DispatchChains(config, 4, v4_updater)
        v4_ep_manager = EndpointManager(config,
                                        IPV4,
                                        v4_updater,
                                        v4_dispatch_chains,
                                        v4_rules_manager)

        v6_updater = IptablesUpdater(ip_version=6)
        v6_ipset_mgr = IpsetManager(IPV6)
        v6_rules_manager = RulesManager(6, v6_updater, v6_ipset_mgr)
        v6_dispatch_chains = DispatchChains(config, 6, v6_updater)
        v6_ep_manager = EndpointManager(config,
                                        IPV6,
                                        v6_updater,
                                        v6_dispatch_chains,
                                        v6_rules_manager)

        update_splitter = UpdateSplitter([v4_ipset_mgr, v6_ipset_mgr],
                                         [v4_rules_manager,
                                          v6_rules_manager],
                                         [v4_ep_manager, v6_ep_manager])
        iface_watcher = InterfaceWatcher(update_splitter)
        etcd_watcher = EtcdWatcher(config, update_splitter)

        _log.info("Starting actors.")
        v4_updater.start()
        v4_ipset_mgr.start()
        v4_rules_manager.start()
        v4_dispatch_chains.start()
        v4_ep_manager.start()

        v6_updater.start()
        v6_ipset_mgr.start()
        v6_rules_manager.start()
        v6_dispatch_chains.start()
        v6_ep_manager.start()

        iface_watcher.start()
        etcd_watcher.start()

        greenlets = [
            v4_updater.greenlet,
            v4_ipset_mgr.greenlet,
            v4_rules_manager.greenlet,
            v4_dispatch_chains.greenlet,
            v4_ep_manager.greenlet,

            v6_updater.greenlet,
            v6_ipset_mgr.greenlet,
            v6_rules_manager.greenlet,
            v6_dispatch_chains.greenlet,
            v6_ep_manager.greenlet,

            iface_watcher.greenlet,
            etcd_watcher.greenlet
        ]

        # Block until etcd config is present and tells us to proceed.
        etcd_watcher.load_config_and_wait_for_ready(async=False)

        # Install the global rules before we start polling for updates.
        _log.info("Installing global rules.")
        install_global_rules(config, v4_updater, v6_updater)

        # Start polling for updates. These kicks make the actors poll
        # indefinitely.
        _log.info("Starting polling for interface and etcd updates.")
        iface_watcher.watch_interfaces(async=True)
        etcd_watcher.watch_etcd(async=True)

        # Wait for something to fail.
        stopped_greenlets_iter = gevent.iwait(greenlets)
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


def watchdog():
    while True:
        _log.info("Still alive")
        gevent.sleep(20)


def main():
    try:
        # Initialise the logging with default parameters.
        common.default_logging()

        # Load config
        # FIXME: old felix used argparse but that's not in Python 2.6, so
        # hard-coded path.

        try:
            config = Config("/etc/calico/felix.cfg")
        except:
            # Attempt to open a log file, ignoring any errors it gets, before
            # we raise the exception.
            try:
                common.complete_logging("/var/log/calico/felix.log",
                                        logging.DEBUG,
                                        logging.DEBUG,
                                        logging.DEBUG)
            except:
                pass

            raise

        _log.info("Felix initializing")
        gevent.spawn(_main_greenlet, config).join()  # Should never return
    except BaseException:
        # Make absolutely sure that we exit by asking the OS to terminate our
        # process.  We don't want to let a stray background thread keep us
        # alive.
        _log.exception("Felix exiting due to exception")
        os._exit(1)
        raise  # Unreachable but keeps the linter happy about the broad except.
