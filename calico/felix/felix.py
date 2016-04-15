# -*- coding: utf-8 -*-
# Copyright (c) Metaswitch Networks 2015. All rights reserved.
# Copyright (c) 2015 Cisco Systems.  All Rights Reserved.
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

from BaseHTTPServer import HTTPServer
import functools
import logging
import optparse
import os
import signal

import gevent
from prometheus_client import MetricsHandler

from calico import common
from calico.felix import devices
from calico.felix import futils
from calico.felix.fiptables import IptablesUpdater
from calico.felix.dispatch import DispatchChains
from calico.felix.profilerules import RulesManager
from calico.felix.frules import install_global_rules, load_nf_conntrack
from calico.felix.splitter import UpdateSplitter, CleanupManager
from calico.felix.config import Config
from calico.felix.futils import IPV4, IPV6
from calico.felix.devices import InterfaceWatcher
from calico.felix.endpoint import EndpointManager
from calico.felix.ipsets import IpsetManager, IpsetActor, HOSTS_IPSET_V4
from calico.felix.masq import MasqueradeManager
from calico.felix.fipmanager import FloatingIPManager
from calico.felix.fetcd import EtcdAPI

_log = logging.getLogger(__name__)


def _main_greenlet(config):
    """
    The root of our tree of greenlets.  Responsible for restarting
    its children if desired.
    """
    try:
        _log.info("Connecting to etcd to get our configuration.")
        hosts_ipset_v4 = IpsetActor(HOSTS_IPSET_V4)

        etcd_api = EtcdAPI(config, hosts_ipset_v4)
        etcd_api.start()
        # Ask the EtcdAPI to fill in the global config object before we
        # proceed.  We don't yet support config updates.
        config_loaded = etcd_api.load_config(async=False)
        config_loaded.wait()

        # Ensure the Kernel's global options are correctly configured for
        # Calico.
        devices.configure_global_kernel_config()

        _log.info("Main greenlet: Configuration loaded, starting remaining "
                  "actors...")

        monitored_items = []
        if config.PROM_METRICS_ENABLED:
            httpd = HTTPServer(("0.0.0.0", config.PROM_METRICS_PORT),
                               MetricsHandler)
            stats_server = gevent.Greenlet(httpd.serve_forever)
            stats_server.start()
            monitored_items.append(stats_server)

        v4_filter_updater = IptablesUpdater("filter", ip_version=4,
                                            config=config)
        v4_nat_updater = IptablesUpdater("nat", ip_version=4, config=config)
        v4_ipset_mgr = IpsetManager(IPV4, config)
        v4_masq_manager = MasqueradeManager(IPV4, v4_nat_updater)
        v4_rules_manager = RulesManager(config,
                                        4,
                                        v4_filter_updater,
                                        v4_ipset_mgr)
        v4_dispatch_chains = DispatchChains(config, 4, v4_filter_updater)
        v4_fip_manager = FloatingIPManager(config, 4, v4_nat_updater)
        v4_ep_manager = EndpointManager(config,
                                        IPV4,
                                        v4_filter_updater,
                                        v4_dispatch_chains,
                                        v4_rules_manager,
                                        v4_fip_manager,
                                        etcd_api.status_reporter)

        cleanup_updaters = [v4_filter_updater, v4_nat_updater]
        cleanup_ip_mgrs = [v4_ipset_mgr]
        update_splitter_args = [v4_ipset_mgr,
                                v4_rules_manager,
                                v4_ep_manager,
                                v4_masq_manager,
                                v4_nat_updater]

        v6_enabled = os.path.exists("/proc/sys/net/ipv6")
        if v6_enabled:
            v6_raw_updater = IptablesUpdater("raw", ip_version=6, config=config)
            v6_filter_updater = IptablesUpdater("filter", ip_version=6,
                                                config=config)
            v6_nat_updater = IptablesUpdater("nat", ip_version=6, config=config)
            v6_ipset_mgr = IpsetManager(IPV6, config)
            v6_rules_manager = RulesManager(config,
                                            6,
                                            v6_filter_updater,
                                            v6_ipset_mgr)
            v6_dispatch_chains = DispatchChains(config, 6, v6_filter_updater)
            v6_fip_manager = FloatingIPManager(config, 6, v6_nat_updater)
            v6_ep_manager = EndpointManager(config,
                                            IPV6,
                                            v6_filter_updater,
                                            v6_dispatch_chains,
                                            v6_rules_manager,
                                            v6_fip_manager,
                                            etcd_api.status_reporter)
            cleanup_updaters.append(v6_filter_updater)
            cleanup_ip_mgrs.append(v6_ipset_mgr)
            update_splitter_args += [v6_ipset_mgr,
                                     v6_rules_manager,
                                     v6_ep_manager,
                                     v6_raw_updater,
                                     v6_nat_updater]

        cleanup_mgr = CleanupManager(config, cleanup_updaters, cleanup_ip_mgrs)
        update_splitter_args.append(cleanup_mgr)
        update_splitter = UpdateSplitter(update_splitter_args)
        iface_watcher = InterfaceWatcher(update_splitter)

        _log.info("Starting actors.")
        hosts_ipset_v4.start()
        cleanup_mgr.start()

        v4_filter_updater.start()
        v4_nat_updater.start()
        v4_ipset_mgr.start()
        v4_masq_manager.start()
        v4_rules_manager.start()
        v4_dispatch_chains.start()
        v4_ep_manager.start()
        v4_fip_manager.start()

        if v6_enabled:
            v6_raw_updater.start()
            v6_filter_updater.start()
            v6_ipset_mgr.start()
            v6_nat_updater.start()
            v6_rules_manager.start()
            v6_dispatch_chains.start()
            v6_ep_manager.start()
            v6_fip_manager.start()

        iface_watcher.start()

        top_level_actors = [
            hosts_ipset_v4,
            cleanup_mgr,

            v4_filter_updater,
            v4_nat_updater,
            v4_ipset_mgr,
            v4_masq_manager,
            v4_rules_manager,
            v4_dispatch_chains,
            v4_ep_manager,
            v4_fip_manager,

            iface_watcher,
            etcd_api,
        ]

        if v6_enabled:
            top_level_actors += [
                v6_raw_updater,
                v6_filter_updater,
                v6_nat_updater,
                v6_ipset_mgr,
                v6_rules_manager,
                v6_dispatch_chains,
                v6_ep_manager,
                v6_fip_manager,
            ]

        monitored_items += [actor.greenlet for actor in top_level_actors]

        # Try to ensure that the nf_conntrack_netlink kernel module is present.
        # This works around an issue[1] where the first call to the "conntrack"
        # command fails while waiting for the module to load.
        # [1] https://github.com/projectcalico/calico/issues/986
        load_nf_conntrack()

        # Install the global rules before we start polling for updates.
        _log.info("Installing global rules.")
        install_global_rules(config, v4_filter_updater, v4_nat_updater,
                             ip_version=4)
        if v6_enabled:
            install_global_rules(config, v6_filter_updater, v6_nat_updater,
                                 ip_version=6, raw_updater=v6_raw_updater)

        # Start polling for updates. These kicks make the actors poll
        # indefinitely.
        _log.info("Starting polling for interface and etcd updates.")
        f = iface_watcher.watch_interfaces(async=True)
        monitored_items.append(f)
        etcd_api.start_watch(update_splitter, async=True)

        # Register a SIG_USR handler to trigger a diags dump.
        def dump_top_level_actors(log):
            for a in top_level_actors:
                # The output will include queue length and the like.
                log.info("%s", a)
        futils.register_diags("Top-level actors", dump_top_level_actors)
        futils.register_process_statistics()
        try:
            gevent.signal(signal.SIGUSR1, functools.partial(futils.dump_diags))
        except AttributeError:
            # It doesn't matter too much if we fail to do this.
            _log.warning("Unable to install diag dump handler")
            pass

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
    common.default_logging(gevent_in_use=True)

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
                                    logging.DEBUG,
                                    gevent_in_use=True)
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
