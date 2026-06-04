# -*- coding: utf-8 -*-
# Copyright (c) 2026 Tigera, Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.  See the License for the specific language governing
# permissions and limitations under the License.

"""Entry point for the ``calico-resync`` CLI.

The CLI is a one-shot wrapper around :meth:`networking_calico.resync.scope.Scope.run`.
It does the minimum required to make the resync usable out-of-process:

1. Register Calico's oslo.config options.
2. Parse ``--config-file`` and friends via ``neutron.common.config``.
3. Initialise the Neutron plugin registry so ``directory.get_plugin()`` returns the
   configured core plugin.
4. Build a :class:`Scope` from the CLI flags.
5. Run the resync and write the JSON result to stdout (or to the file given by
   ``--output``, which is preferable for tooling that doesn't want to compete with
   oslo.log noise on stdout).

Exit codes
----------
* ``0`` - resync completed and ``ok`` is True.
* ``1`` - resync completed but ``ok`` is False (something raised inside ``Scope.run``);
          the JSON ``error`` field describes it.
* ``2`` - argument parsing or setup failed (argparse default).
"""

import argparse
import json
import sys

from keystoneauth1 import loading as ksa_loading

from neutron import manager
from neutron.common import config as common_config
from neutron_lib.plugins import directory as plugin_dir

from oslo_config import cfg

from networking_calico.common import config as calico_config
from networking_calico.plugins.ml2.drivers.calico import mech_calico
from networking_calico.resync import scope as scope_mod


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="calico-resync",
        description=(
            "Reconcile all or a subset of the Neutron data "
            "model into etcd.  Reads the same neutron.conf as "
            "neutron-server."
        ),
    )
    parser.add_argument(
        "--config-file",
        action="append",
        default=None,
        metavar="PATH",
        help=(
            "oslo.config file to read (repeat for layered config).  "
            "Defaults to /etc/neutron/neutron.conf."
        ),
    )
    parser.add_argument(
        "--network",
        action="append",
        default=[],
        dest="networks",
        metavar="ID",
        help="Resync this network (also resyncs its subnets and ports).",
    )
    parser.add_argument(
        "--subnet",
        action="append",
        default=[],
        dest="subnets",
        metavar="ID",
        help="Resync this subnet (also resyncs ports on it).",
    )
    parser.add_argument(
        "--port",
        action="append",
        default=[],
        dest="ports",
        metavar="ID",
        help="Resync this port.",
    )
    parser.add_argument(
        "--security-group",
        action="append",
        default=[],
        dest="security_groups",
        metavar="ID",
        help="Resync this security group's NetworkPolicy.",
    )
    parser.add_argument(
        "--include-sgs-for-ports",
        action="store_true",
        help=(
            "When resyncing ports, also resync the security groups "
            "they belong to.  Off by default because the port -> SG "
            "binding is via labels, so port-only resync is usually "
            "sufficient."
        ),
    )
    parser.add_argument(
        "-o",
        "--output",
        default=None,
        metavar="PATH",
        help=(
            "Write the JSON ResyncResult to PATH instead of stdout.  "
            "Useful for tooling — depending on the layered config, "
            "oslo.log may emit log lines to stdout, making the result "
            "harder to parse cleanly."
        ),
    )
    return parser


def main(argv=None) -> int:
    """Entry point for the ``calico-resync`` console script."""
    args = _build_parser().parse_args(argv)

    # argparse's action="append" appends to (rather than replaces) the default, so we
    # apply the default explicitly here.
    config_files = args.config_file or ["/etc/neutron/neutron.conf"]

    # Register options before parsing config so cfg.CONF.calico exists.
    calico_config.register_options(cfg.CONF)

    # Register Neutron's core options (base_mac, etc) before init() — it validates
    # cfg.CONF.base_mac immediately but does NOT register the core opts itself.  In
    # neutron-server this happens earlier in startup; as a standalone CLI we have to do
    # it ourselves.
    common_config.register_common_config_options()

    # Register the [keystone_authtoken] options that make_keystone_client reads
    # (username, password, auth_url, etc).  In neutron-server these are registered as a
    # side-effect of keystonemiddleware loading the auth plugin on the first request;
    # the CLI has no such trigger so we force-register them here.  We register the
    # v3password plugin's options because make_keystone_client is hardcoded to build a
    # v3.Password client — any deployment that calico-resync supports is therefore using
    # v3password fields in [keystone_authtoken], whether or not auth_type is set
    # explicitly.
    ksa_loading.register_auth_conf_options(cfg.CONF, "keystone_authtoken")
    ksa_loading.register_session_conf_options(cfg.CONF, "keystone_authtoken")
    v3password_loader = ksa_loading.get_plugin_loader("password")
    cfg.CONF.register_opts(
        ksa_loading.get_auth_plugin_conf_options(v3password_loader),
        group="keystone_authtoken",
    )

    # Parse oslo.config (and configure logging) from --config-file.  To route logs
    # anywhere other than wherever neutron.conf would naturally send them (typically
    # stderr/journald, which mixes badly with the JSON result on stdout), layer in an
    # additional --config-file with [DEFAULT] log_file = ... and use_stderr = False, the
    # same way neutron-dhcp-agent reads neutron.conf + dhcp_agent.ini.
    common_config.init(["--config-file=%s" % path for path in config_files])
    common_config.setup_logging()

    # Fail fast on an unsupported MySQL driver, before doing any real work --
    # this is the same check the mech driver does in initialize(), reading
    # [database] connection from oslo.config.
    mech_calico._check_mysql_driver()

    # Initialise the Neutron plugin registry so the core plugin is instantiated and
    # discoverable via directory.get_plugin().
    manager.init()

    result = scope_mod.Scope(
        plugin_dir.get_plugin(),
        networks=args.networks,
        subnets=args.subnets,
        ports=args.ports,
        security_groups=args.security_groups,
        include_security_groups_for_ports=args.include_sgs_for_ports,
    ).run()

    if args.output:
        with open(args.output, "w") as f:
            json.dump(result.to_dict(), f, indent=2, sort_keys=True)
            f.write("\n")
    else:
        json.dump(result.to_dict(), sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")

    return 0 if result.ok else 1


if __name__ == "__main__":
    sys.exit(main())
