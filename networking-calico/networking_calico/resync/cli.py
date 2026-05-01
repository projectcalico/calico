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

The CLI is a one-shot wrapper around
:func:`networking_calico.resync.runner.run_resync`.  It does the
minimum required to make the runner usable out-of-process:

1. Register Calico's oslo.config options.
2. Parse ``--config-file`` and friends via ``neutron.common.config``.
3. Initialise the Neutron plugin registry so
   ``directory.get_plugin()`` returns the configured core plugin.
4. Build a :class:`Scope` from the CLI flags.
5. Run the resync and print the JSON result to stdout.

Exit codes
----------
* ``0`` - resync completed and ``ok`` is True.
* ``1`` - resync completed but ``ok`` is False (something raised
  inside ``run_resync``); the JSON ``error`` field describes it.
* ``2`` - argument parsing or setup failed (argparse default).
"""

import argparse
import json
import sys

from neutron import manager
from neutron.common import config as common_config

from oslo_config import cfg

from networking_calico.common import config as calico_config
from networking_calico.resync import runner
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
        "--all",
        action="store_true",
        help=(
            "Resync everything.  Default if no scope flags are given. "
            "Mutually exclusive with the per-resource flags."
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
    return parser


def main(argv=None) -> int:
    """Entry point for the ``calico-resync`` console script."""
    args = _build_parser().parse_args(argv)

    # argparse's action="append" appends to (rather than replaces) the
    # default, so we apply the default explicitly here.
    config_files = args.config_file or ["/etc/neutron/neutron.conf"]

    # Register options before parsing config so cfg.CONF.calico exists.
    calico_config.register_options(cfg.CONF)

    # Parse oslo.config (and configure logging) from --config-file.
    common_config.init(["--config-file=%s" % path for path in config_files])
    common_config.setup_logging()

    # Initialise the Neutron plugin registry so the core plugin is
    # instantiated and discoverable via directory.get_plugin().
    manager.init()

    scope = scope_mod.from_args(
        all_=args.all,
        networks=args.networks,
        subnets=args.subnets,
        ports=args.ports,
        security_groups=args.security_groups,
        include_security_groups_for_ports=args.include_sgs_for_ports,
    )

    result = runner.run_resync(scope)

    json.dump(result.to_dict(), sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")

    return 0 if result.ok else 1


if __name__ == "__main__":
    sys.exit(main())
