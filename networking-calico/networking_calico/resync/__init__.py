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
"""On-demand resync of Neutron data into etcd.

This package is the single, shared implementation of the
Neutron-DB-to-etcd reconciliation that used to be driven from a periodic
thread inside the ML2 mechanism driver.  It is callable in two ways:

  * In-process from the driver, at start-of-day, to seed (or repair)
    etcd state when neutron-server starts.

  * Out-of-process from the ``calico-resync`` CLI, so an operator can
    repair etcd state at any time without restarting neutron-server.

Both paths share the same ``run_resync`` entry point so that scope
expansion, syncer construction and result reporting are identical.
"""

from networking_calico.resync.runner import ResyncResult, run_resync
from networking_calico.resync.scope import Scope

__all__ = ["ResyncResult", "Scope", "run_resync"]
