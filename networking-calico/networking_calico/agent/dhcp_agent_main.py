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

"""Production entry-point wrapper for the Calico DHCP agent.

This module exists to keep ``eventlet.monkey_patch()`` out of the
``dhcp_agent`` library module itself.  Calling ``monkey_patch()`` at
module-import time -- the way the DHCP agent used to do it -- patches
``socket`` / ``threading`` / etc. in any Python process that imports
the module, including unit-test processes that just want to construct
``CalicoDhcpAgent`` to assert on its methods.  Under that contamination,
subunit's test runner (which writes binary subunit-protocol messages to
stdout via ``os.fdopen(fileno, 'wb', 0)``) ends up parked in
``epoll_wait()`` on an empty FD set, and the whole test run hangs.

The fix is to do ``monkey_patch()`` here, *before* importing the
``dhcp_agent`` module.  In production, ``setup.py`` registers this
module's ``main`` as the ``calico-dhcp-agent`` console-script entry
point -- so the daemon still runs under a fully monkey-patched
interpreter, just like before.  In unit tests, ``dhcp_agent`` is
imported directly and ``monkey_patch()`` does not run.

Per the eventlet docs the patch must happen as early as possible:
https://eventlet.readthedocs.io/en/latest/patching.html
"""

import eventlet

eventlet.monkey_patch()

from networking_calico.agent.dhcp_agent import main  # noqa: E402

__all__ = ["main"]


if __name__ == "__main__":
    main()
