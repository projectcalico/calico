# Copyright 2015-2016 Metaswitch Networks
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

# Workaround for https://github.com/kennethreitz/requests/issues/2870

# Some distributions 'unvendor' requests' bundled version of urllib3, leaving a
# stub in requests.packages which monkey-patches requests.packages.urllib3
# with the system-wide version.  Due to a bug in the implementation, this
# causes sys["urllib3"].exceptions to point to
# sys["requests.packages.urllib3.exceptions"] instead of
# sys["urllib3.exceptions"].  In turn, this causes python-etcd to fail to catch
# certain exceptions.
#
# Here we correct that bug.

import sys

# Import all the relevant packages so that any clobbering happens now.
import requests                 # noqa
import urllib3                  # noqa
import urllib3.exceptions       # noqa

# Check for clobbering using sys.modules[] because it's definitive.  This
# condition checks whether python-etcd has the same version of the exceptions
# classes that urllib3 will use.
#
# More specifically, when urllib3 raises an exception, the relevant code is:
#
#   from .exceptions import (
#       ProtocolError, DecodeError, ReadTimeoutError, ResponseNotChunked
#   )
#
#   [...]
#
#                   raise ReadTimeoutError(self._pool, None, 'Read timed out.')
#
# That means that ReadTimeoutError comes from the 'urllib3.exceptions' module.
#
# Whereas when python-etcd tries to catch and handle that exception, the
# relevant code is:
#
#   import urllib3
#
#   [...]
#
#                           isinstance(e,
#                                      urllib3.exceptions.ReadTimeoutError)):
#
# This means that the exception it is checking for is the
# 'exceptions.ReadTimeoutError' attribute of the 'urllib3' module.
#
# Normally the latter should be the same as the 'ReadTimeoutError' attribute of
# the 'urllib3.exceptions' module, and hence match the exception that urllib3
# raises.  But the monkey-patching performed by distributions' modification of
# the requests code can mess that up.
#
# So, here we check for that mistake, and correct it.  Note that that equally
# means that we are breaking requests somehow - but that doesn't matter because
# the Calico DHCP agent doesn't actually execute any requests code.  (To be
# clear: the Calico DHCP agent imports a slew of Neutron utility modules, which
# in turn import other Neutron and Oslo and even Keystone modules, and so on,
# and some of those import requests.  But the Calico DHCP agent actually
# executes only a small subset of all that code.)

if sys.modules["urllib3"].exceptions is not sys.modules["urllib3.exceptions"]:
    # So just fix it.
    sys.modules["urllib3"].exceptions = sys.modules["urllib3.exceptions"]
