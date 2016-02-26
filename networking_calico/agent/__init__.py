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

# Force clobber to happen now so it doesn't happen after this.
import requests   # noqa

import urllib3
import urllib3.exceptions as u3e

# This is what python-etcd actually cares about.
if urllib3.exceptions is not u3e:
    # So just fix it.
    urllib3.exceptions = u3e
