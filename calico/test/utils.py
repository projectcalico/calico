# -*- coding: utf-8 -*-
# Copyright (c) 2016 Tigera, Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
calico.test.utils
~~~~~~~~~~~~~~~~~

Test-only utility functions.
"""

import logging

from hypothesis.internal.reflection import proxies
from nose.tools import assert_true

from calico.monotonic import monotonic_time

_log = logging.getLogger(__name__)


def fail_if_time_exceeds(time_limit):
    """
    Decorator that causes a test to fail if it takes too long.  Note:
    this doesn't time out the test; it still runs to completion.

    Uses hypothesis' proxies decorator rather than wraps for
    hypothesis compatibility.

    :param time_limit: Time limit in seconds.
    """
    def decorator(fn):
        @proxies(fn)
        def wrapped(*args, **kwargs):
            start_time = monotonic_time()
            rc = fn(*args, **kwargs)
            end_time = monotonic_time()
            time_taken = end_time - start_time
            assert_true(time_taken < time_limit, "Test took too long")
            return rc
        return wrapped
    return decorator
