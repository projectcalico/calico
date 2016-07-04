# -*- coding: utf-8 -*-
# Copyright (c) 2015-2016 Tigera, Inc. All rights reserved.
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
calico.geventutils
~~~~~~~~~~~~~~~~~~

Helper utilities for gevent.
"""
import itertools
import logging

import gevent
import gevent.local

_log = logging.getLogger(__name__)


tid_storage = gevent.local.local()
tid_counter = itertools.count()
# Ought to do itertools.count(start=1), but python 2.6 does not support it.
tid_counter.next()


def greenlet_id():
    """
    Returns an integer greenlet ID.
    itertools.count() is atomic, if the internet is correct.
    http://stackoverflow.com/questions/23547604/python-counter-atomic-increment
    """
    try:
        tid = tid_storage.tid
    except:
        tid = tid_counter.next()
        tid_storage.tid = tid
    return tid


class GreenletFilter(logging.Filter):
    def filter(self, record):
        record.tid = greenlet_id()
        return True
