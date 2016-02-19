# -*- coding: utf-8 -*-
# Copyright 2015 Metaswitch Networks
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
calico.stats
~~~~~~~~~~~~

Stats collection functions.
"""

import logging

from calico.monotonic import monotonic_time

_log = logging.getLogger(__name__)


class RateStat(object):
    """
    Records instances of an event and calculates the rate.
    """
    def __init__(self, name):
        self.name = name
        self.start_time = None
        self.count = None
        self.reset()

    def reset(self):
        self.start_time = monotonic_time()
        self.count = 0

    def store_occurence(self):
        self.count += 1

    @property
    def time_since_start(self):
        now = monotonic_time()
        time_since_start = now - self.start_time
        return time_since_start

    @property
    def rate(self):
        time_since_start = self.time_since_start
        return self.count / time_since_start if time_since_start > 0 else 0.0

    def __str__(self):
        return "%s: %s in %.1fs (%.3f/s)" % (self.name, self.count,
                                             self.time_since_start, self.rate)


class AggregateStat(RateStat):
    """
    Records a sequence of numeric stats and calculates aggregate stats.
    """
    def __init__(self, name, unit):
        super(AggregateStat, self).__init__(name)
        self.unit = unit
        self.max = None
        self.min = None
        self.sum = None
        self.reset()

    def reset(self):
        super(AggregateStat, self).reset()
        self.max = None
        self.min = None
        self.sum = 0.0

    def store_reading(self, value):
        self.store_occurence()
        self.sum += value
        if self.max is None or value > self.max:
            self.max = value
        if self.min is None or value < self.min:
            self.min = value

    @property
    def mean(self):
        return self.sum / self.count if self.count else 0.0

    def __str__(self):
        return (
            super(AggregateStat, self).__str__() +
            (
                " min=%.3f%s mean=%.3f%s max=%.3f%s" % (
                    self.min or 0.0, self.unit,
                    self.mean or 0.0, self.unit,
                    self.max or 0.0, self.unit,
                )
            )
        )

