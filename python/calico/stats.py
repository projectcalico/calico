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
calico.stats
~~~~~~~~~~~~

Stats collection functions.
"""

import logging
import re

from prometheus_client import Gauge, Summary

from calico.monotonic import monotonic_time

_log = logging.getLogger(__name__)


def sanitize_name(name):
    return re.sub(r'[^a-zA-Z0-9]', '_', name)


_gauge_cache = {}


class RateStat(object):
    """
    Records instances of an event and calculates the rate.
    """
    def __init__(self, name):
        self.name = name
        self.start_time = None
        self.count = None
        gauge_name = "felix_" + sanitize_name(name) + "_rate"
        if gauge_name not in _gauge_cache:
            _gauge_cache[gauge_name] = Gauge(gauge_name, "Rate of %s" % name)
        self.gauge = _gauge_cache[gauge_name]
        self.reset()
        self.gauge.set_function(lambda: self.rate)

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


_summary_cache = {}


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
        summary_name = "felix_" + sanitize_name(name)
        if summary_name not in _summary_cache:
            summary = Summary(summary_name, "%s in %s" % (name, unit))
            _summary_cache[summary_name] = summary
        self.summary = _summary_cache[summary_name]
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
        self.summary.observe(value)

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
