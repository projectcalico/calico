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
calico.monotonic
~~~~~~~~~~~~~~~~

Monotonic clock functions.

monotonic_time() should be used for timing and calculating timer pops
in preference to time.time() which can be non-monotonic or jump
wildly, especially in a VM.
"""
import logging

_log = logging.getLogger(__name__)

__all__ = ["monotonic_time"]

import ctypes
import os

# see <linux/time.h>
CLOCK_PROCESS_CPUTIME_ID = 2
CLOCK_MONOTONIC_RAW = 4


class Timespec(ctypes.Structure):
    _fields_ = [
        ('tv_sec', ctypes.c_long),
        ('tv_nsec', ctypes.c_long)
    ]


librt = ctypes.CDLL('librt.so.1', use_errno=True)
clock_gettime = librt.clock_gettime
clock_gettime.argtypes = [ctypes.c_int, ctypes.POINTER(Timespec)]


def monotonic_time():
    """
    :returns: a time in seconds from an unspecified epoch (which may vary
        between processes).  Guaranteed to be monotonic within the life of
        a process.
    """
    t = Timespec()
    if clock_gettime(CLOCK_MONOTONIC_RAW, ctypes.pointer(t)) != 0:
        errno_ = ctypes.get_errno()
        raise OSError(errno_, os.strerror(errno_))
    return t.tv_sec + t.tv_nsec * 1e-9


def cpu_time():
    """
    :returns: CPU time in seconds
    """
    t = Timespec()
    if clock_gettime(CLOCK_PROCESS_CPUTIME_ID, ctypes.pointer(t)) != 0:
        errno_ = ctypes.get_errno()
        raise OSError(errno_, os.strerror(errno_))
    return t.tv_sec + t.tv_nsec * 1e-9
