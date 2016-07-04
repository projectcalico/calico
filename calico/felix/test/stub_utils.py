# -*- coding: utf-8 -*-
# Copyright (c) 2014-2016 Tigera, Inc. All rights reserved.
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
felix.test.stub_utils
~~~~~~~~~~~~

Test utilities.
"""
import logging
import random

# Logger
log = logging.getLogger(__name__)

# The current time.
test_time = 0

def set_time(value):
    global test_time
    test_time = value
    log.debug("Time now set to : %d", test_time)

def get_time():
    return test_time

def get_mac():
    """
    Gets a random mac address.
    """
    mac = ("%02x:%02x:%02x:%02x:%02x:%02x" %
                    (random.randint(0x00, 0xff),
                     random.randint(0x00, 0xff),
                     random.randint(0x00, 0xff),
                     random.randint(0x00, 0xff),
                     random.randint(0x00, 0xff),
                     random.randint(0x00, 0xff)))
    return mac

# Exception raised when tests reach the end.
class TestOverException(Exception):
    pass
