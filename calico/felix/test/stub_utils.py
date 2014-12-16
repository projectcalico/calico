# -*- coding: utf-8 -*-
# Copyright 2014 Metaswitch Networks
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

from collections import namedtuple
CommandOutput = namedtuple('CommandOutput', ['stdout', 'stderr'])

# Logger
log = logging.getLogger(__name__)

# The current time.
test_time = 0

def set_time(value):
    global test_time
    test_time = value
    log.debug("Time now set to : %d" % test_time)

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

class UnexpectedSystemCall(Exception):
    pass

def call_silent(args):
    """
    This is a stub version of the call_silent function from futils, that always
    returns 0.
    TODO: We should do better here.
    """
    return 0

def check_call(args):
    """
    This is a stub version of the check_calls function from futils, that does
    some minimal version of that function - see the function for arguments.
    TODO: We should do better here.
    """
    if args[0] == "ipset":
        # IP set management
        if args[1] == "list":
            return CommandOutput("", "")
        elif args[1] == "flush":
            return CommandOutput("", "")
        elif args[1] == "create":
            return CommandOutput("", "")
        elif args[1] == "swap":
            return CommandOutput("", "")
    elif args[0] == "ip" and args[1] == "-6":
        # IP route management - IP v6. For now, just return success and no data.
        return CommandOutput("", "")
    elif args[0] == "ip":
        # IP route management - IP v4. For now, just return success and no data.
        return CommandOutput("", "")
    elif args[0] == "arp":
        # arp configuration
        return CommandOutput("", "")
    else:
        raise UnexpectedSystemCall("Unexpected system call : %s" % args)
    
