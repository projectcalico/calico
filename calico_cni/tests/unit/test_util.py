# Copyright 2015 Metaswitch Networks
#
# Licensed under the Apache License, Version 2.0 (the 'License');
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import sys
import json
import unittest
from mock import patch, MagicMock, Mock, call
from nose.tools import assert_equal, assert_true, assert_false, assert_raises

from calico_cni.constants import *
from calico_cni.util import *


class UtilTest(unittest.TestCase):
    """
    Test class for util module. 
    """
    def test_parse_cni_args_mainline(self):
        # Call method.
        cni_args = "ARG1=VAL1;ARG_2=VAL_2;ARG-3=786.3;KEY= VAL;string=This is a string" 
        parsed = parse_cni_args(cni_args)

        # Assert correctly parsed.
        assert_equal(parsed["ARG1"], "VAL1")
        assert_equal(parsed["ARG_2"], "VAL_2")
        assert_equal(parsed["ARG-3"], "786.3")
        assert_equal(parsed["KEY"], "VAL")
        assert_equal(parsed["string"], "This is a string")

    def test_parse_cni_args_invalid(self):
        # Missing equals sign.
        parsed = parse_cni_args("INVALID:ARG")
        assert_equal(parsed, {})

        # Invalid characters.
        parsed = parse_cni_args("ARG1=ARG2:#1=#2;WHAT=")
        assert_equal(parsed, {})

    def test_parse_cni_args_empty(self):
        # Empty string.
        parsed = parse_cni_args("")
        assert_equal(parsed, {})

        # Empty string with a single space.
        parsed = parse_cni_args(" ")
        assert_equal(parsed, {})
