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
import json
import logging
from pprint import pformat
from unittest import TestCase

import yaml
from deepdiff import DeepDiff

from tests.st.utils.utils import (get_ip, wipe_etcd, calicoctl)

HOST_IPV4 = get_ip()

logging.basicConfig(level=logging.DEBUG, format="%(message)s")
logger = logging.getLogger(__name__)

class TestBase(TestCase):
    """
    Base class for test-wide methods.
    """

    def setUp(self):
        """
        Clean up before every test.
        """
        self.ip = HOST_IPV4

        self.wipe_etcd()

        # Log a newline to ensure that the first log appears on its own line.
        logger.info("")

    def wipe_etcd(self):
        wipe_etcd(self.ip)

    def check_data_in_datastore(self, data_in, resource, yaml_format=True):
        for data in data_in:
            if yaml_format:
                out = calicoctl(
                    "get %s %s --output=yaml" % (resource, data['metadata']['name']))
                output = yaml.safe_load(out)
            else:
                out = calicoctl(
                    "get %s %s --output=json" % (resource, data['metadata']['name']))
                output = json.loads(out)

            # Remove any empty fields from the output.
            output_clean_spec = {k: v for k, v in output[0]['spec'].items() if v}

            # Remove creationTimestamp and resourceVersion from metada as they cannot be asserted.
            del output[0]['metadata']['creationTimestamp']
            del output[0]['metadata']['resourceVersion']
            
            output[0]['spec']=output_clean_spec
            self.assert_same(data, output[0])

    @staticmethod
    def assert_same(thing1, thing2):
        """
        Compares two things.  Debug logs the differences between them before
        asserting that they are the same.
        """
        assert cmp(thing1, thing2) == 0, \
            "Items are not the same.  Difference is:\n %s" % \
            pformat(DeepDiff(thing1, thing2), indent=2)

    @staticmethod
    def writeyaml(filename, data):
        """
        Converts a python dict to yaml and outputs to a file.
        :param filename: filename to write
        :param data: dictionary to write out as yaml
        """
        with open(filename, 'w') as f:
            text = yaml.dump(data, default_flow_style=False)
            logger.debug("Writing %s: \n%s" % (filename, text))
            f.write(text)

    @staticmethod
    def writejson(filename, data):
        """
        Converts a python dict to json and outputs to a file.
        :param filename: filename to write
        :param data: dictionary to write out as json
        """
        with open(filename, 'w') as f:
            text = json.dumps(data,
                              sort_keys=True,
                              indent=2,
                              separators=(',', ': '))
            logger.debug("Writing %s: \n%s" % (filename, text))
            f.write(text)
