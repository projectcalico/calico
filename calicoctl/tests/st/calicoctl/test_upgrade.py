# Copyright (c) 2015-2017 Tigera, Inc. All rights reserved.
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

import logging
import os
import random

import pytest
import yaml
import json

from tests.st.utils.utils import calicoctl, \
    name, wipe_etcd, get_ip, clean_calico_data
from tests.st.utils.v1_data import data

ETCD_SCHEME = os.environ.get("ETCD_SCHEME", "http")
ETCD_CA = os.environ.get("ETCD_CA_CERT_FILE", "")
ETCD_CERT = os.environ.get("ETCD_CERT_FILE", "")
ETCD_KEY = os.environ.get("ETCD_KEY_FILE", "")
ETCD_HOSTNAME_SSL = "etcd-authority-ssl"

logging.basicConfig(level=logging.DEBUG, format="%(message)s")
logger = logging.getLogger(__name__)

tests = [
    ("bgppeer_long_node_name", False, None),
    ("bgppeer_dotted_asn", False, None),
    ("hep_bad_label", True, "a qualified name must consist of alphanumeric characters"),
    ("hep_tame", False, None),
    ("hep_mixed_ip", False, None),
    ("hep_label_too_long", True, "name part must be no more than 63 characters"),
    ("hep_long_fields", False, None),
    ("hep_name_too_long", True, "name is too long by 11 bytes"),
    ("ippool_mixed", False, None),
    ("ippool_v4_small", False, None),
    ("ippool_v4_large", False, None),
    ("node_long_name", False, None),
    ("node_tame", False, None),
    ("policy_long_name", False, None),
    ("policy_big", False, None),
    ("policy_tame", False, None),
    ("profile_big", False, None),
    ("profile_tame", False, None),
    ("wep_bad_workload_id", True, "field must not begin with a '-'"),
    ("wep_lots_ips", False, None),
    ("wep_similar_name", True, "workload was not added through the Calico CNI plugin and cannot be converted"),
    ("wep_similar_name_2", False, None),
    ("do_not_track", False, None),
    ("prednat_policy", False, None),
    ("profile_long_labels", True, None),
]
random.shuffle(tests)


def _test_converter(testname, fail_expected, error_text=None, format="yaml"):
    """
    Convert a v1 object to v3, then apply the result and read it back.
    """
    # Let's start every test afresh
    wipe_etcd(get_ip())
    testdata = data[testname]

    # Convert data to V3 API using the tool under test
    rc = calicoctl("convert -o %s" % format, data=testdata, format=format)
    if not fail_expected:
        logger.debug("Trying to convert manifest from V1 to V3")
        rc.assert_no_error()
        if format == "yaml":
            parsed_output = yaml.safe_load(rc.output)
        else:
            parsed_output = json.loads(rc.output)
        # Get the converted data and clean it up (remove fields we don't care about)
        converted_data = clean_calico_data(parsed_output)
        original_resource = rc

        # Apply the converted data
        rc = calicoctl("create", data=original_resource.output, format=format)
        logger.debug("Trying to create resource using converted manifest")
        rc.assert_no_error()
        rc = calicoctl("get %s %s -o yaml" % (converted_data['kind'], name(converted_data)))

        # Comparison here needs to be against cleaned versions of data to remove Creation Timestamp
        logger.debug("Comparing 'get'ted output with original converted yaml")
        cleaned_output = yaml.safe_dump(
            clean_calico_data(
                yaml.safe_load(rc.output),
                extra_keys_to_remove=['projectcalico.org/orchestrator']
            )
        )
        original_resource.assert_data(cleaned_output, format=format)
    else:
        rc.assert_error(error_text)


def test_converter_yaml(subtests):
    """
    Convert a v1 object to v3, then apply the result and read it back.
    """
    for testname, fail_expected, error_text in tests:
        with subtests.test(testname=testname, fail_expected=fail_expected, error_text=error_text):
            _test_converter(testname, fail_expected, error_text=error_text, format="yaml")


def test_converter_json(subtests):
    """
    Convert a v1 object to v3, then apply the result and read it back.
    """
    for testname, fail_expected, error_text in tests:
        with subtests.test(testname=testname, fail_expected=fail_expected, error_text=error_text):
            _test_converter(testname, fail_expected, error_text=error_text, format="json")
