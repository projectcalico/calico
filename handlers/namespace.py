# Copyright (c) 2017 Tigera, Inc. All rights reserved.
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
import simplejson as json
from constants import *
from pycalico.datastore import DatastoreClient
from pycalico.datastore_datatypes import Rules, Rule

_log = logging.getLogger("__main__")
client = DatastoreClient()


def add_update_namespace(namespace):
    """
    Configures a Profile for the given Kubernetes namespace.
    """
    namespace_name = namespace["metadata"]["name"]
    _log.debug("Adding/updating namespace: %s", namespace_name)

    # Determine the profile name to create.
    profile_name = NS_PROFILE_FMT % namespace_name

    # Build the rules to use.
    rules = Rules(inbound_rules=[Rule(action="allow")],
                  outbound_rules=[Rule(action="allow")])

    # Assign labels to the profile.  We modify the keys to use
    # a special prefix to indicate that these labels are inherited
    # from the namespace.
    ns_labels = namespace["metadata"].get("labels", {})
    labels = {NS_LABEL_KEY_FMT % k: v for k, v in ns_labels.iteritems()}
    _log.debug("Generated namespace labels: %s", labels)

    # Create the Calico profile to represent this namespace, or
    # update it if it already exists.
    client.create_profile(profile_name, rules, labels)

    _log.debug("Created/updated profile for namespace %s", namespace_name)


def delete_namespace(namespace):
    """
    Takes a deleted namespace and removes the corresponding
    configuration from the Calico datastore.
    """
    # Delete the Calico policy which represents this namespace.
    namespace_name = namespace["metadata"]["name"]
    profile_name = NS_PROFILE_FMT % namespace_name
    _log.debug("Deleting namespace profile: %s", profile_name)
    try:
        client.remove_profile(profile_name)
    except KeyError:
        _log.info("Unable to find profile for namespace '%s'", namespace_name)
