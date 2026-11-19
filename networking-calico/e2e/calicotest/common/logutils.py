# Copyright (c) 2018-2025 Tigera, Inc. All rights reserved.
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

from calicotest.common import datamodel_v3

_log = logging.getLogger(__name__)


LOG_LEVEL_KEY = "logSeverityFile"


def get_felix_log_level():
    log_level = None
    felix_config = datamodel_v3.get("FelixConfiguration", "default")
    if LOG_LEVEL_KEY in felix_config:
        log_level = felix_config[LOG_LEVEL_KEY]

    if log_level:
        _log.info("Found a value in LogSeverityFile: %s", log_level)
    else:
        _log.info("LogSeverityFile key not found in etcd")

    return log_level


def set_felix_log_level(log_level):
    felix_config = datamodel_v3.get("FelixConfiguration", "default")
    if log_level is not None:
        felix_config[LOG_LEVEL_KEY] = log_level
    elif LOG_LEVEL_KEY in felix_config:
        del felix_config[LOG_LEVEL_KEY]
    datamodel_v3.put("FelixConfiguration", "default", felix_config)
