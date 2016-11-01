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
felix.test.stub_etcd
~~~~~~~~~~~~

Stub version of the etcd interface.
"""
import logging

# Logger
log = logging.getLogger(__name__)

class EtcdException(Exception):
    pass

class EtcdKeyNotFound(Exception):
    pass

#*****************************************************************************#
#* The next few methods are not exposed to production code, but are called   *#
#* by test code.                                                             *#
#*****************************************************************************#
class Client(object):
    def __init__(self, host="127.0.0.1", port=4001):
        self.host = host
        self.port = port

    def read(self, path, recursive=False):
        pass

    def watch(self, path, recursive=False):
        pass

class EtcdResult(object):
    def __init__(self, key, value):
        self.key = key
        self.value = value
