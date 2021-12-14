# Copyright (c) 2013 Hewlett-Packard Development Company, L.P.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# THIS FILE IS MANAGED BY THE GLOBAL REQUIREMENTS REPO - DO NOT EDIT
from setuptools import find_packages
from setuptools import setup

setup(
    name='networking-calico',
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'calico-dhcp-agent = networking_calico.agent.dhcp_agent:main',
        ],
        'neutron.ml2.mechanism_drivers': [
            'calico = networking_calico.plugins.ml2.drivers.calico.' +
            'mech_calico:CalicoMechanismDriver',
        ],
        'neutron.core_plugins': [
            'calico = networking_calico.plugins.calico.plugin:CalicoPlugin',
        ],
    },
    version="0.0.0",
)
