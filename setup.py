#!/usr/bin/env python
# Copyright (c) 2014-2016 Tigera, Inc. All rights reserved.
#
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import inspect
import os
import os.path
import setuptools
import sys

PY26_DEPENDENCIES = ['argparse']

def collect_requirements():
    def filter_requirements(filters, file):
        for reqfilter in filters:
            if reqfilter in file:
                return True

        return False

    reqs = set()

    # This monstrosity is the only way to definitely get the location of
    # setup.py regardless of how you execute it. It's tempting to use __file__
    # but that only works if setup.py is executed directly, otherwise it all
    # goes terribly wrong.
    directory =  os.path.dirname(
        os.path.abspath(inspect.getfile(inspect.currentframe()))
    )

    files = os.listdir(directory)
    unfiltered_reqs = (f for f in files if f.endswith('requirements.txt'))

    # If the environment variable $CALICODEPS is set, only the corresponding
    # dependencies are installed.
    deps = os.environ.get('CALICODEPS')
    if deps:
        filters = map(lambda s: s.lower().strip(), deps.split(','))
        requirements_files = (
            f for f in unfiltered_reqs if filter_requirements(filters, f)
        )
    else:
        requirements_files = unfiltered_reqs

    for reqfile in requirements_files:
        with open(reqfile, 'r') as f:
            for line in f:
                line = line.split('#', 1)[0].strip()
                if line:
                    reqs.add(line)

    # If we're running on Python 2.6, add other necessary dependencies. These
    # are added unconditionally.
    if sys.version_info < (2, 7):
        reqs.add(*PY26_DEPENDENCIES)

    return reqs

setuptools.setup(
    name="calico",
    version="1.4.4.dev1",
    packages=setuptools.find_packages(),
    entry_points={
        'console_scripts': [
            'calico-felix = calico.felix.felix:main',
            'calico-cleanup = calico.felix.cleanup:main',
        ],
        'calico.felix.iptables_generator': [
            'default = '
            'calico.felix.plugins.fiptgenerator:FelixIptablesGenerator',
        ],
    },
    scripts=['utils/calico-diags'],
    install_requires=collect_requirements()
)
