# -*- coding: utf-8 -*-
# Copyright (c) 2016 Tigera, Inc. All rights reserved.
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
calico.pyilauncher
~~~~~~~~~~~~~~~~~~

Main script used as the entry-point to the pyinstaller executable.
"""

import sys

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "driver":
        sys.argv[1:] = sys.argv[2:]
        from calico.etcddriver.__main__ import main
    elif len(sys.argv) > 1 and sys.argv[1] == "cleanup":
        sys.argv[1:] = sys.argv[2:]
        from calico.felix.cleanup import main
    else:
        from calico.felix.felix import main
    main()
