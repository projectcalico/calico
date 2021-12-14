# Copyright (c) 2018 Tigera, Inc. All rights reserved.
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

#!/bin/bash

testDir="/tmp/t1"
input='{"kubernetes.io/fsGroup":"0","kubernetes.io/fsType":"","kubernetes.io/pod.name":"udsver-client-3419040874-jzd9n","kubernetes.io/pod.namespace":"default","kubernetes.io/pod.uid":"d113fb2d-bb61-11e7-bea2-080027631ab3","kubernetes.io/pvOrVolumeName":"test-volume","kubernetes.io/readwrite":"rw","kubernetes.io/serviceAccount.name":"default"}'

if [ $# -eq 1 ]; then	
	mkdir -p ${testDir}
	chmod 777 ${testDir}
	$1 mount ${testDir} ${input}
else
	umount ${testDir}
fi
