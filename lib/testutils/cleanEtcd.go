// Copyright (c) 2016 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package testutils

import (
	"log"
	"os/exec"
)

// CleanEtcd is a utility function to wipe clean "/calico" recursively from etcd.
func CleanEtcd() {
	err := exec.Command("etcdctl", "rm", "/calico", "--recursive").Run()
	if err != nil {
		log.Println(err)
	}
}

// DumpEtcd prints out a recursive dump of the contents of etcd.
func DumpEtcd() {
	output, err := exec.Command("curl", "http://127.0.0.1:2379/v2/keys?recursive=true").Output()
	if err != nil {
		log.Println(err)
	} else {
		log.Println(string(output))
	}
}
