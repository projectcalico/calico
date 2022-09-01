// Copyright (c) 2019 Tigera, Inc. All rights reserved.

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

package utils

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
)

var calicoctl = "/go/src/github.com/projectcalico/calico/calicoctl/bin/calicoctl-linux-amd64"
var version_helper = "/go/src/github.com/projectcalico/calico/calicoctl/tests/fv/helper/bin/calico_version_helper"

func getEnv(kdd bool) []string {
	env := []string{"ETCD_ENDPOINTS=http://127.0.0.1:2379"}

	if kdd {
		val, ok := os.LookupEnv("KUBECONFIG")
		if ok {
			env = []string{"KUBECONFIG=" + val, "DATASTORE_TYPE=kubernetes"}
		} else {
			env = []string{"K8S_API_ENDPOINT=https://localhost:6443", "DATASTORE_TYPE=kubernetes"}
		}
	}
	env = append(env, "K8S_INSECURE_SKIP_TLS_VERIFY=true")

	return env
}

func Calicoctl(kdd bool, args ...string) string {
	out, err := CalicoctlMayFail(kdd, args...)
	Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Failed to run calicoctl (kdd:%v) %v", kdd, args))
	return out
}

func CalicoctlMayFail(kdd bool, args ...string) (string, error) {
	cmd := exec.Command(calicoctl, args...)
	cmd.Env = getEnv(kdd)
	out, err := cmd.CombinedOutput()

	log.Infof("Run: calicoctl %v", strings.Join(args, " "))
	log.Infof("Output:\n%v", string(out))
	log.Infof("Error: %v", err)

	return string(out), err
}

func SetCalicoVersion(kdd bool, args ...string) (string, error) {
	// Set CalicoVersion in ClusterInformation
	helperCmd := exec.Command(version_helper, args...)
	helperCmd.Env = getEnv(kdd)
	helperOut, helperErr := helperCmd.CombinedOutput()

	log.Infof("Run: %s %s", version_helper, strings.Join(args, " "))
	log.Infof("Output:\n%v", string(helperOut))
	log.Infof("Error: %v", helperErr)

	return string(helperOut), helperErr
}
