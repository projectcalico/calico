// Copyright (c) 2017 Tigera, Inc. All rights reserved.
//
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

// The utils in this file are specific to the policy controller,
// and are not expected to be shared across projects.

package testutils

import (
	"fmt"
	"os"

	"github.com/projectcalico/felix/fv/containers"
)

func RunPolicyController(etcdIP, kconfigfile string) *containers.Container {
	return containers.Run("calico-policy-controller",
		containers.RunOpts{AutoRemove: true},
		"--privileged",
		"-e", fmt.Sprintf("ETCD_ENDPOINTS=http://%s:2379", etcdIP),
		"-e", "ENABLED_CONTROLLERS=workloadendpoint,namespace,policy,node,serviceaccount",
		"-e", "LOG_LEVEL=debug",
		"-e", fmt.Sprintf("KUBECONFIG=%s", kconfigfile),
		"-e", "RECONCILER_PERIOD=10s",
		"-v", fmt.Sprintf("%s:%s", kconfigfile, kconfigfile),
		fmt.Sprintf("%s", os.Getenv("CONTAINER_NAME")))
}
