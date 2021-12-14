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

	"github.com/projectcalico/calico/felix/fv/containers"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
)

func RunPolicyController(datastoreType apiconfig.DatastoreType, etcdIP, kconfigfile, ctrls string) *containers.Container {
	if ctrls == "" {
		// Default to all controllers.
		ctrls = "workloadendpoint,namespace,policy,node,serviceaccount"
	}
	return containers.Run("calico-kube-controllers",
		containers.RunOpts{AutoRemove: true},
		"-e", fmt.Sprintf("ETCD_ENDPOINTS=http://%s:2379", etcdIP),
		"-e", fmt.Sprintf("DATASTORE_TYPE=%s", datastoreType),
		"-e", fmt.Sprintf("ENABLED_CONTROLLERS=%s", ctrls),
		"-e", "LOG_LEVEL=debug",
		"-e", fmt.Sprintf("KUBECONFIG=%s", kconfigfile),
		"-e", "RECONCILER_PERIOD=10s",
		"-v", fmt.Sprintf("%s:%s", kconfigfile, kconfigfile),
		os.Getenv("CONTAINER_NAME"))
}
