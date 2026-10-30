// Copyright (c) 2022-2024 Tigera, Inc. All rights reserved.

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

package convert

import "fmt"

// ErrIncompatibleCluster indicates that a config option was detected in the existing install
// which Operator does not support.
type ErrIncompatibleCluster struct {
	// err describes the error
	err string
	// fix explains what the user can do, if anything, to continue the migration.
	fix string
	// component identifies which component caused the problem.
	component string
}

func (e ErrIncompatibleCluster) Error() string {
	if e.fix != "" {
		return fmt.Sprintf("%s. To fix it, %s on %s", e.err, e.fix, e.component)
	}
	return fmt.Sprintf("%s on %s", e.err, e.component)
}

const (
	ComponentCalicoNode      = "daemonset/calico-node"
	ComponentKubeControllers = "deployment/calico-kube-controllers"
	ComponentTypha           = "deployment/calico-typha"
	ComponentCNIConfig       = "cni-config"
	ComponentIPPools         = "ippools"
)

func ErrMissingHostPathVolume(component, volume, hostPath string) ErrIncompatibleCluster {
	return ErrIncompatibleCluster{
		err:       fmt.Sprintf("did not detect expected '%s' volume with hostPath '%s'", volume, hostPath),
		component: component,
		fix:       fmt.Sprintf("add the expected volume to %s", component),
	}
}

func ErrIncompatibleAnnotation(annotations map[string]string, component string) error {
	return ErrIncompatibleCluster{
		err:       fmt.Sprintf("unexpected annotation '%v'", annotations),
		component: component,
		fix:       "remove the annotation from the component",
	}
}
