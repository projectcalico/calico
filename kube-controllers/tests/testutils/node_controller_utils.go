// Copyright (c) 2017-2020 Tigera, Inc. All rights reserved.
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
	"context"
	"fmt"
	"os"
	"reflect"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/fv/containers"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

func RunNodeController(datastoreType apiconfig.DatastoreType, etcdIP, kconfigfile string, autoHepEnabled bool) *containers.Container {
	// Default to all controllers.
	ctrls := "workloadendpoint,namespace,policy,node,serviceaccount"

	autoHep := "disabled"
	if autoHepEnabled {
		autoHep = "enabled"
	}

	return containers.Run("calico-kube-controllers",
		containers.RunOpts{AutoRemove: true},
		"--privileged",
		"-e", fmt.Sprintf("ETCD_ENDPOINTS=http://%s:2379", etcdIP),
		"-e", fmt.Sprintf("DATASTORE_TYPE=%s", datastoreType),
		"-e", fmt.Sprintf("ENABLED_CONTROLLERS=%s", ctrls),
		"-e", fmt.Sprintf("AUTO_HOST_ENDPOINTS=%s", autoHep),
		"-e", "SYNC_NODE_LABELS=true",
		"-e", "LOG_LEVEL=debug",
		"-e", fmt.Sprintf("KUBECONFIG=%s", kconfigfile),
		"-e", "RECONCILER_PERIOD=10s",
		"-v", fmt.Sprintf("%s:%s", kconfigfile, kconfigfile),
		os.Getenv("CONTAINER_NAME"))
}

func RunKubeControllerWithEnv(datastoreType apiconfig.DatastoreType, etcdIP, kconfigfile string, env map[string]string) *containers.Container {
	args := []string{
		"--privileged",
	}

	for k, v := range env {
		args = append(args, "-e", k+"="+v)
	}

	args = append(args,
		"-e", fmt.Sprintf("ETCD_ENDPOINTS=http://%s:2379", etcdIP),
		"-e", fmt.Sprintf("DATASTORE_TYPE=%s", datastoreType),
		"-e", fmt.Sprintf("KUBECONFIG=%s", kconfigfile),
		"-v", fmt.Sprintf("%s:%s", kconfigfile, kconfigfile),
		os.Getenv("CONTAINER_NAME"))

	return containers.Run("calico-kube-controllers",
		containers.RunOpts{AutoRemove: true},
		args...)
}

func ExpectNodeLabels(c client.Interface, labels map[string]string, node string) error {
	cn, err := c.Nodes().Get(context.Background(), node, options.GetOptions{})
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(cn.Labels, labels) {
		s := fmt.Sprintf("Labels do not match.\n\nExpected: %#v\n  Actual: %#v\n", labels, cn.Labels)
		logrus.Warn(s)
		return fmt.Errorf(s)
	}
	return nil
}

func ExpectHostendpoint(c client.Interface, hepName string, expectedLabels map[string]string, expectedIPs, expectedProfiles []string) error {
	hep, err := c.HostEndpoints().Get(context.Background(), hepName, options.GetOptions{})
	if err != nil {
		return err
	}

	if hep.Spec.InterfaceName != "*" {
		return fmt.Errorf("expected all-interfaces hostendpoint. Expected: %q, Actual: %q", "*", hep.Spec.InterfaceName)
	}
	if len(hep.Spec.Ports) > 0 {
		return fmt.Errorf("expected ports to be empty. Actual: %q", hep.Spec.Ports)
	}

	if !reflect.DeepEqual(hep.Labels, expectedLabels) {
		s := fmt.Sprintf("labels do not match.\n\nExpected: %#v\n  Actual: %#v\n", expectedLabels, hep.Labels)
		logrus.Warn(s)
		return fmt.Errorf(s)
	}

	if !reflect.DeepEqual(hep.Spec.ExpectedIPs, expectedIPs) {
		s := fmt.Sprintf("expectedIPs do not match.\n\nExpected: %#v\n  Actual: %#v\n", expectedIPs, hep.Spec.ExpectedIPs)
		logrus.Warn(s)
		return fmt.Errorf(s)
	}

	if !reflect.DeepEqual(hep.Spec.Profiles, expectedProfiles) {
		s := fmt.Sprintf("profiles do not match.\n\nExpected: %#v\n  Actual: %#v\n", expectedProfiles, hep.Spec.Profiles)
		logrus.Warn(s)
		return fmt.Errorf(s)
	}

	return nil
}

func ExpectHostendpointDeleted(c client.Interface, name string) error {
	hep, err := c.HostEndpoints().Get(context.Background(), name, options.GetOptions{})
	if err != nil {
		// We are done if the hep does not exist.
		if _, ok := err.(errors.ErrorResourceDoesNotExist); ok {
			return nil
		}
		return err
	}
	if hep != nil {
		return fmt.Errorf("hostendpoint %q is still not deleted", name)
	}
	return nil
}
