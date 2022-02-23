// Copyright (c) 2021 Tigera, Inc. All rights reserved.
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
// limitations under the License.package util

package util

import (
	"context"
	"time"

	"k8s.io/klog/v2"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	calicoclient "github.com/projectcalico/api/pkg/client/clientset_generated/clientset/typed/projectcalico/v3"
)

// WaitForGlobalNetworkPoliciesToNotExist waits for the GlobalNetworkPolicy with the given name to no
// longer exist.
func WaitForGlobalNetworkPoliciesToNotExist(client calicoclient.ProjectcalicoV3Interface, name string) error {
	return wait.PollImmediate(500*time.Millisecond, wait.ForeverTestTimeout,
		func() (bool, error) {
			klog.V(5).Infof("Waiting for broker %v to not exist", name)
			_, err := client.GlobalNetworkPolicies().Get(context.Background(), name, metav1.GetOptions{})
			if nil == err {
				return false, nil
			}

			if errors.IsNotFound(err) {
				return true, nil
			}

			return false, nil
		},
	)
}

// WaitForGlobalNetworkPoliciesToExist waits for the GlobalNetworkPolicy with the given name
// to exist.
func WaitForGlobalNetworkPoliciesToExist(client calicoclient.ProjectcalicoV3Interface, name string) error {
	return wait.PollImmediate(500*time.Millisecond, wait.ForeverTestTimeout,
		func() (bool, error) {
			klog.V(5).Infof("Waiting for serviceClass %v to exist", name)
			_, err := client.GlobalNetworkPolicies().Get(context.Background(), name, metav1.GetOptions{})
			if nil == err {
				return true, nil
			}

			return false, nil
		},
	)
}
