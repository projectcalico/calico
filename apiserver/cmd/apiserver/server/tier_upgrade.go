// Copyright (c) 2017-2024 Tigera, Inc. All rights reserved.

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

package server

import (
	"context"
	"fmt"
	"os"
	"strings"

	v1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"

	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/libcalico-go/lib/winutils"
)

const (
	policyNameMigrationNeeded    = "policyNameMigrationNeeded"
	apiServerNamespacePath       = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
	policyNameMigrationConfigMap = "apiserver-policy-name-migration"
)

// migratePolicyNames handles renaming all policies in the cluster to remove the default tier prefix.
// We do this for backwards compatibility with Calico < 3.29, which did not use the default prefix.
// This will ensure that policies created before the default prefix was added will still be manageable by the user of ci tools like ArgoCD
func migratePolicyNames() error {
	k8sconfig, err := winutils.BuildConfigFromFlags("", os.Getenv("KUBECONFIG"))
	if err != nil {
		return fmt.Errorf("failed to build kubernetes client config: %s", err)
	}

	// Get Kubernetes clientset
	k8sClientset, err := kubernetes.NewForConfig(k8sconfig)
	if err != nil {
		return fmt.Errorf("failed to build kubernetes client: %s", err)
	}
	if !updateNeeded(k8sClientset) {
		klog.Infof("Policy name migration is not needed")
		return nil
	}
	klog.Infof("Migrating policy names")
	calicoClient, err := client.NewFromEnv()
	if err != nil {
		return err
	}

	networkPolicies, err := calicoClient.NetworkPolicies().List(context.Background(), options.ListOptions{})
	if err != nil {
		return err
	}
	for _, policy := range networkPolicies.Items {
		policy.Name = removeDefaultTierPrefix(policy.Name)
		_, err = calicoClient.NetworkPolicies().Update(context.Background(), &policy, options.SetOptions{})
		if err != nil {
			return err
		}
	}

	globalNetworkPolicies, err := calicoClient.GlobalNetworkPolicies().List(context.Background(), options.ListOptions{})
	if err != nil {
		return err
	}
	for _, policy := range globalNetworkPolicies.Items {
		policy.Name = removeDefaultTierPrefix(policy.Name)
		_, err = calicoClient.GlobalNetworkPolicies().Update(context.Background(), &policy, options.SetOptions{})
		if err != nil {
			return err
		}
	}

	//Update was successful, update the configmap to indicate that migration is complete so we don't run the tier migration again
	err = markMigrationComplete(k8sClientset)
	if err != nil {
		klog.Errorf("Failed to mark migration as successful: %s", err)
	}

	return nil
}

func removeDefaultTierPrefix(name string) string {
	return strings.TrimPrefix(name, "default.")
}

func updateNeeded(k8sClientset *kubernetes.Clientset) bool {
	namespace, err := os.ReadFile(apiServerNamespacePath)
	if err != nil {
		klog.Errorf("Failed to read namespace: %s", err)
	}

	tierMigration, err := k8sClientset.CoreV1().ConfigMaps(string(namespace)).Get(context.Background(), policyNameMigrationConfigMap, metav1.GetOptions{})
	if err != nil {
		if k8serrors.IsNotFound(err) {
			return true
		} else {
			klog.Errorf("Failed to get api-server configmap: %s", err)
			return false
		}
	}

	return tierMigration.Data[policyNameMigrationNeeded] != "false"
}

func markMigrationComplete(k8sClientset *kubernetes.Clientset) error {
	namespace, err := os.ReadFile(apiServerNamespacePath)
	if err != nil {
		klog.Errorf("Failed to read namespace: %s", err)
	}

	tierMigration, err := k8sClientset.CoreV1().ConfigMaps(string(namespace)).Get(context.Background(), policyNameMigrationConfigMap, metav1.GetOptions{})
	if err != nil {
		if k8serrors.IsNotFound(err) {
			configMap := v1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      policyNameMigrationConfigMap,
					Namespace: string(namespace),
				},
				Data: map[string]string{
					policyNameMigrationNeeded: "false",
				},
			}
			_, err = k8sClientset.CoreV1().ConfigMaps(string(namespace)).Create(context.Background(), &configMap, metav1.CreateOptions{})
		}
		return err
	}

	tierMigration.Data[policyNameMigrationNeeded] = "false"
	_, err = k8sClientset.CoreV1().ConfigMaps(string(namespace)).Update(context.Background(), tierMigration, metav1.UpdateOptions{})
	return err
}
