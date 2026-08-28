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

import (
	"context"
	"fmt"

	"github.com/tigera/operator/pkg/controller/migration/cni"

	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type components struct {
	node            CheckedDaemonSet
	kubeControllers *appsv1.Deployment
	typha           *appsv1.Deployment

	// client is used to resolve spec fields that reference other data sources
	client client.Client

	cni cni.NetworkComponents
}

// getComponents loads the main calico components into structs for later parsing.
func getComponents(ctx context.Context, client client.Client) (*components, error) {
	var ds = appsv1.DaemonSet{}

	// verify canal isn't present, or block
	if err := client.Get(ctx, types.NamespacedName{
		Name:      "canal-node",
		Namespace: metav1.NamespaceSystem,
	}, &ds); err == nil {
		return nil, fmt.Errorf("detected existing canal installation")
	} else if !errors.IsNotFound(err) {
		return nil, fmt.Errorf("failed to check for existing canal installation: %v", err)
	}

	if err := client.Get(ctx, types.NamespacedName{
		Name:      "calico-node",
		Namespace: metav1.NamespaceSystem,
	}, &ds); err != nil {
		if errors.IsNotFound(err) {
			return nil, nil
		}
	}

	var kc = new(appsv1.Deployment)
	if err := client.Get(ctx, types.NamespacedName{
		Name:      "calico-kube-controllers",
		Namespace: metav1.NamespaceSystem,
	}, kc); err != nil {
		if !errors.IsNotFound(err) {
			return nil, fmt.Errorf("failed to get kube-controllers deployment: %v", err)
		}
		log.Info("did not detect kube-controllers")
		kc = nil
	}

	var t = new(appsv1.Deployment)
	if err := client.Get(ctx, types.NamespacedName{
		Name:      "calico-typha",
		Namespace: metav1.NamespaceSystem,
	}, t); err != nil {
		if !errors.IsNotFound(err) {
			return nil, fmt.Errorf("failed to get typha deployment: %v", err)
		}
		// typha is optional, so just log.
		log.Info("did not detect typha")
		t = nil
	}

	comps := &components{
		client: client,
		node: CheckedDaemonSet{
			ds,
			map[string]checkedFields{},
		},
		kubeControllers: kc,
		typha:           t,
	}

	// do some upfront processing of CNI by loading it into comps
	var err error
	comps.cni, err = loadCNI(comps)

	return comps, err
}

// loadCNI pulls the CNI network config from it's env var source within components
// and then returns the parsed data.
func loadCNI(comps *components) (nc cni.NetworkComponents, err error) {
	// do some upfront processing of CNI by loading it into comps
	c := getContainer(comps.node.Spec.Template.Spec, containerInstallCNI)
	if c == nil {
		log.V(5).Info("no install-cni container found on calico-node")
		return
	}

	cniConfig, err := comps.node.getEnv(ctx, comps.client, containerInstallCNI, "CNI_NETWORK_CONFIG")
	if err != nil {
		return nc, err
	}
	if cniConfig != nil {
		log.V(5).Info("no env var CNI_NETWORK_CONFIG found on calico-node")
		nc, err = cni.Parse(*cniConfig)
	}

	return nc, err
}
