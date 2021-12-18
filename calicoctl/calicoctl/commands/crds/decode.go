// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.

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

package crds

import (
	v1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"

	"github.com/ghodss/yaml"
)

//go:generate go run ../../../scripts/importcrds.go

func CalicoCRDs() ([]*v1.CustomResourceDefinition, error) {
	var crds []*v1.CustomResourceDefinition

	bgpconfig := v1.CustomResourceDefinition{}
	err := yaml.Unmarshal([]byte(bgpconfigurations), &bgpconfig)
	if err != nil {
		return crds, err
	}
	crds = append(crds, &bgpconfig)

	cns := v1.CustomResourceDefinition{}
	err = yaml.Unmarshal([]byte(caliconodestatuses), &cns)
	if err != nil {
		return crds, err
	}
	crds = append(crds, &cns)

	bgpPeer := v1.CustomResourceDefinition{}
	err = yaml.Unmarshal([]byte(bgppeers), &bgpPeer)
	if err != nil {
		return crds, err
	}
	crds = append(crds, &bgpPeer)

	blockAffinity := v1.CustomResourceDefinition{}
	err = yaml.Unmarshal([]byte(blockaffinities), &blockAffinity)
	if err != nil {
		return crds, err
	}
	crds = append(crds, &blockAffinity)

	clusterInfo := v1.CustomResourceDefinition{}
	err = yaml.Unmarshal([]byte(clusterinformations), &clusterInfo)
	if err != nil {
		return crds, err
	}
	crds = append(crds, &clusterInfo)

	felixConfig := v1.CustomResourceDefinition{}
	err = yaml.Unmarshal([]byte(felixconfigurations), &felixConfig)
	if err != nil {
		return crds, err
	}
	crds = append(crds, &felixConfig)

	globalPolicy := v1.CustomResourceDefinition{}
	err = yaml.Unmarshal([]byte(globalnetworkpolicies), &globalPolicy)
	if err != nil {
		return crds, err
	}
	crds = append(crds, &globalPolicy)

	globalNetSet := v1.CustomResourceDefinition{}
	err = yaml.Unmarshal([]byte(globalnetworksets), &globalNetSet)
	if err != nil {
		return crds, err
	}
	crds = append(crds, &globalNetSet)

	hep := v1.CustomResourceDefinition{}
	err = yaml.Unmarshal([]byte(hostendpoints), &hep)
	if err != nil {
		return crds, err
	}
	crds = append(crds, &hep)

	ipamBlock := v1.CustomResourceDefinition{}
	err = yaml.Unmarshal([]byte(ipamblocks), &ipamBlock)
	if err != nil {
		return crds, err
	}
	crds = append(crds, &ipamBlock)

	ipamConfig := v1.CustomResourceDefinition{}
	err = yaml.Unmarshal([]byte(ipamconfigs), &ipamConfig)
	if err != nil {
		return crds, err
	}
	crds = append(crds, &ipamConfig)

	ipamHandle := v1.CustomResourceDefinition{}
	err = yaml.Unmarshal([]byte(ipamhandles), &ipamHandle)
	if err != nil {
		return crds, err
	}
	crds = append(crds, &ipamHandle)

	ipPool := v1.CustomResourceDefinition{}
	err = yaml.Unmarshal([]byte(ippools), &ipPool)
	if err != nil {
		return crds, err
	}
	crds = append(crds, &ipPool)

	ipResv := v1.CustomResourceDefinition{}
	err = yaml.Unmarshal([]byte(ipreservations), &ipResv)
	if err != nil {
		return crds, err
	}
	crds = append(crds, &ipResv)

	kubeControllerConfig := v1.CustomResourceDefinition{}
	err = yaml.Unmarshal([]byte(kubecontrollersconfigurations), &kubeControllerConfig)
	if err != nil {
		return crds, err
	}
	crds = append(crds, &kubeControllerConfig)

	policy := v1.CustomResourceDefinition{}
	err = yaml.Unmarshal([]byte(networkpolicies), &policy)
	if err != nil {
		return crds, err
	}
	crds = append(crds, &policy)

	netset := v1.CustomResourceDefinition{}
	err = yaml.Unmarshal([]byte(networksets), &netset)
	if err != nil {
		return crds, err
	}
	crds = append(crds, &netset)

	return crds, nil
}
