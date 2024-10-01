// Copyright (c) 2024 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package config

import (
	"fmt"

	v1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"sigs.k8s.io/yaml"
)

func ExampleCRDFiles() {
	var crd v1.CustomResourceDefinition
	rawYAML, err := CRDFiles.ReadFile("crd/crd.projectcalico.org_felixconfigurations.yaml")
	if err != nil {
		panic(err)
	}
	err = yaml.Unmarshal(rawYAML, &crd)
	if err != nil {
		panic(err)
	}
	fmt.Println(crd.GetName())
	// Output: felixconfigurations.crd.projectcalico.org
}

func ExampleLoadCRD() {
	crd, err := LoadCRD("crd.projectcalico.org", "felixconfigurations")
	if err != nil {
		panic(err)
	}
	fmt.Println(crd.GetName())
	// Output: felixconfigurations.crd.projectcalico.org
}
