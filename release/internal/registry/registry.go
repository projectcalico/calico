// Copyright (c) 2024 Tigera, Inc. All rights reserved.

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

package registry

const defaultCalicoRegistry = "quay.io/calico"

var DefaultProductRegistry = defaultCalicoRegistry

var DefaultCalicoRegistries = []string{
	defaultCalicoRegistry,
	"docker.io/calico",
	"gcr.io/projectcalico-org",
	"eu.gcr.io/projectcalico-org",
	"asia.gcr.io/projectcalico-org",
	"us.gcr.io/projectcalico-org",
}

// DefaultOperatorRegistries are the registries the operator image publishes to. It
// ships alongside the other Calico component images, but is not mirrored to GCR.
var DefaultOperatorRegistries = []string{defaultCalicoRegistry, "docker.io/calico"}

var DefaultHelmRegistries = []string{
	"quay.io/calico/charts",
}
