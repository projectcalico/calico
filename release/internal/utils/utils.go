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

package utils

const (
	// ProductName is used in the release process to identify the product.
	ProductName = CalicoProductName

	// Calico is the product name for projectcalico.
	Calico = "calico"

	// CalicoRepoName is the name of the projectcalico repo.
	CalicoRepoName = Calico

	// BirdRepoName is the name of the bird repo.
	BirdRepoName = "bird"

	// CalicoProductCode is the code for projectcalico.
	CalicoProductCode = "os"

	// CalicoProductName is the name of the projectcalico product.
	CalicoProductName = "Calico"

	// ProjectCalicoOrg is the name of the Project Calico organization.
	ProjectCalicoOrg = "projectcalico"

	// TigeraOrg is the name of the Tigera organization.
	TigeraOrg = "tigera"
)

// Contains returns true if the a string is in a string slice.
func Contains(haystack []string, needle string) bool {
	for _, item := range haystack {
		if item == needle {
			return true
		}
	}
	return false
}
