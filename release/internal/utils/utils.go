package utils

import (
	"os"
	"path/filepath"

	"github.com/sirupsen/logrus"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

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

const (
	// Calico is the product name for projectcalico.
	Calico = "calico"

	// CalicoRepoName is the name of the projectcalico repo.
	CalicoRepoName = Calico

	// BirdRepoName is the name of the bird repo.
	BirdRepoName = "bird"

	// CalicoProductCode is the code for projectcalico.
	CalicoProductCode = "os"

	// ProjectCalicoOrg is the name of the Project Calico organization.
	ProjectCalicoOrg = "projectcalico"

	// TigeraOrg is the name of the Tigera organization.
	TigeraOrg = "tigera"

	// CalicoEnterprise is the product name for Calico Enterprise.
	CalicoEnterprise = "calico enterprise"
)

// CalicoProductName returns the calico product name in title case.
func CalicoProductName() string {
	return cases.Title(language.English).String(Calico)
}

// EnterpriseProductName returns the calico enterprise product name in title case.
func EnterpriseProductName() string {
	return cases.Title(language.English).String(CalicoEnterprise)
}

// Contains returns true if the a string is in a string slice.
func Contains(haystack []string, needle string) bool {
	for _, item := range haystack {
		if item == needle {
			return true
		}
	}
	return false
}

// DetermineProduct determines the product name based on the presence of a calico.yaml file.
func DetermineProduct(repoRoot string) string {
	info, err := os.Stat(filepath.Join(repoRoot, "manifests", "calico.yaml"))
	if err != nil {
		if os.IsNotExist(err) {
			return EnterpriseProductName()
		}
		logrus.WithError(err).Fatal("error checking for calico.yaml")
	}
	if info.IsDir() {
		logrus.Fatalf("calico.yaml is a directory")
	}
	return CalicoProductName()
}
