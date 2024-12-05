package utils

import (
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
	// Calico is the name of projectcalico.product.
	Calico = "calico"

	// CalicoCode is the code for Calico.
	CalicoCode = "os"

	// CalicoOrg is the organization for Calico.
	CalicoOrg = "projectcalico"

	// CalicoRepo is the repository for Calico.
	CalicoRepo = "calico"

	DevTagSuffix = "0.dev"

	ReleaseBranchPrefix = "release"

	GitRemote = "origin"
)

// DisplayProductName returns the product name in title case.
func DisplayProductName() string {
	return cases.Title(language.English).String(Calico)
}
