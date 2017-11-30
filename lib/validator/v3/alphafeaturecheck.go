// Copyright (c) 2017 Tigera, Inc. All rights reserved.

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

package v3

import (
	"errors"

	apiv3 "github.com/projectcalico/libcalico-go/lib/apis/v3"
)

// ValidateNoServiceAccountRules checks if the set of rules have the
// serviceAccount match set and if yes then it returns an error.
func ValidateNoServiceAccountRules(ingress, egress []apiv3.Rule) error {
	for _, rule := range ingress {
		if rule.Source.ServiceAccounts != nil ||
			rule.Destination.ServiceAccounts != nil {
			return errors.New("alpha feature Service Account Match used")
		}
	}

	for _, rule := range egress {
		if rule.Source.ServiceAccounts != nil ||
			rule.Destination.ServiceAccounts != nil {
			return errors.New("alpha feature Service Account Match used")
		}
	}

	return nil
}

// ValidateNoHTTPRules checks if the set of rules have the
// serviceAccount match set and if yes then it returns an error.
func ValidateNoHTTPRules(ingress, egress []apiv3.Rule) error {
	for _, rule := range ingress {
		if rule.HTTP != nil {
			return errors.New("alpha feature HTTP Rules used")
		}
	}

	for _, rule := range egress {
		if rule.HTTP != nil {
			return errors.New("alpha feature HTTP Rules used")
		}
	}

	return nil
}
