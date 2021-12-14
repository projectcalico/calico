// Copyright (c) 2019 Tigera, Inc. All rights reserved.

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

package updateprocessors

import (
	"fmt"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/selector/parser"
)

// parseSelectorAttachPrefix takes a v3 selector and returns the appropriate v1 representation
// by prefixing the keys with the given prefix.
// If prefix is `pcns.` then the selector changes from `k == 'v'` to `pcns.k == 'v'`.
func parseSelectorAttachPrefix(s, prefix string) string {
	parsedSelector, err := parser.Parse(s)
	if err != nil {
		log.WithError(err).Errorf("Failed to parse selector: %s (for prefix) %s", s, prefix)
		return ""
	}
	parsedSelector.AcceptVisitor(parser.PrefixVisitor{Prefix: prefix})
	updated := parsedSelector.String()
	log.WithFields(log.Fields{"original": s, "updated": updated}).Debug("Updated selector")
	return updated
}

// prefixAndAppendSelector prefixes a new selector string with the given prefix and appends it to an existing selector string.
func prefixAndAppendSelector(currentSelector, newSelector, prefix string) string {
	if newSelector != "" {
		prefixedSelector := parseSelectorAttachPrefix(newSelector, prefix)
		if prefixedSelector != "" {
			if currentSelector != "" {
				currentSelector = fmt.Sprintf("(%s) && %s", currentSelector, prefixedSelector)
			} else {
				currentSelector = prefixedSelector
			}
		}
	}
	return currentSelector
}
