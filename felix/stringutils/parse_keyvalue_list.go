// Copyright (c) 2020 Tigera, Inc. All rights reserved.
// Copyright (c) 2020 Nordix Foundation
//
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

package stringutils

// https://play.golang.org/p/xSEX1CAcQE

import (
	"fmt"
	"regexp"
	"strings"
)

var rex = regexp.MustCompile(`\s*(\w+)=(.*)`)

// ParseKeyValueList parses a comma-separated key=value list to a map.
// Keys must contain only word characters (leading spaces ignored).
// Spaces in the value are preserved.
func ParseKeyValueList(param string) (map[string]string, error) {
	res := make(map[string]string)
	if len(strings.TrimSpace(param)) == 0 {
		return res, nil
	}
	var invalidItems []string
	for _, item := range strings.Split(param, ",") {
		if item == "" {
			// Accept empty items (e.g tailing ",")
			continue
		}
		kv := rex.FindStringSubmatch(item)
		if kv == nil {
			invalidItems = append(invalidItems, item)
			continue
		}
		res[kv[1]] = kv[2]
	}
	if len(invalidItems) > 0 {
		return nil, fmt.Errorf("Invalid items %v", invalidItems)
	}
	return res, nil
}
