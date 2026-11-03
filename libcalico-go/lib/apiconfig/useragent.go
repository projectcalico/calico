// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package apiconfig

import (
	"fmt"
	"runtime"

	"github.com/projectcalico/calico/pkg/buildinfo"
)

// UserAgentFor renders the user agent a Calico component should present. The API
// server takes the text before the first slash as the field manager on a write, so
// the component name has to come first.
func UserAgentFor(component string) string {
	version := buildinfo.Version
	if version == "" {
		version = "unknown"
	}
	return fmt.Sprintf("%s/%s (%s/%s)", component, version, runtime.GOOS, runtime.GOARCH)
}
