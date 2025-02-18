// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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

package version

import "fmt"

// BuildVersion stores the SemVer for the given build
var BuildVersion string

// BuildDate stores the date of the build
var BuildDate string

// GitDescription stores the tag description
var GitDescription string

// GitRevision stores git commit hash for the given build
var GitRevision string

// Version prints version and build information.
func Version() {
	fmt.Println("Version:     ", BuildVersion)
	fmt.Println("Build date:  ", BuildDate)
	fmt.Println("Git tag ref: ", GitDescription)
	fmt.Println("Git commit:  ", GitRevision)
}
