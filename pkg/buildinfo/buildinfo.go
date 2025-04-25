// Copyright (c) 2019-2025 Tigera, Inc. All rights reserved.
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

package buildinfo

import "fmt"

// Filled in by build process.
var (
	// Version is the version of the code.
	Version string

	// GitRevision is the commit hash of the code.
	GitRevision string

	// BuildDate is the date when the code was built.
	BuildDate string
)

// PrintVersion prints version and build information.
func PrintVersion() {
	fmt.Println("Version:     ", Version)
	fmt.Println("Build date:  ", BuildDate)
	fmt.Println("Git commit:  ", GitRevision)
}
