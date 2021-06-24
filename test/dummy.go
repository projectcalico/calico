// Copyright (c) 2021 Tigera, Inc. All rights reserved.

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

package test

// this is for packages that need to be included in go.mod but aren't actually imported in the code (i.e. used for
// testing). If this isn't done, mod tidy will remove the dependency from go.mod.
import (
	_ "sigs.k8s.io/kind/pkg/apis/config/defaults"
)
