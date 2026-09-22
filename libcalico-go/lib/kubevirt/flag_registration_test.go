// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

package kubevirt_test

import (
	goflag "flag"
	"testing"

	// Imported for its side effects only: linking the kubevirt clientset must
	// not register anything on flag.CommandLine.
	_ "kubevirt.io/client-go/log"
)

// TestKubevirtClientDoesNotRegisterGlobalFlags guards against a regression that
// forced us onto a fork of kubevirt.io/client-go for several releases.  Its log
// package used to register a "-v" flag on flag.CommandLine from init(), which
// panicked with "flag redefined: v" in any binary where something else -- klog,
// glog, the k8s e2e framework -- had already registered "-v" there.  Since
// kubevirt/kubevirt#18294 the flag lives on a package-private FlagSet, reachable
// via log.VerbosityFlag().
//
// If this test starts failing after a client-go bump, the global registration is
// back; raise it upstream rather than re-forking.
func TestKubevirtClientDoesNotRegisterGlobalFlags(t *testing.T) {
	if f := goflag.CommandLine.Lookup("v"); f != nil {
		t.Fatalf("kubevirt.io/client-go registered a %q flag on flag.CommandLine (value type %T); "+
			"binaries that also register %q will panic at startup", "v", f.Value, "v")
	}
}
