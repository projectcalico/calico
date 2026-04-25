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

package main

import (
	"testing"
)

func TestDispatch(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		cniCommand string
		wantMode   dispatchMode
	}{
		{
			name:       "plain calicoctl basename runs the ctl command tree as root",
			args:       []string{"/usr/bin/calicoctl", "get", "nodes"},
			cniCommand: "",
			wantMode:   modeCalicoctl,
		},
		{
			name:       "calicoctl basename ignores CNI_COMMAND in the env",
			args:       []string{"/usr/bin/calicoctl", "get", "nodes"},
			cniCommand: "ADD",
			wantMode:   modeCalicoctl,
		},
		{
			name:       "calicoctl-linux-amd64 release artifact runs ctl as root",
			args:       []string{"./calicoctl-linux-amd64", "get", "nodes"},
			cniCommand: "",
			wantMode:   modeCalicoctl,
		},
		{
			name:       "calicoctl-windows-amd64.exe release artifact runs ctl as root",
			args:       []string{"./calicoctl-windows-amd64.exe", "get", "nodes"},
			cniCommand: "",
			wantMode:   modeCalicoctl,
		},
		{
			name:       "calicoctl.exe (renamed) runs ctl as root",
			args:       []string{"calicoctl.exe", "get", "nodes"},
			cniCommand: "",
			wantMode:   modeCalicoctl,
		},
		{
			name:       "calico-ipam basename dispatches to IPAM plugin",
			args:       []string{"/opt/cni/bin/calico-ipam"},
			cniCommand: "ADD",
			wantMode:   modeCNIIPAM,
		},
		{
			name:       "plain calico with CNI_COMMAND and no args dispatches to CNI plugin",
			args:       []string{"/opt/cni/bin/calico"},
			cniCommand: "ADD",
			wantMode:   modeCNI,
		},
		{
			name:       "plain calico without CNI_COMMAND runs Cobra",
			args:       []string{"/usr/bin/calico"},
			cniCommand: "",
			wantMode:   modeCobra,
		},
		{
			name:       "plain calico with subcommand ignores CNI_COMMAND (footgun guard)",
			args:       []string{"/usr/bin/calico", "component", "felix"},
			cniCommand: "ADD",
			wantMode:   modeCobra,
		},
		{
			name:       "plain calico with subcommand and no CNI_COMMAND runs Cobra",
			args:       []string{"/usr/bin/calico", "health", "--port=9099"},
			cniCommand: "",
			wantMode:   modeCobra,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotMode := dispatch(tt.args, tt.cniCommand)
			if gotMode != tt.wantMode {
				t.Errorf("mode = %v, want %v", gotMode, tt.wantMode)
			}
		})
	}
}
