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
	"reflect"
	"testing"
)

func TestDispatch(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		cniCommand string
		wantMode   dispatchMode
		wantArgs   []string
	}{
		{
			name:       "calicoctl basename inserts ctl subcommand and preserves argv[0]",
			args:       []string{"/usr/bin/calicoctl", "get", "nodes"},
			cniCommand: "",
			wantMode:   modeCobra,
			wantArgs:   []string{"/usr/bin/calicoctl", "ctl", "get", "nodes"},
		},
		{
			name:       "calicoctl basename ignores CNI_COMMAND in the env",
			args:       []string{"/usr/bin/calicoctl", "get", "nodes"},
			cniCommand: "ADD",
			wantMode:   modeCobra,
			wantArgs:   []string{"/usr/bin/calicoctl", "ctl", "get", "nodes"},
		},
		{
			name:       "calicoctl with no args still rewrites (help path)",
			args:       []string{"/usr/bin/calicoctl"},
			cniCommand: "",
			wantMode:   modeCobra,
			wantArgs:   []string{"/usr/bin/calicoctl", "ctl"},
		},
		{
			name:       "uds basename inserts component flexvol and preserves argv[0]",
			args:       []string{"/usr/libexec/kubernetes/kubelet-plugins/volume/exec/nodeagent~uds/uds", "mount", "/dest", "{}"},
			cniCommand: "",
			wantMode:   modeCobra,
			wantArgs:   []string{"/usr/libexec/kubernetes/kubelet-plugins/volume/exec/nodeagent~uds/uds", "component", "flexvol", "mount", "/dest", "{}"},
		},
		{
			name:       "uds basename with no args still rewrites (help path)",
			args:       []string{"/host/driver/uds"},
			cniCommand: "",
			wantMode:   modeCobra,
			wantArgs:   []string{"/host/driver/uds", "component", "flexvol"},
		},
		{
			name:       "uds basename ignores CNI_COMMAND in the env",
			args:       []string{"/host/driver/uds", "init"},
			cniCommand: "ADD",
			wantMode:   modeCobra,
			wantArgs:   []string{"/host/driver/uds", "component", "flexvol", "init"},
		},
		{
			name:       "calico-ipam basename dispatches to IPAM plugin",
			args:       []string{"/opt/cni/bin/calico-ipam"},
			cniCommand: "ADD",
			wantMode:   modeCNIIPAM,
			wantArgs:   []string{"/opt/cni/bin/calico-ipam"},
		},
		{
			name:       "plain calico with CNI_COMMAND and no args dispatches to CNI plugin",
			args:       []string{"/opt/cni/bin/calico"},
			cniCommand: "ADD",
			wantMode:   modeCNI,
			wantArgs:   []string{"/opt/cni/bin/calico"},
		},
		{
			name:       "plain calico without CNI_COMMAND runs Cobra",
			args:       []string{"/usr/bin/calico"},
			cniCommand: "",
			wantMode:   modeCobra,
			wantArgs:   []string{"/usr/bin/calico"},
		},
		{
			name:       "plain calico with cobra subcommand ignores CNI_COMMAND (footgun guard)",
			args:       []string{"/usr/bin/calico", "component", "felix"},
			cniCommand: "ADD",
			wantMode:   modeCobra,
			wantArgs:   []string{"/usr/bin/calico", "component", "felix"},
		},
		{
			name:       "plain calico with CNI_COMMAND and netconf positional arg dispatches to CNI plugin",
			args:       []string{"/opt/cni/bin/calico", `{"name":"net","type":"calico"}`},
			cniCommand: "ADD",
			wantMode:   modeCNI,
			wantArgs:   []string{"/opt/cni/bin/calico", `{"name":"net","type":"calico"}`},
		},
		{
			name:       "plain calico with CNI_COMMAND and -t flag dispatches to CNI plugin",
			args:       []string{"/opt/cni/bin/calico", "-t"},
			cniCommand: "VERSION",
			wantMode:   modeCNI,
			wantArgs:   []string{"/opt/cni/bin/calico", "-t"},
		},
		{
			name:       "plain calico with subcommand and no CNI_COMMAND runs Cobra",
			args:       []string{"/usr/bin/calico", "health", "--port=9099"},
			cniCommand: "",
			wantMode:   modeCobra,
			wantArgs:   []string{"/usr/bin/calico", "health", "--port=9099"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotMode, gotArgs := dispatch(tt.args, tt.cniCommand)
			if gotMode != tt.wantMode {
				t.Errorf("mode = %v, want %v", gotMode, tt.wantMode)
			}
			if !reflect.DeepEqual(gotArgs, tt.wantArgs) {
				t.Errorf("args = %v, want %v", gotArgs, tt.wantArgs)
			}
		})
	}
}
