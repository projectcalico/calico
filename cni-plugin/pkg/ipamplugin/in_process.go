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

package ipamplugin

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/containernetworking/cni/pkg/invoke"
	"github.com/containernetworking/cni/pkg/skel"
)

var _ invoke.Exec = &inProcessExec{}

// inProcessExec runs calico-ipam inside the calling process and execs any other IPAM
// plugin. A runtime that kills the calico plugin at its deadline then takes the IPAM call
// down with it, instead of leaving a calico-ipam process to finish an allocation for a
// sandbox the runtime has already given up on.
type inProcessExec struct {
	invoke.DefaultExec
}

// NewInProcessExec returns an invoke.Exec that runs calico-ipam in this process. Any other
// plugin is exec'd with its logs sent to stderr, as the CNI library's default does.
func NewInProcessExec() invoke.Exec {
	return &inProcessExec{DefaultExec: invoke.DefaultExec{RawExec: &invoke.RawExec{Stderr: os.Stderr}}}
}

// ExecPlugin implements invoke.Exec.
func (e *inProcessExec) ExecPlugin(ctx context.Context, pluginPath string, stdinData []byte, environ []string) ([]byte, error) {
	if !isCalicoIPAM(filepath.Base(pluginPath)) {
		return e.DefaultExec.ExecPlugin(ctx, pluginPath, stdinData, environ)
	}

	env := envMap(environ)
	args := &skel.CmdArgs{
		ContainerID: env["CNI_CONTAINERID"],
		Netns:       env["CNI_NETNS"],
		IfName:      env["CNI_IFNAME"],
		Args:        env["CNI_ARGS"],
		Path:        env["CNI_PATH"],
		StdinData:   stdinData,
	}
	switch env["CNI_COMMAND"] {
	case "ADD":
		result, err := add(ctx, args)
		if err != nil {
			return nil, err
		}
		return json.Marshal(result)
	case "DEL":
		return nil, del(ctx, args)
	default:
		return nil, fmt.Errorf("calico-ipam does not support %s in-process", env["CNI_COMMAND"])
	}
}

// FindInPath implements invoke.Exec. calico-ipam resolves without a lookup, since it runs in
// this process and its binary need not be on CNI_PATH.
func (e *inProcessExec) FindInPath(plugin string, paths []string) (string, error) {
	if isCalicoIPAM(plugin) {
		return plugin, nil
	}
	return e.DefaultExec.FindInPath(plugin, paths)
}

func isCalicoIPAM(name string) bool {
	return name == "calico-ipam" || name == "calico-ipam.exe"
}

// envMap indexes a KEY=VALUE environment. A later entry wins, as it does for exec.
func envMap(environ []string) map[string]string {
	env := make(map[string]string, len(environ))
	for _, kv := range environ {
		k, v, _ := strings.Cut(kv, "=")
		env[k] = v
	}
	return env
}
