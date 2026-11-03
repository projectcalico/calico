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

package k8s

import (
	"context"
	"encoding/json"
	"net"
	"strings"

	"github.com/containernetworking/cni/pkg/version"
)

// fakeIPAMCall records one invocation of the fake IPAM plugin.
type fakeIPAMCall struct {
	Command string
	IP      string
	Stdin   []byte
}

// fakeIPAMIPAMConf is the part of the IPAM stdin the fake reads.
type fakeIPAMIPAMConf struct {
	AssignIPv4 string `json:"assign_ipv4"`
	AssignIPv6 string `json:"assign_ipv6"`
}

// fakeIPAMConf is the part of the CNI stdin the fake reads.
type fakeIPAMConf struct {
	IPAM fakeIPAMIPAMConf `json:"ipam"`
}

// fakeIPAMResult is a 1.0.0 CNI result as the fake emits it.
type fakeIPAMResult struct {
	CNIVersion string          `json:"cniVersion"`
	IPs        []fakeIPAMIPCfg `json:"ips"`
}

// fakeIPAMIPCfg is one address in a fakeIPAMResult.
type fakeIPAMIPCfg struct {
	Address string `json:"address"`
}

// fakeIPAMExec is an invoke.Exec that stands in for the calico-ipam binary. ADDs with an IP=
// argument return that address unless addErrs has an error for it. ADDs without one return
// the fresh addresses, filtered by the assign_ipv4 and assign_ipv6 values on stdin.
type fakeIPAMExec struct {
	addErrs map[string]error
	fresh   []string
	calls   []fakeIPAMCall
}

func (f *fakeIPAMExec) FindInPath(plugin string, _ []string) (string, error) {
	return "/fake/" + plugin, nil
}

func (f *fakeIPAMExec) Decode(_ []byte) (version.PluginInfo, error) {
	return version.PluginSupports("1.0.0"), nil
}

func (f *fakeIPAMExec) ExecPlugin(_ context.Context, _ string, stdin []byte, environ []string) ([]byte, error) {
	call := fakeIPAMCall{Stdin: stdin}
	for _, e := range environ {
		switch {
		case strings.HasPrefix(e, "CNI_COMMAND="):
			call.Command = strings.TrimPrefix(e, "CNI_COMMAND=")
		case strings.HasPrefix(e, "CNI_ARGS="):
			for _, kv := range strings.Split(strings.TrimPrefix(e, "CNI_ARGS="), ";") {
				if v, ok := strings.CutPrefix(kv, "IP="); ok {
					call.IP = v
				}
			}
		}
	}
	f.calls = append(f.calls, call)

	if call.Command != "ADD" {
		return nil, nil
	}
	if err, ok := f.addErrs[call.IP]; ok && call.IP != "" {
		return nil, err
	}

	var addrs []string
	if call.IP != "" {
		addrs = []string{call.IP}
	} else {
		var conf fakeIPAMConf
		if err := json.Unmarshal(stdin, &conf); err != nil {
			return nil, err
		}
		for _, a := range f.fresh {
			isV4 := net.ParseIP(a).To4() != nil
			if isV4 && conf.IPAM.AssignIPv4 == "false" || !isV4 && conf.IPAM.AssignIPv6 != "true" {
				continue
			}
			addrs = append(addrs, a)
		}
	}

	res := fakeIPAMResult{CNIVersion: "1.0.0"}
	for _, a := range addrs {
		bits := "/32"
		if net.ParseIP(a).To4() == nil {
			bits = "/128"
		}
		res.IPs = append(res.IPs, fakeIPAMIPCfg{Address: a + bits})
	}
	return json.Marshal(res)
}

// callsFor returns the recorded calls with the given CNI command.
func (f *fakeIPAMExec) callsFor(command string) []fakeIPAMCall {
	var out []fakeIPAMCall
	for _, c := range f.calls {
		if c.Command == command {
			out = append(out, c)
		}
	}
	return out
}

// freshAdds returns the recorded ADD calls that carried no IP= argument.
func (f *fakeIPAMExec) freshAdds() []fakeIPAMCall {
	var out []fakeIPAMCall
	for _, c := range f.callsFor("ADD") {
		if c.IP == "" {
			out = append(out, c)
		}
	}
	return out
}
