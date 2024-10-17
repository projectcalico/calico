// Copyright (c) 2023 Tigera, Inc. All rights reserved.
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

package hook

import (
	"strings"

	"github.com/projectcalico/calico/felix/bpf/bpfutils"
	tcdefs "github.com/projectcalico/calico/felix/bpf/tc/defs"
)

func init() {
	initObjectFiles()
}

// Hook is the hook to which a BPF program should be attached. This is relative to
// the host namespace so workload PolDirnIngress policy is attached to the HookEgress.
type Hook int

func (h Hook) String() string {
	switch h {
	case Ingress:
		return "ingress"
	case Egress:
		return "egress"
	case XDP:
		return "xdp"
	}

	return "unknown"
}

func StringToHook(s string) Hook {
	switch s {
	case "ingress":
		return Ingress
	case "egress":
		return Egress
	case "xdp":
		return XDP
	}

	return Bad
}

const (
	Ingress Hook = iota
	Egress
	XDP
	Count

	Bad Hook = -1
)

var All = []Hook{Ingress, Egress, XDP}

type AttachType struct {
	Hook       Hook
	Family     int
	Type       tcdefs.EndpointType
	LogLevel   string
	FIB        bool
	ToHostDrop bool
	DSR        bool
}

func (at AttachType) ObjectFile() string {
	return objectFiles[at]
}

func (at AttachType) hasHostConflictProg() bool {
	switch at.Type {
	case tcdefs.EpTypeWorkload:
		return false
	}

	return at.Hook == Egress
}

type DefPolicy int

const (
	DefPolicyDeny  DefPolicy = -1
	DefPolicyNone  DefPolicy = 0
	DefPolicyAllow DefPolicy = 1
)

func (at AttachType) DefaultPolicy() DefPolicy {
	if at.Hook == XDP || at.Type == tcdefs.EpTypeHost || at.Type == tcdefs.EpTypeNAT || at.Type == tcdefs.EpTypeLO {
		return DefPolicyNone
	}

	if at.Type == tcdefs.EpTypeTunnel || at.Type == tcdefs.EpTypeL3Device {
		return DefPolicyAllow
	}

	return DefPolicyDeny
}

var objectFiles = make(map[AttachType]string)

func initObjectFiles() {
	for _, family := range []int{4, 6} {
		for _, logLevel := range []string{"off", "debug"} {
			for _, epToHostDrop := range []bool{false, true} {
				epToHostDrop := epToHostDrop
				for _, fibEnabled := range []bool{false, true} {
					fibEnabled := fibEnabled
					epTypes := []tcdefs.EndpointType{
						tcdefs.EpTypeWorkload,
						tcdefs.EpTypeHost,
						tcdefs.EpTypeTunnel,
						tcdefs.EpTypeL3Device,
						tcdefs.EpTypeNAT,
						tcdefs.EpTypeLO,
					}
					for _, epType := range epTypes {
						epType := epType
						for _, hook := range []Hook{Ingress, Egress} {
							hook := hook
							for _, dsr := range []bool{false, true} {
								toOrFrom := tcdefs.ToEp
								if hook == Ingress {
									toOrFrom = tcdefs.FromEp
								}

								objectFiles[AttachType{
									Family:     family,
									Type:       epType,
									Hook:       hook,
									ToHostDrop: epToHostDrop,
									FIB:        fibEnabled,
									DSR:        dsr,
									LogLevel:   logLevel,
								}] = tcdefs.ProgFilename(
									family,
									epType,
									toOrFrom,
									epToHostDrop,
									fibEnabled,
									dsr,
									logLevel,
									bpfutils.SupportsBTF(),
								)
							}
						}
					}
				}
			}
		}
	}

	for _, family := range []int{4, 6} {
		for _, logLevel := range []string{"off", "debug"} {
			l := strings.ToLower(logLevel)
			if l == "off" {
				l = "no_log"
			}
			filename := "xdp_" + l + ".o"
			if family == 6 {
				filename = "xdp_" + l + "_co-re_v6.o"
			}

			objectFiles[AttachType{
				Family:   family,
				Hook:     XDP,
				LogLevel: logLevel,
			}] = filename
		}
	}
}

func ListAttachTypes() []AttachType {
	var ret []AttachType

	for at := range objectFiles {
		ret = append(ret, at)
	}

	return ret
}
