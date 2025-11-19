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
	"sync"

	tcdefs "github.com/projectcalico/calico/felix/bpf/tc/defs"
	bpfutils "github.com/projectcalico/calico/felix/bpf/utils"
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
	ToHostDrop bool
	DSR        bool
}

func (at AttachType) ObjectFile() string {
	return ObjectFile(at)
}

func (at AttachType) hasHostConflictProg() bool {
	switch at.Type {
	case tcdefs.EpTypeWorkload:
		return false
	}

	return at.Hook == Egress
}

func (at AttachType) hasIPDefrag() bool {
	if at.Family != 4 {
		return false
	}

	switch at.Type {
	case tcdefs.EpTypeLO, tcdefs.EpTypeNAT:
		return false
	}

	return at.Hook == Ingress
}

func (at AttachType) hasMaglev() bool {
	return at.Type == tcdefs.EpTypeHost && at.Hook == Ingress
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

	if at.Type == tcdefs.EpTypeIPIP || at.Type == tcdefs.EpTypeL3Device || at.Type == tcdefs.EpTypeVXLAN {
		return DefPolicyAllow
	}

	return DefPolicyDeny
}

var (
	objectFilesLock sync.Mutex
	objectFiles     = make(map[AttachType]string)
)

func ObjectFile(at AttachType) string {
	objectFilesLock.Lock()
	defer objectFilesLock.Unlock()

	return objectFiles[at]
}

func SetObjectFile(at AttachType, file string) {
	objectFilesLock.Lock()
	defer objectFilesLock.Unlock()

	objectFiles[at] = file
}

func initObjectFiles() {
	for _, family := range []int{4, 6} {
		for _, logLevel := range []string{"off", "debug"} {
			for _, epToHostDrop := range []bool{false, true} {
				epToHostDrop := epToHostDrop
				epTypes := []tcdefs.EndpointType{
					tcdefs.EpTypeWorkload,
					tcdefs.EpTypeHost,
					tcdefs.EpTypeIPIP,
					tcdefs.EpTypeL3Device,
					tcdefs.EpTypeNAT,
					tcdefs.EpTypeLO,
					tcdefs.EpTypeVXLAN,
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

							attachType := AttachType{
								Family:     family,
								Type:       epType,
								Hook:       hook,
								ToHostDrop: epToHostDrop,
								DSR:        dsr,
								LogLevel:   logLevel,
							}
							filename := tcdefs.ProgFilename(
								family,
								epType,
								toOrFrom,
								epToHostDrop,
								dsr,
								logLevel,
								bpfutils.BTFEnabled,
							)
							SetObjectFile(attachType, filename)
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

			SetObjectFile(AttachType{
				Family:   family,
				Hook:     XDP,
				LogLevel: logLevel,
			}, filename)
		}
	}
}

func ListAttachTypes() []AttachType {
	objectFilesLock.Lock()
	defer objectFilesLock.Unlock()

	var ret []AttachType

	for at := range objectFiles {
		ret = append(ret, at)
	}

	return ret
}
