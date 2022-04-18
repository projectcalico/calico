// Copyright (c) 2020-2022 Tigera, Inc. All rights reserved.
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

package tc

import (
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/environment"
)

// TCHook is the hook to which a BPF program should be attached.  This is relative to the host namespace
// so workload PolDirnIngress policy is attached to the HookEgress.
type Hook string

const (
	HookIngress Hook = "ingress"
	HookEgress  Hook = "egress"
)

type ToOrFromEp string

const (
	FromEp ToOrFromEp = "from"
	ToEp   ToOrFromEp = "to"
)

type EndpointType string

const (
	EpTypeWorkload EndpointType = "workload"
	EpTypeHost     EndpointType = "host"
	EpTypeTunnel   EndpointType = "tunnel"
	EpTypeL3Device EndpointType = "l3dev"
)

type ProgName string

var programNames = []ProgName{
	"calico_tc_norm_pol_tail",
	"calico_tc_skb_accepted_entrypoint",
	"calico_tc_skb_send_icmp_replies",
	"calico_tc_skb_drop",
	"calico_tc_v6",
	"calico_tc_v6_norm_pol_tail",
	"calico_tc_v6_skb_accepted_entrypoint",
	"calico_tc_v6_skb_send_icmp_replies",
	"calico_tc_v6_skb_drop",
}

func SectionName(endpointType EndpointType, fromOrTo ToOrFromEp) string {
	return fmt.Sprintf("calico_%s_%s_ep", fromOrTo, endpointType)
}

func ProgFilename(epType EndpointType, toOrFrom ToOrFromEp, epToHostDrop, fib, dsr bool, logLevel string, btf bool, features *environment.Features) string {
	if epToHostDrop && (epType != EpTypeWorkload || toOrFrom == ToEp) {
		// epToHostDrop only makes sense in the from-workload program.
		logrus.Debug("Ignoring epToHostDrop, doesn't apply to this target")
		epToHostDrop = false
	}
	if fib && (toOrFrom != FromEp) {
		// FIB lookup only makes sense for traffic towards the host.
		logrus.Debug("Ignoring fib enabled, doesn't apply to this target")
		fib = false
	}

	var hostDropPart string
	if epType == EpTypeWorkload && epToHostDrop {
		hostDropPart = "host_drop_"
	}
	fibPart := ""
	if fib {
		fibPart = "fib_"
	}
	dsrPart := ""
	if dsr && ((epType == EpTypeWorkload && toOrFrom == FromEp) || (epType == EpTypeHost)) {
		dsrPart = "dsr_"
	}
	logLevel = strings.ToLower(logLevel)
	if logLevel == "off" {
		logLevel = "no_log"
	}
	var epTypeShort string
	switch epType {
	case EpTypeWorkload:
		epTypeShort = "wep"
	case EpTypeHost:
		epTypeShort = "hep"
	case EpTypeTunnel:
		if features.IPIPDeviceIsL3 {
			epTypeShort = "l3"
		} else {
			epTypeShort = "tnl"
		}
	case EpTypeL3Device:
		epTypeShort = "l3"
	}
	corePart := ""
	if btf {
		corePart = "_co-re"
	}
	oFileName := fmt.Sprintf("%v_%v_%s%s%s%v%s.o",
		toOrFrom, epTypeShort, hostDropPart, fibPart, dsrPart, logLevel, corePart)
	return oFileName
}
