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
	EpTypeNAT      EndpointType = "nat"
	EpTypeLO       EndpointType = "lo"
)

func SectionName(endpointType EndpointType, fromOrTo ToOrFromEp) string {
	return fmt.Sprintf("calico_%s_%s_ep", fromOrTo, endpointType)
}

func ProgFilename(epType EndpointType, toOrFrom ToOrFromEp, epToHostDrop, fib, dsr bool, logLevel string, btf bool) string {
	if epToHostDrop && (epType != EpTypeWorkload || toOrFrom == ToEp) {
		// epToHostDrop only makes sense in the from-workload program.
		logrus.Debug("Ignoring epToHostDrop, doesn't apply to this target")
		epToHostDrop = false
	}

	// Should match CALI_FIB_LOOKUP_ENABLED in bpf.h
	if fib {
		toHost := (epType == EpTypeWorkload || epType == EpTypeHost || epType == EpTypeLO) && toOrFrom == FromEp
		toHEP := (epType == EpTypeHost || epType == EpTypeLO) && toOrFrom == ToEp

		realFIB := epType != EpTypeL3Device && (toHost || toHEP)

		if !realFIB {
			// FIB lookup only makes sense for traffic towards the host.
			logrus.Debug("Ignoring fib enabled, doesn't apply to this target")
		}
		fib = realFIB
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
		epTypeShort = "tnl"
	case EpTypeL3Device:
		epTypeShort = "l3"
	case EpTypeNAT:
		epTypeShort = "nat"
	case EpTypeLO:
		epTypeShort = "lo"
	}
	corePart := ""
	if btf {
		corePart = "_co-re"
	}
	oFileName := fmt.Sprintf("%v_%v_%s%s%s%v%s.o",
		toOrFrom, epTypeShort, hostDropPart, fibPart, dsrPart, logLevel, corePart)
	return oFileName
}
