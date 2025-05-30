// Copyright (c) 2017-2025 Tigera, Inc. All rights reserved.
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

package metric

import (
	"fmt"

	"k8s.io/kubernetes/pkg/proxy"

	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/collector/types/tuple"
	"github.com/projectcalico/calico/felix/collector/utils"
)

type Value struct {
	DeltaPackets int
	DeltaBytes   int
}

// Reset will set all the counters stored to 0
func (mv *Value) Reset() {
	mv.DeltaBytes = 0
	mv.DeltaPackets = 0
}

// Increments adds delta values for all counters using another MetricValue
func (mv *Value) Increment(other Value) {
	mv.DeltaBytes += other.DeltaBytes
	mv.DeltaPackets += other.DeltaPackets
}

func (mv Value) String() string {
	return fmt.Sprintf("delta=%v deltaBytes=%v",
		mv.DeltaPackets, mv.DeltaBytes)
}

// ServiceInfo holds information of a service for a MetricUpdate
type ServiceInfo struct {
	proxy.ServicePortName
	// the preDNATPort used to query from the Service info in dstService
	PortNum int
}

type UpdateType int

const (
	UpdateTypeReport UpdateType = iota
	UpdateTypeExpire
)

const (
	UpdateTypeReportStr = "report"
	UpdateTypeExpireStr = "expire"
)

func (ut UpdateType) String() string {
	if ut == UpdateTypeReport {
		return UpdateTypeReportStr
	}
	return UpdateTypeExpireStr
}

type Update struct {
	UpdateType UpdateType

	// Tuple key
	Tuple           tuple.Tuple
	NatOutgoingPort int

	// Endpoint information.
	SrcEp      calc.EndpointData
	DstEp      calc.EndpointData
	DstService ServiceInfo

	// isConnection is true if this update is from an active connection.
	IsConnection bool

	// Rules identification
	RuleIDs        []*calc.RuleID
	PendingRuleIDs []*calc.RuleID

	// Whether the rules IDs contains a deny rule.
	HasDenyRule bool

	// Sometimes we may need to send updates without having all the rules
	// in place. This field will help aggregators determine if they need
	// to handle this update or not. Typically this is used when we receive
	// HTTP Data updates after the connection itself has closed.
	UnknownRuleID *calc.RuleID

	// Inbound/Outbound packet/byte counts.
	InMetric  Value
	OutMetric Value
}

func (mu Update) String() string {
	var (
		srcName, dstName string
	)
	if mu.SrcEp != nil {
		srcName = utils.EndpointName(mu.SrcEp.Key())
	} else {
		srcName = utils.UnknownEndpoint
	}
	if mu.DstEp != nil {
		dstName = utils.EndpointName(mu.DstEp.Key())
	} else {
		dstName = utils.UnknownEndpoint
	}

	format := "MetricUpdate: type=%s tuple={%v}, srcEp={%v} dstEp={%v} isConnection={%v}, ruleID={%v}, unknownRuleID={%v} inMetric={%s} outMetric={%s}"

	return fmt.Sprintf(format,
		mu.UpdateType, &(mu.Tuple), srcName, dstName, mu.IsConnection, mu.RuleIDs, mu.UnknownRuleID,
		mu.InMetric, mu.OutMetric,
	)
}

func (mu Update) GetLastRuleID() *calc.RuleID {
	if len(mu.RuleIDs) > 0 {
		return mu.RuleIDs[len(mu.RuleIDs)-1]
	} else if mu.UnknownRuleID != nil {
		return mu.UnknownRuleID
	}
	return nil
}
