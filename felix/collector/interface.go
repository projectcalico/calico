// Copyright (c) 2018-2023 Tigera, Inc. All rights reserved.

package collector

import (
	"github.com/projectcalico/calico/felix/collector/types"
	"github.com/projectcalico/calico/felix/proto"
)

type Collector interface {
	Start() error
	ReportingChannel() chan<- *proto.DataplaneStats
	RegisterMetricsReporter(types.Reporter)
	SetPacketInfoReader(PacketInfoReader)
	SetConntrackInfoReader(ConntrackInfoReader)
}
