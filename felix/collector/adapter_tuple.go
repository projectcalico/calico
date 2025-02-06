// Copyright (c) 2024 Tigera, Inc. All rights reserved.
package collector

import (
	"net"

	"github.com/projectcalico/calico/felix/collector/types/tuple"
)

// TupleAsFlow adapts Tuple to the l4 and l7 flow interfaces for use in the matchers.
type TupleAsFlow tuple.Tuple

func (a *TupleAsFlow) GetSourceIP() net.IP {
	return (*tuple.Tuple)(a).SourceNet()
}

func (a *TupleAsFlow) GetDestIP() net.IP {
	return (*tuple.Tuple)(a).DestNet()
}

func (a *TupleAsFlow) GetSourcePort() int {
	return (*tuple.Tuple)(a).GetSourcePort()
}

func (a *TupleAsFlow) GetDestPort() int {
	return (*tuple.Tuple)(a).GetDestPort()
}

func (a *TupleAsFlow) GetProtocol() int {
	return (*tuple.Tuple)(a).Proto
}

func (a *TupleAsFlow) GetHttpMethod() *string {
	return nil
}

func (a *TupleAsFlow) GetHttpPath() *string {
	return nil
}

func (a *TupleAsFlow) GetSourcePrincipal() *string {
	return nil
}

func (a *TupleAsFlow) GetDestPrincipal() *string {
	return nil
}

func (a *TupleAsFlow) GetSourceLabels() map[string]string {
	return nil
}

func (a *TupleAsFlow) GetDestLabels() map[string]string {
	return nil
}
