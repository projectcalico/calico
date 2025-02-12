// Copyright (c) 2024-2025 Tigera, Inc. All rights reserved.

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
