// Copyright (c) 2023 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package labelrestrictionindex

import (
	"testing"

	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/libcalico-go/lib/selector"
)

type dummyGauge float64

func (d *dummyGauge) Set(f float64) {
	*d = dummyGauge(f)
}

func TestLabelRestrictionIndex(t *testing.T) {
	RegisterTestingT(t)

	var optGauge, unoptGauge dummyGauge
	idx := New[string](WithGauges[string](&optGauge, &unoptGauge))

	allSel := mustParseSelector("all()")
	idx.AddSelector("all", allSel)
	hasA := mustParseSelector("has(a)")
	idx.AddSelector("hasA", hasA)
	aEqualsA := mustParseSelector("a == 'A'")
	idx.AddSelector("aEqualsA", aEqualsA)
	aIn := mustParseSelector("a in {'A1','A2'}")
	idx.AddSelector("aIn", aIn)
	bIn := mustParseSelector("b in {'B1','B2'}")
	idx.AddSelector("bIn", bIn)
	impossible := mustParseSelector("a == 'A' && a == 'B'")
	idx.AddSelector("impossible", impossible)

	Expect(optGauge).To(BeNumerically("==", 5))
	Expect(unoptGauge).To(BeNumerically("==", 1))

	// TODO Deletion and iteration.
}

func mustParseSelector(s string) selector.Selector {
	sel, err := selector.Parse(s)
	Expect(err).NotTo(HaveOccurred())
	return sel
}
