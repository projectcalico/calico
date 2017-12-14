// Copyright (c) 2017 Tigera, Inc. All rights reserved.

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

package converters

import (
	"testing"

	. "github.com/onsi/gomega"
)

var table = []struct {
	v1 string
	v3 string
}{
	{"foo == 'bar'", "foo == 'bar'"},
	{"calico/k8s_ns == 'default'", "projectcalico.org/namespace == 'default'"},
	{"calico/k8s_ns in {'default'}", "projectcalico.org/namespace in {'default'}"},
	{"has(calico/k8s_ns)", "has(projectcalico.org/namespace)"},
	{"has(calico/k8s_ns) || foo == 'bar'", "has(projectcalico.org/namespace) || foo == 'bar'"},
}

func TestCanConvertSelectors(t *testing.T) {
	for _, entry := range table {
		t.Run(entry.v1, func(t *testing.T) {
			RegisterTestingT(t)
			Expect(convertSelector(entry.v1)).To(Equal(entry.v3), entry.v1)
		})
	}
}
