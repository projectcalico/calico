// Copyright (c) 2018 Tigera, Inc. All rights reserved.
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

package policysync_test

import (
	"reflect"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/policysync"
	"github.com/projectcalico/calico/felix/proto"

	"strings"
)

var _ = Describe("AddIPSetsRule", func() {

	It("should add all fields that end in IpSetIds", func() {
		r := proto.Rule{}
		var fields []string
		rt := reflect.TypeOf(r)
		rv := reflect.ValueOf(&r)
		for i := 0; i < rt.NumField(); i++ {
			fn := rt.Field(i).Name
			if strings.HasSuffix(fn, "IpSetIds") {
				fields = append(fields, fn)
				fv := rv.Elem().Field(i)
				fv.Set(reflect.ValueOf([]string{fn}))
			}
		}
		result := make(map[string]bool)
		policysync.AddIPSetsRule(&r, result)
		for _, fn := range fields {
			Expect(result[fn]).To(BeTrue())
		}
	})
})
