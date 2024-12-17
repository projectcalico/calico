// Copyright (c) 2024 Tigera, Inc. All rights reserved.
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

package selector

import (
	"testing"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/selector/parser"
)

var sel Selector

func BenchmarkParse(b *testing.B) {
	logrus.SetLevel(logrus.InfoLevel)
	p := parser.NewParser()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var err error
		sel, err = p.Parse(`! (a == "b"&&! c != "d") || !(a == "b" && !c != "d")`)
		if err != nil {
			b.Errorf("Failed to parse selector: %v", err)
		}
	}
}

func BenchmarkValidate(b *testing.B) {
	logrus.SetLevel(logrus.InfoLevel)
	p := parser.NewParser()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var err error
		err = p.Validate(`! (a == "b"&&! c != "d") || !(a == "b" && !c != "d")`)
		if err != nil {
			b.Errorf("Failed to parse selector: %v", err)
		}
	}
}
