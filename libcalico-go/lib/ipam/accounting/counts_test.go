// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

package accounting

import (
	"math/big"
	"reflect"
	"testing"

	. "github.com/onsi/gomega"
)

// A field that clone does not deep-copy fails here, so a new Counts field cannot share state with the cache.
func TestCountsCloneSharesNothing(t *testing.T) {
	RegisterTestingT(t)
	orig := &Counts{}
	ov := reflect.ValueOf(orig).Elem()
	for i := range ov.NumField() {
		f := ov.Field(i)
		switch {
		case f.Type() == reflect.TypeOf(&big.Int{}):
			f.Set(reflect.ValueOf(big.NewInt(int64(i + 1))))
		case f.Kind() == reflect.Map:
			m := reflect.MakeMap(f.Type())
			m.SetMapIndex(reflect.New(f.Type().Key()).Elem(), reflect.ValueOf(i+1).Convert(f.Type().Elem()))
			f.Set(m)
		case f.Kind() == reflect.Int:
			f.SetInt(int64(i + 1))
		default:
			t.Fatalf("Counts.%s has a type this test cannot fill; teach it, and clone, about %s", ov.Type().Field(i).Name, f.Type())
		}
	}

	c := orig.clone()
	Expect(c).To(Equal(orig))
	cv := reflect.ValueOf(c).Elem()
	for i := range ov.NumField() {
		if k := ov.Field(i).Kind(); k == reflect.Pointer || k == reflect.Map {
			Expect(cv.Field(i).UnsafePointer()).NotTo(Equal(ov.Field(i).UnsafePointer()), ov.Type().Field(i).Name)
		}
	}
}
