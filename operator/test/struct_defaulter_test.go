// Copyright (c) 2022-2026 Tigera, Inc. All rights reserved.

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

package test

import (
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

type testInterface interface {
	TestFunc()
}

type testInterfaceImpl struct {
	PrimitivesStruct
}

func (t *testInterfaceImpl) TestFunc() {}

type PrimitivesStruct struct {
	Int        int
	IntPtr     *int
	Int32      int32
	Int32Ptr   *int32
	Int64      int64
	Int64Ptr   *int64
	Uint       uint
	UintPtr    *uint
	Uint32     uint32
	Uint32Ptr  *uint32
	Uint64     uint64
	Uint64Ptr  *uint64
	Float32    float32
	Float32Ptr *float32
	Float64    float64
	Float64Ptr *float64
	String     string
	StringPtr  *string
	Bool       bool
	BoolPtr    *bool
}

var _ = Describe("StructDefaulter", func() {
	It("returns an error if it doesn't have an implementation for an interface", func() {
		defaulter := NewNonZeroStructDefaulter()
		strct := struct {
			Interface testInterface
		}{}
		Expect(defaulter.SetDefault(&strct)).Should(Equal(fmt.Errorf("no implementation for interface 'testInterface'")))
	})

	It("defaults all primitive types", func() {
		defaulter := NewNonZeroStructDefaulter()
		primitives := PrimitivesStruct{}
		Expect(defaulter.SetDefault(&primitives)).ShouldNot(HaveOccurred())
		Expect(primitives).Should(Equal(getPrimitivesStruct()))
	})

	It("defaults structs all primitive types", func() {
		defaulter := NewNonZeroStructDefaulter()
		strct := struct {
			Primitives PrimitivesStruct
		}{}
		Expect(defaulter.SetDefault(&strct)).ShouldNot(HaveOccurred())
		Expect(strct).Should(Equal(struct {
			Primitives PrimitivesStruct
		}{
			Primitives: getPrimitivesStruct(),
		}))
	})

	It("defaults struct pointers all primitive types", func() {
		defaulter := NewNonZeroStructDefaulter()
		strct := struct {
			Primitives *PrimitivesStruct
		}{}

		primitives := getPrimitivesStruct()
		Expect(defaulter.SetDefault(&strct)).ShouldNot(HaveOccurred())
		Expect(strct).Should(Equal(struct {
			Primitives *PrimitivesStruct
		}{
			Primitives: &primitives,
		}))
	})

	It("uses the given implementation for an interface with default values", func() {
		defaulter := NewNonZeroStructDefaulter(WithInterfaceImplementations(map[string]interface{}{
			"testInterface": testInterfaceImpl{},
		}))
		strct := struct {
			Interface testInterface
		}{}
		Expect(defaulter.SetDefault(&strct)).ShouldNot(HaveOccurred())
		Expect(strct.Interface).Should(Equal(&testInterfaceImpl{
			PrimitivesStruct: getPrimitivesStruct(),
		}))
	})

	It("defaults array types", func() {
		strct := struct {
			Array []string
		}{}
		defaulter := NewNonZeroStructDefaulter()
		Expect(defaulter.SetDefault(&strct)).ShouldNot(HaveOccurred())
		Expect(strct.Array).Should(Equal([]string{DefaultNonZeroString}))
	})

	It("defaults map types", func() {
		strct := struct {
			Map map[string]string
		}{}
		defaulter := NewNonZeroStructDefaulter()
		Expect(defaulter.SetDefault(&strct)).ShouldNot(HaveOccurred())
		Expect(strct.Map).Should(Equal(map[string]string{
			DefaultNonZeroString: DefaultNonZeroString,
		}))
	})

	It("defaults chan types", func() {
		strct := struct {
			Chan chan string
		}{}
		defaulter := NewNonZeroStructDefaulter()
		Expect(defaulter.SetDefault(&strct)).ShouldNot(HaveOccurred())
		Expect(strct.Chan).ShouldNot(BeNil())
	})
})

func getPrimitivesStruct() PrimitivesStruct {
	defaultInt := int(DefaultNonZeroInt64)
	defaultInt32 := int32(DefaultNonZeroInt64)
	defaultInt64 := DefaultNonZeroInt64
	defaultUint := uint(DefaultNonZeroUint64)
	defaultUint32 := uint32(DefaultNonZeroUint64)
	defaultUint64 := DefaultNonZeroUint64
	defaultFloat32 := float32(DefaultNonZeroFloat64)
	defaultFloat64 := DefaultNonZeroFloat64
	defaultString := DefaultNonZeroString
	defaultBool := DefaultNonZeroBool

	return PrimitivesStruct{
		Int:        defaultInt,
		IntPtr:     &defaultInt,
		Int32:      defaultInt32,
		Int32Ptr:   &defaultInt32,
		Int64:      defaultInt64,
		Int64Ptr:   &defaultInt64,
		Uint:       defaultUint,
		UintPtr:    &defaultUint,
		Uint32:     defaultUint32,
		Uint32Ptr:  &defaultUint32,
		Uint64:     defaultUint64,
		Uint64Ptr:  &defaultUint64,
		Float32:    defaultFloat32,
		Float32Ptr: &defaultFloat32,
		Float64:    defaultFloat64,
		Float64Ptr: &defaultFloat64,
		String:     defaultString,
		StringPtr:  &defaultString,
		Bool:       defaultBool,
		BoolPtr:    &defaultBool,
	}
}
