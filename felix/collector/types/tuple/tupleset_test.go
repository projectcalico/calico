// Copyright (c) 2018-2023 Tigera, Inc. All rights reserved.

package tuple

import (
	"fmt"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/collector/utils"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

var (
	localIp1Str = "10.0.0.1"
	localIp1    = utils.IpStrTo16Byte(localIp1Str)
	localIp2Str = "10.0.0.2"
	localIp2    = utils.IpStrTo16Byte(localIp2Str)
	proto_tcp   = 6
)

var _ = Describe("Set", func() {
	var s Set
	t1 := Make(localIp1, localIp2, proto_tcp, 1, 1)
	t2 := Make(localIp1, localIp2, proto_tcp, 2, 2)
	t3 := Make(localIp1, localIp2, proto_tcp, 3, 3)
	BeforeEach(func() {
		s = NewSet()
	})
	It("should be empty", func() {
		Expect(s.Len()).To(BeZero())
	})
	Describe("after adding t1 and t2", func() {
		BeforeEach(func() {
			s.Add(t1)
			s.Add(t2)
			s.Add(t2) // Duplicate should have no effect
		})
		It("should have 2 tuples", func() {
			Expect(s.Len()).Should(Equal(2))
		})
		It("should contain t1", func() {
			Expect(s.Contains(t1)).To(BeTrue())
		})
		It("should contain t2", func() {
			Expect(s.Contains(t2)).To(BeTrue())
		})
		It("should not contain t3", func() {
			Expect(s.Contains(t3)).To(BeFalse())
		})
		Describe("after removing t2", func() {
			BeforeEach(func() {
				s.Discard(t2)
			})
			It("should have 1 tple", func() {
				Expect(s.Len()).Should(Equal(1))
			})
			It("should contain t1", func() {
				Expect(s.Contains(t1)).To(BeTrue())
			})
			It("should not contain t2", func() {
				Expect(s.Contains(t2)).To(BeFalse())
			})
			It("should not contain t3", func() {
				Expect(s.Contains(t3)).To(BeFalse())
			})
		})
	})

	It("should stringify as pointer or non-pointer type", func() {
		t1 := Make(localIp1, localIp2, proto_tcp, 1, 1)
		f1 := fmt.Sprintf("%v", t1)
		Expect(f1).To(Equal("src=10.0.0.1 dst=10.0.0.2 proto=6 sport=1 dport=1"))
		f2 := fmt.Sprintf("%v", &t1)
		Expect(f1).To(Equal(f2))
	})

	It("should support making a copy with updated source port", func() {
		t1 := Make(localIp1, localIp2, proto_tcp, 1, 1)
		t2 = t1.WithSourcePort(2)
		Expect(t1.L4Src).To(Equal(1))
		Expect(t2.L4Src).To(Equal(2))
	})
})

func BenchmarkSetGeneric(b *testing.B) {
	t := Make(localIp1, localIp2, proto_tcp, 1000, 1000)
	s := set.New[Tuple]()
	b.ResetTimer()
	b.ReportAllocs()
	for n := 0; n < b.N; n++ {
		s.Add(t)
	}
}

func BenchmarkSetTuple(b *testing.B) {
	t := Make(localIp1, localIp2, proto_tcp, 1000, 1000)
	s := NewSet()
	b.ResetTimer()
	b.ReportAllocs()
	for n := 0; n < b.N; n++ {
		s.Add(t)
	}
}
