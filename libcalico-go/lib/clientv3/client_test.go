package clientv3

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = Describe("selectAllocatablePools pool filtering", func() {
	var pool *v3.IPPool

	BeforeEach(func() {
		pool = &v3.IPPool{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-pool",
			},
			Spec: v3.IPPoolSpec{
				CIDR:     "192.168.0.0/16",
				Disabled: false,
			},
		}
	})

	It("should exclude pools marked for deletion", func() {
		now := metav1.Now()
		pool.DeletionTimestamp = &now
		Expect(selectAllocatablePools([]v3.IPPool{*pool}, 4)).To(BeEmpty())
	})

	It("should exclude disabled pools", func() {
		pool.Spec.Disabled = true
		Expect(selectAllocatablePools([]v3.IPPool{*pool}, 4)).To(BeEmpty())
	})

	It("should exclude pools with invalid CIDR", func() {
		pool.Spec.CIDR = "invalid-cidr"
		Expect(selectAllocatablePools([]v3.IPPool{*pool}, 4)).To(BeEmpty())
		Expect(selectAllocatablePools([]v3.IPPool{*pool}, 6)).To(BeEmpty())
	})

	It("should exclude pools with mismatched IP version", func() {
		// IPv4 CIDR
		pool.Spec.CIDR = "192.168.0.0/16"
		Expect(selectAllocatablePools([]v3.IPPool{*pool}, 6)).To(BeEmpty())

		// IPv6 CIDR
		pool.Spec.CIDR = "2001:db8::/64"
		Expect(selectAllocatablePools([]v3.IPPool{*pool}, 4)).To(BeEmpty())
	})

	It("should include valid pools with matching IP version", func() {
		// IPv4 CIDR
		pool.Spec.CIDR = "192.168.0.0/16"
		Expect(selectAllocatablePools([]v3.IPPool{*pool}, 4)).To(HaveLen(1))

		// IPv6 CIDR
		pool.Spec.CIDR = "2001:db8::/64"
		Expect(selectAllocatablePools([]v3.IPPool{*pool}, 6)).To(HaveLen(1))
	})
})
