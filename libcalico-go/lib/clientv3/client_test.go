package clientv3

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = Describe("FilterIPPool", func() {
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

	It("should return false for pools marked for deletion", func() {
		now := metav1.Now()
		pool.DeletionTimestamp = &now
		Expect(filterIPPool(pool, 4)).To(BeFalse())
	})

	It("should return false for disabled pools", func() {
		pool.Spec.Disabled = true
		Expect(filterIPPool(pool, 4)).To(BeFalse())
	})

	It("should return false for pools with invalid CIDR", func() {
		pool.Spec.CIDR = "invalid-cidr"
		Expect(filterIPPool(pool, 4)).To(BeFalse())
		Expect(filterIPPool(pool, 6)).To(BeFalse())
	})

	It("should return false for pools with mismatched IP version", func() {
		// IPv4 CIDR
		pool.Spec.CIDR = "192.168.0.0/16"
		Expect(filterIPPool(pool, 6)).To(BeFalse())

		// IPv6 CIDR
		pool.Spec.CIDR = "2001:db8::/64"
		Expect(filterIPPool(pool, 4)).To(BeFalse())
	})

	It("should return true for valid pools with matching IP version", func() {
		// IPv4 CIDR
		pool.Spec.CIDR = "192.168.0.0/16"
		Expect(filterIPPool(pool, 4)).To(BeTrue())

		// IPv6 CIDR
		pool.Spec.CIDR = "2001:db8::/64"
		Expect(filterIPPool(pool, 6)).To(BeTrue())
	})
})
