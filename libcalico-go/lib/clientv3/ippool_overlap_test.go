// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package clientv3

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func poolWithCondition(name, cidr string, status metav1.ConditionStatus) v3.IPPool {
	p := v3.IPPool{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       v3.IPPoolSpec{CIDR: cidr},
	}
	if status != "" {
		p.Status = &v3.IPPoolStatus{
			Conditions: []metav1.Condition{{
				Type:   v3.IPPoolConditionAllocatable,
				Status: status,
			}},
		}
	}
	return p
}

func unmarkedPool(name, cidr string) v3.IPPool {
	return poolWithCondition(name, cidr, "")
}

func poolNames(pools []v3.IPPool) []string {
	names := []string{}
	for _, p := range pools {
		names = append(names, p.Name)
	}
	return names
}

var _ = Describe("selectAllocatablePools", func() {
	It("excludes an unmarked pool overlapped by an allocatable pool", func() {
		pools := []v3.IPPool{
			poolWithCondition("active", "192.168.0.0/16", metav1.ConditionTrue),
			unmarkedPool("new", "192.168.1.0/24"),
		}
		Expect(poolNames(selectAllocatablePools(pools, 4))).To(ConsistOf("active"))
	})

	It("keeps an unmarked pool that overlaps nothing", func() {
		pools := []v3.IPPool{
			poolWithCondition("active", "192.168.0.0/16", metav1.ConditionTrue),
			unmarkedPool("new", "10.0.0.0/16"),
		}
		Expect(poolNames(selectAllocatablePools(pools, 4))).To(ConsistOf("active", "new"))
	})

	It("keeps every pool when none carry a condition yet", func() {
		pools := []v3.IPPool{
			unmarkedPool("a", "192.168.0.0/16"),
			unmarkedPool("b", "192.168.1.0/24"),
		}
		Expect(poolNames(selectAllocatablePools(pools, 4))).To(ConsistOf("a", "b"))
	})

	It("excludes an unmarked pool overlapped by a terminating pool", func() {
		now := metav1.Now()
		terminating := poolWithCondition("old", "192.168.0.0/16", metav1.ConditionFalse)
		terminating.DeletionTimestamp = &now
		pools := []v3.IPPool{terminating, unmarkedPool("new", "192.168.1.0/24")}
		Expect(selectAllocatablePools(pools, 4)).To(BeEmpty())
	})

	It("keeps an unmarked pool overlapped only by an administratively disabled pool", func() {
		disabled := poolWithCondition("disabled", "192.168.0.0/16", metav1.ConditionFalse)
		disabled.Spec.Disabled = true
		pools := []v3.IPPool{disabled, unmarkedPool("new", "192.168.1.0/24")}
		Expect(poolNames(selectAllocatablePools(pools, 4))).To(ConsistOf("new"))
	})

	It("keeps an allocatable pool even when it overlaps another allocatable pool", func() {
		pools := []v3.IPPool{
			poolWithCondition("outer", "10.0.0.0/8", metav1.ConditionTrue),
			poolWithCondition("inner", "10.1.0.0/16", metav1.ConditionTrue),
		}
		Expect(poolNames(selectAllocatablePools(pools, 4))).To(ConsistOf("outer", "inner"))
	})

	It("finds a covering pool that starts before a nearer non-covering one", func() {
		pools := []v3.IPPool{
			poolWithCondition("outer", "10.0.0.0/8", metav1.ConditionTrue),
			poolWithCondition("inner", "10.1.0.0/16", metav1.ConditionTrue),
			unmarkedPool("new", "10.2.0.0/16"),
		}
		Expect(poolNames(selectAllocatablePools(pools, 4))).To(ConsistOf("outer", "inner"))
	})

	It("does not mask across IP versions", func() {
		pools := []v3.IPPool{
			poolWithCondition("v4", "0.0.0.0/1", metav1.ConditionTrue),
			unmarkedPool("v6", "fd00::/64"),
		}
		Expect(poolNames(selectAllocatablePools(pools, 6))).To(ConsistOf("v6"))
	})

	It("still excludes pools explicitly marked not allocatable", func() {
		pools := []v3.IPPool{poolWithCondition("blocked", "192.168.0.0/16", metav1.ConditionFalse)}
		Expect(selectAllocatablePools(pools, 4)).To(BeEmpty())
	})
})
