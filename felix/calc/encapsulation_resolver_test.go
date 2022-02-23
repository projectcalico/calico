// Copyright (c) 2022 Tigera, Inc. All rights reserved.

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

package calc_test

import (
	"reflect"
	"unsafe"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	. "github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/config"
	"github.com/projectcalico/calico/felix/dispatcher"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/encap"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/net"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = Describe("EncapsulationCalculator", func() {
	var encapsulationCalculator *EncapsulationCalculator
	var conf *config.Config
	BeforeEach(func() {
		conf = config.New()
		encapsulationCalculator = NewEncapsulationCalculator(conf, nil)
	})
	Context("FelixConfig not set", func() {
		DescribeTable("pool tests",
			func(apiPoolsToAdd []*apiv3.IPPool, apiPoolsToRemove []string, modelPoolsToAdd []*model.IPPool, modelPoolsToRemove []string, poolsToInit *model.KVPairList, expectedIPIP, expectedVXLAN bool) {
				if poolsToInit != nil {
					encapsulationCalculator.SetAPIPools(poolsToInit)
				}
				for _, p := range apiPoolsToAdd {
					encapsulationCalculator.UpdateAPIPool(p)
				}
				for _, p := range modelPoolsToAdd {
					encapsulationCalculator.UpdateModelPool(p)
				}
				for _, p := range apiPoolsToRemove {
					encapsulationCalculator.RemovePool(p)
				}
				for _, p := range modelPoolsToRemove {
					_, cidr, err := net.ParseCIDR(p)
					Expect(err).To(Not(HaveOccurred()))
					encapsulationCalculator.RemoveModelPool(model.IPPoolKey{CIDR: *cidr})
				}
				Expect(encapsulationCalculator.IPIPEnabled()).To(Equal(expectedIPIP))
				Expect(encapsulationCalculator.VXLANEnabled()).To(Equal(expectedVXLAN))
			},
			Entry("uninitialized",
				nil, nil, nil, nil, nil,
				false, false),
			Entry("API pool with no encap",
				[]*apiv3.IPPool{getAPIPool("192.168.1.0/24", apiv3.IPIPModeNever, apiv3.VXLANModeNever)},
				nil, nil, nil, nil,
				false, false),
			Entry("API pool with IPIP 'Always'",
				[]*apiv3.IPPool{getAPIPool("192.168.1.0/24", apiv3.IPIPModeAlways, apiv3.VXLANModeNever)},
				nil, nil, nil, nil,
				true, false),
			Entry("API pool with VXLAN 'Always'",
				[]*apiv3.IPPool{getAPIPool("192.168.1.0/24", apiv3.IPIPModeNever, apiv3.VXLANModeAlways)},
				nil, nil, nil, nil,
				false, true),
			Entry("API pool with IPIP 'CrossSubnet' and VXLAN 'CrossSubnet'",
				[]*apiv3.IPPool{getAPIPool("192.168.1.0/24", apiv3.IPIPModeCrossSubnet, apiv3.VXLANModeCrossSubnet)},
				nil, nil, nil, nil,
				true, true),
			Entry("2 API pools with mixed encaps",
				[]*apiv3.IPPool{getAPIPool("192.168.1.0/24", apiv3.IPIPModeNever, apiv3.VXLANModeAlways), getAPIPool("192.168.2.0/24", apiv3.IPIPModeCrossSubnet, apiv3.VXLANModeNever)},
				nil, nil, nil, nil,
				true, true),
			Entry("2 API pools with mixed encaps, then remove one pool",
				[]*apiv3.IPPool{getAPIPool("192.168.1.0/24", apiv3.IPIPModeNever, apiv3.VXLANModeAlways), getAPIPool("192.168.2.0/24", apiv3.IPIPModeCrossSubnet, apiv3.VXLANModeNever)},
				[]string{"192.168.2.0/24"},
				nil, nil, nil,
				false, true),
			Entry("Initialize with SetAPIPools with no encap",
				nil, nil, nil, nil,
				&model.KVPairList{
					KVPairs: []*model.KVPair{
						{
							Value: getAPIPool("192.168.1.0/24", apiv3.IPIPModeNever, apiv3.VXLANModeNever),
						},
						{
							Value: getAPIPool("192.168.2.0/24", apiv3.IPIPModeNever, apiv3.VXLANModeNever),
						},
					},
				},
				false, false),
			Entry("Initialize with SetAPIPools with mixed encaps",
				nil, nil, nil, nil,
				&model.KVPairList{
					KVPairs: []*model.KVPair{
						{
							Value: getAPIPool("192.168.1.0/24", apiv3.IPIPModeNever, apiv3.VXLANModeAlways),
						},
						{
							Value: getAPIPool("192.168.2.0/24", apiv3.IPIPModeCrossSubnet, apiv3.VXLANModeNever),
						},
					},
				},
				true, true),
			Entry("Initialize with SetAPIPools, update one API pool and remove another",
				[]*apiv3.IPPool{getAPIPool("192.168.1.0/24", apiv3.IPIPModeAlways, apiv3.VXLANModeNever)},
				[]string{"192.168.2.0/24"},
				nil, nil,
				&model.KVPairList{
					KVPairs: []*model.KVPair{
						{
							Value: getAPIPool("192.168.1.0/24", apiv3.IPIPModeNever, apiv3.VXLANModeAlways),
						},
						{
							Value: getAPIPool("192.168.2.0/24", apiv3.IPIPModeCrossSubnet, apiv3.VXLANModeAlways),
						},
					},
				},
				true, false),
			Entry("Model pool with no encap",
				nil, nil,
				[]*model.IPPool{getModelPool("192.168.1.0/24", encap.Undefined, encap.Undefined)},
				nil, nil,
				false, false),
			Entry("Model pool with IPIP 'Always'",
				nil, nil,
				[]*model.IPPool{getModelPool("192.168.1.0/24", encap.Always, encap.Undefined)},
				nil, nil,
				true, false),
			Entry("Model pool with VXLAN 'Always'",
				nil, nil,
				[]*model.IPPool{getModelPool("192.168.1.0/24", encap.Undefined, encap.Always)},
				nil, nil,
				false, true),
			Entry("Model pool with IPIP 'CrossSubnet' and VXLAN 'CrossSubnet'",
				nil, nil,
				[]*model.IPPool{getModelPool("192.168.1.0/24", encap.CrossSubnet, encap.CrossSubnet)},
				nil, nil,
				true, true),
			Entry("2 Model pools with mixed encaps",
				nil, nil,
				[]*model.IPPool{getModelPool("192.168.1.0/24", encap.Undefined, encap.Always), getModelPool("192.168.2.0/24", encap.CrossSubnet, encap.Undefined)},
				nil, nil,
				true, true),
			Entry("2 Model pools with mixed encaps, then remove one pool",
				nil, nil,
				[]*model.IPPool{getModelPool("192.168.1.0/24", encap.Undefined, encap.Always), getModelPool("192.168.2.0/24", encap.CrossSubnet, encap.Undefined)},
				[]string{"192.168.2.0/24"},
				nil,
				false, true),
			Entry("Initialize with SetAPIPools, update one Model pool and remove another",
				nil, nil,
				[]*model.IPPool{getModelPool("192.168.1.0/24", encap.Always, encap.Undefined)},
				[]string{"192.168.2.0/24"},
				&model.KVPairList{
					KVPairs: []*model.KVPair{
						{
							Value: getAPIPool("192.168.1.0/24", apiv3.IPIPModeNever, apiv3.VXLANModeAlways),
						},
						{
							Value: getAPIPool("192.168.2.0/24", apiv3.IPIPModeCrossSubnet, apiv3.VXLANModeAlways),
						},
					},
				},
				true, false),
		)
	})
	Context("FelixConfig set", func() {
		t := true
		f := false
		DescribeTable("FelixConfig tests",
			func(felixIPIP, felixVXLAN *bool, apiPoolsToAdd []*apiv3.IPPool, modelPoolsToAdd []*model.IPPool, expectedIPIP, expectedVXLAN bool) {
				conf.DeprecatedIpInIpEnabled = felixIPIP
				conf.DeprecatedVXLANEnabled = felixVXLAN
				for _, p := range apiPoolsToAdd {
					encapsulationCalculator.UpdateAPIPool(p)
				}
				for _, p := range modelPoolsToAdd {
					encapsulationCalculator.UpdateModelPool(p)
				}
				Expect(encapsulationCalculator.IPIPEnabled()).To(Equal(expectedIPIP))
				Expect(encapsulationCalculator.VXLANEnabled()).To(Equal(expectedVXLAN))
			},
			Entry("IPIP true in FelixConfig and no pools",
				&t, nil, nil, nil,
				true, false),
			Entry("VXLAN true in FelixConfig and no pools",
				nil, &t, nil, nil,
				false, true),
			Entry("Both IPIP and VXLAN true in FelixConfig and no pools",
				&t, &t, nil, nil,
				true, true),
			Entry("Both IPIP and VXLAN false in FelixConfig with mixed pools",
				&f, &f,
				[]*apiv3.IPPool{getAPIPool("192.168.1.0/24", apiv3.IPIPModeNever, apiv3.VXLANModeAlways), getAPIPool("192.168.2.0/24", apiv3.IPIPModeCrossSubnet, apiv3.VXLANModeNever)},
				[]*model.IPPool{getModelPool("192.168.3.0/24", encap.Undefined, encap.Always), getModelPool("192.168.4.0/24", encap.CrossSubnet, encap.Undefined)},
				false, false),
		)
	})
})

var _ = Describe("EncapsulationResolver", func() {
	var encapsulationResolver *EncapsulationResolver
	var conf *config.Config
	var restartTriggered bool
	configChangedRestartCallback := func() {
		restartTriggered = true
	}

	BeforeEach(func() {
		conf = config.New()
		restartTriggered = false
		encapsulationResolver = NewEncapsulationResolver(conf, configChangedRestartCallback)
	})

	Describe("OnStatusUpdate", func() {
		It("should not touch inSync to true when receiving other status updates", func() {
			encapsulationResolver.OnStatusUpdate(api.WaitForDatastore)
			inSync, ok := getUnexportedField(reflect.ValueOf(encapsulationResolver).Elem().FieldByName("inSync")).(bool)
			Expect(ok).To(BeTrue())
			Expect(inSync).To(BeFalse())

			encapsulationResolver.OnStatusUpdate(api.ResyncInProgress)
			inSync, ok = getUnexportedField(reflect.ValueOf(encapsulationResolver).Elem().FieldByName("inSync")).(bool)
			Expect(ok).To(BeTrue())
			Expect(inSync).To(BeFalse())
		})

		It("should update inSync to true when receiving InSync status update", func() {
			encapsulationResolver.OnStatusUpdate(api.InSync)
			inSync, ok := getUnexportedField(reflect.ValueOf(encapsulationResolver).Elem().FieldByName("inSync")).(bool)
			Expect(ok).To(BeTrue())
			Expect(inSync).To(BeTrue())
		})
	})

	Describe("RegisterWith", func() {
		var disp *dispatcher.Dispatcher

		BeforeEach(func() {
			disp = dispatcher.NewDispatcher()
			encapsulationResolver.RegisterWith(disp)
			encapsulationResolver.OnStatusUpdate(api.InSync)
		})
		It("should Register for IPPool updates only", func() {
			disp.OnUpdate(api.Update{
				KVPair:     model.KVPair{Key: model.HostEndpointKey{}},
				UpdateType: api.UpdateTypeKVNew,
			})
			Expect(restartTriggered).To(BeFalse())
		})
	})

	Describe("Not inSync", func() {
		It("should not trigger restart when adding pools with IPIP encap", func() {
			_, cidr, err := net.ParseCIDR("192.168.1.0/24")
			Expect(err).To(Not(HaveOccurred()))
			encapsulationResolver.OnPoolUpdate(addPoolUpdate(*cidr, encap.Always, encap.Undefined))
			Expect(restartTriggered).To(BeFalse())
		})

		It("should not trigger restart when adding pools with VXLAN encap", func() {
			_, cidr, err := net.ParseCIDR("192.168.1.0/24")
			Expect(err).To(Not(HaveOccurred()))
			encapsulationResolver.OnPoolUpdate(addPoolUpdate(*cidr, encap.Undefined, encap.CrossSubnet))
			Expect(restartTriggered).To(BeFalse())
		})
		It("should not trigger restart when adding and removing pools", func() {
			_, cidr, err := net.ParseCIDR("192.168.1.0/24")
			Expect(err).To(Not(HaveOccurred()))
			encapsulationResolver.OnPoolUpdate(addPoolUpdate(*cidr, encap.Always, encap.CrossSubnet))
			Expect(restartTriggered).To(BeFalse())
			encapsulationResolver.OnPoolUpdate(removePoolUpdate(*cidr))
			Expect(restartTriggered).To(BeFalse())
		})
		It("should not trigger restart when changing encap in FelixConfig", func() {
			t := true
			conf.DeprecatedIpInIpEnabled = &t
			conf.DeprecatedVXLANEnabled = &t
			Expect(restartTriggered).To(BeFalse())
		})
	})

	Describe("Already inSync", func() {
		It("should trigger restart when adding pools with IPIP encap", func() {
			encapsulationResolver.OnStatusUpdate(api.InSync)

			_, cidr, err := net.ParseCIDR("192.168.1.0/24")
			Expect(err).To(Not(HaveOccurred()))
			encapsulationResolver.OnPoolUpdate(addPoolUpdate(*cidr, encap.Always, encap.Undefined))
			Expect(restartTriggered).To(BeTrue())
		})
		It("should trigger restart when adding pools with VXLAN encap", func() {
			encapsulationResolver.OnStatusUpdate(api.InSync)

			_, cidr, err := net.ParseCIDR("192.168.1.0/24")
			Expect(err).To(Not(HaveOccurred()))
			encapsulationResolver.OnPoolUpdate(addPoolUpdate(*cidr, encap.Undefined, encap.CrossSubnet))
			Expect(restartTriggered).To(BeTrue())
		})
		It("should trigger restart when removing pools", func() {
			_, cidr1, err := net.ParseCIDR("192.168.1.0/24")
			Expect(err).To(Not(HaveOccurred()))
			encapsulationResolver.OnPoolUpdate(addPoolUpdate(*cidr1, encap.Always, encap.CrossSubnet))

			_, cidr2, err := net.ParseCIDR("192.168.2.0/24")
			Expect(err).To(Not(HaveOccurred()))
			encapsulationResolver.OnPoolUpdate(addPoolUpdate(*cidr2, encap.Undefined, encap.Always))
			Expect(restartTriggered).To(BeFalse())

			encapsulationResolver.OnStatusUpdate(api.InSync)
			Expect(restartTriggered).To(BeTrue())

			restartTriggered = false // reset restartTriggered
			encapsulationResolver.OnPoolUpdate(removePoolUpdate(*cidr1))
			Expect(restartTriggered).To(BeTrue())
		})
		It("should not trigger restart when changing encap in FelixConfig (Felix will restart through another code path)", func() {
			encapsulationResolver.OnStatusUpdate(api.InSync)

			t := true
			conf.DeprecatedIpInIpEnabled = &t
			conf.DeprecatedVXLANEnabled = &t
			Expect(restartTriggered).To(BeFalse())
		})
	})

	Describe("Changing inSync", func() {
		It("should not trigger restart when adding pools before inSync, but should right after", func() {
			_, cidr, err := net.ParseCIDR("192.168.1.0/24")
			Expect(err).To(Not(HaveOccurred()))
			encapsulationResolver.OnPoolUpdate(addPoolUpdate(*cidr, encap.Always, encap.Undefined))
			Expect(restartTriggered).To(BeFalse())

			encapsulationResolver.OnStatusUpdate(api.InSync)
			Expect(restartTriggered).To(BeTrue())
		})
		It("should not trigger restart when changing FelixConfig before inSync, but should right after", func() {
			t := true
			f := false
			conf.DeprecatedIpInIpEnabled = &f
			conf.DeprecatedVXLANEnabled = &t

			encapsulationResolver.OnStatusUpdate(api.InSync)
			Expect(restartTriggered).To(BeTrue())
		})
	})
})

func addPoolUpdate(cidr net.IPNet, ipipMode, vxlanMode encap.Mode) api.Update {
	return api.Update{
		KVPair: model.KVPair{
			Key: model.IPPoolKey{
				CIDR: cidr,
			},
			Value: &model.IPPool{
				CIDR:      cidr,
				IPIPMode:  ipipMode,
				VXLANMode: vxlanMode,
			},
		},
		UpdateType: api.UpdateTypeKVNew,
	}
}

func removePoolUpdate(cidr net.IPNet) api.Update {
	return api.Update{
		KVPair: model.KVPair{
			Key: model.IPPoolKey{
				CIDR: cidr,
			},
			Value: nil,
		},
		UpdateType: api.UpdateTypeKVDeleted,
	}
}

func getAPIPool(cidr string, ipipMode apiv3.IPIPMode, vxlanMode apiv3.VXLANMode) *apiv3.IPPool {
	return &apiv3.IPPool{
		Spec: apiv3.IPPoolSpec{
			CIDR:      cidr,
			IPIPMode:  ipipMode,
			VXLANMode: vxlanMode,
		},
	}
}

func getModelPool(cidr string, ipipMode, vxlanMode encap.Mode) *model.IPPool {
	_, parsedCidr, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil
	}
	return &model.IPPool{
		CIDR:      *parsedCidr,
		IPIPMode:  ipipMode,
		VXLANMode: vxlanMode,
	}
}

// getUnexportedField uses reflect+unsafe to access unexported fields in a struct
func getUnexportedField(field reflect.Value) interface{} {
	return reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem().Interface()
}
