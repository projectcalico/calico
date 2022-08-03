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

package calc

import (
	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/config"
	"github.com/projectcalico/calico/felix/dispatcher"
	"github.com/projectcalico/calico/felix/proto"

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
			func(apiPoolsToAdd []model.KVPair, apiPoolsToRemove []string, modelPoolsToAdd []model.KVPair, modelPoolsToRemove []string, poolsToInit *model.KVPairList, expectedIPIP, expectedVXLAN, expectedVXLANV6 bool) {
				if poolsToInit != nil {
					encapsulationCalculator.initPools(poolsToInit)
				}
				for _, p := range apiPoolsToAdd {
					err := encapsulationCalculator.handlePool(p)
					Expect(err).To(Not(HaveOccurred()))
				}
				for _, p := range modelPoolsToAdd {
					err := encapsulationCalculator.handlePool(p)
					Expect(err).To(Not(HaveOccurred()))
				}
				for _, p := range apiPoolsToRemove {
					encapsulationCalculator.removePool(p)
				}
				for _, p := range modelPoolsToRemove {
					_, cidr, err := net.ParseCIDR(p)
					Expect(err).To(Not(HaveOccurred()))
					p := model.KVPair{
						Key: model.IPPoolKey{
							CIDR: *cidr,
						},
						Value: nil,
					}
					err = encapsulationCalculator.handlePool(p)
					Expect(err).To(Not(HaveOccurred()))
				}
				Expect(encapsulationCalculator.IPIPEnabled()).To(Equal(expectedIPIP))
				Expect(encapsulationCalculator.VXLANEnabled()).To(Equal(expectedVXLAN))
				Expect(encapsulationCalculator.VXLANEnabledV6()).To(Equal(expectedVXLANV6))
			},
			Entry("uninitialized",
				nil, nil, nil, nil, nil,
				false, false, false),
			Entry("API pool with no encap",
				[]model.KVPair{*getAPIPool("192.168.1.0/24", apiv3.IPIPModeNever, apiv3.VXLANModeNever)},
				nil, nil, nil, nil,
				false, false, false),
			Entry("API pool with IPIP 'Always'",
				[]model.KVPair{*getAPIPool("192.168.1.0/24", apiv3.IPIPModeAlways, apiv3.VXLANModeNever)},
				nil, nil, nil, nil,
				true, false, false),
			Entry("API pool with VXLAN 'Always'",
				[]model.KVPair{*getAPIPool("192.168.1.0/24", apiv3.IPIPModeNever, apiv3.VXLANModeAlways)},
				nil, nil, nil, nil,
				false, true, false),
			Entry("API pool with IPIP 'CrossSubnet' and VXLAN 'CrossSubnet'",
				[]model.KVPair{*getAPIPool("192.168.1.0/24", apiv3.IPIPModeCrossSubnet, apiv3.VXLANModeCrossSubnet)},
				nil, nil, nil, nil,
				true, true, false),
			Entry("2 API pools with mixed encaps",
				[]model.KVPair{*getAPIPool("192.168.1.0/24", apiv3.IPIPModeNever, apiv3.VXLANModeAlways), *getAPIPool("192.168.2.0/24", apiv3.IPIPModeCrossSubnet, apiv3.VXLANModeNever)},
				nil, nil, nil, nil,
				true, true, false),
			Entry("2 API pools with mixed encaps, then remove one pool",
				[]model.KVPair{*getAPIPool("192.168.1.0/24", apiv3.IPIPModeNever, apiv3.VXLANModeAlways), *getAPIPool("192.168.2.0/24", apiv3.IPIPModeCrossSubnet, apiv3.VXLANModeNever)},
				[]string{"192.168.2.0/24"},
				nil, nil, nil,
				false, true, false),
			Entry("Initialize with initPools with no encap",
				nil, nil, nil, nil,
				&model.KVPairList{
					KVPairs: []*model.KVPair{
						getAPIPool("192.168.1.0/24", apiv3.IPIPModeNever, apiv3.VXLANModeNever),
						getAPIPool("192.168.2.0/24", apiv3.IPIPModeNever, apiv3.VXLANModeNever),
					},
				},
				false, false, false),
			Entry("Initialize with initPools with mixed encaps",
				nil, nil, nil, nil,
				&model.KVPairList{
					KVPairs: []*model.KVPair{
						getAPIPool("192.168.1.0/24", apiv3.IPIPModeNever, apiv3.VXLANModeAlways),
						getAPIPool("192.168.2.0/24", apiv3.IPIPModeCrossSubnet, apiv3.VXLANModeNever),
					},
				},
				true, true, false),
			Entry("Initialize with initPools, update one API pool and remove another",
				[]model.KVPair{*getAPIPool("192.168.1.0/24", apiv3.IPIPModeAlways, apiv3.VXLANModeNever)},
				[]string{"192.168.2.0/24"},
				nil, nil,
				&model.KVPairList{
					KVPairs: []*model.KVPair{
						getAPIPool("192.168.1.0/24", apiv3.IPIPModeNever, apiv3.VXLANModeAlways),
						getAPIPool("192.168.2.0/24", apiv3.IPIPModeCrossSubnet, apiv3.VXLANModeAlways),
					},
				},
				true, false, false),
			Entry("Model pool with no encap",
				nil, nil,
				[]model.KVPair{*getModelPool("192.168.1.0/24", encap.Undefined, encap.Undefined)},
				nil, nil,
				false, false, false),
			Entry("Model pool with IPIP 'Always'",
				nil, nil,
				[]model.KVPair{*getModelPool("192.168.1.0/24", encap.Always, encap.Undefined)},
				nil, nil,
				true, false, false),
			Entry("Model pool with VXLAN 'Always'",
				nil, nil,
				[]model.KVPair{*getModelPool("192.168.1.0/24", encap.Undefined, encap.Always)},
				nil, nil,
				false, true, false),
			Entry("Model pool with IPIP 'CrossSubnet' and VXLAN 'CrossSubnet'",
				nil, nil,
				[]model.KVPair{*getModelPool("192.168.1.0/24", encap.CrossSubnet, encap.CrossSubnet)},
				nil, nil,
				true, true, false),
			Entry("2 Model pools with mixed encaps",
				nil, nil,
				[]model.KVPair{*getModelPool("192.168.1.0/24", encap.Undefined, encap.Always), *getModelPool("192.168.2.0/24", encap.CrossSubnet, encap.Undefined)},
				nil, nil,
				true, true, false),
			Entry("2 Model pools with mixed encaps, then remove one pool",
				nil, nil,
				[]model.KVPair{*getModelPool("192.168.1.0/24", encap.Undefined, encap.Always), *getModelPool("192.168.2.0/24", encap.CrossSubnet, encap.Undefined)},
				[]string{"192.168.2.0/24"},
				nil,
				false, true, false),
			Entry("Initialize with initPools, update one Model pool and remove another",
				nil, nil,
				[]model.KVPair{*getModelPool("192.168.1.0/24", encap.Always, encap.Undefined)},
				[]string{"192.168.2.0/24"},
				&model.KVPairList{
					KVPairs: []*model.KVPair{
						getAPIPool("192.168.1.0/24", apiv3.IPIPModeNever, apiv3.VXLANModeAlways),
						getAPIPool("192.168.2.0/24", apiv3.IPIPModeCrossSubnet, apiv3.VXLANModeAlways),
					},
				},
				true, false, false),
			Entry("V6 API pool with VXLAN 'Always'",
				[]model.KVPair{*getAPIPool("fe80::0/122", apiv3.IPIPModeNever, apiv3.VXLANModeAlways)},
				nil, nil, nil, nil,
				false, false, true),
			Entry("V6 API pool with VXLAN 'CrossSubnet'",
				[]model.KVPair{*getAPIPool("fe80::0/122", apiv3.IPIPModeNever, apiv3.VXLANModeCrossSubnet)},
				nil, nil, nil, nil,
				false, false, true),
			Entry("Initialize with initPools with empty string for encaps",
				nil, nil, nil, nil,
				&model.KVPairList{
					KVPairs: []*model.KVPair{
						getAPIPool("192.168.1.0/24", "", ""),
						getAPIPool("192.168.2.0/24", "", ""),
					},
				},
				false, false, false),
			Entry("API pool with empty string for encaps",
				[]model.KVPair{*getAPIPool("192.168.1.0/24", "", "")},
				nil, nil, nil, nil,
				false, false, false),
		)
	})
	Context("FelixConfig set", func() {
		t := true
		f := false
		DescribeTable("FelixConfig tests",
			func(felixIPIP, felixVXLAN *bool, apiPoolsToAdd, modelPoolsToAdd []model.KVPair, expectedIPIP, expectedVXLAN bool) {
				conf.IpInIpEnabled = felixIPIP
				conf.VXLANEnabled = felixVXLAN
				for _, p := range apiPoolsToAdd {
					err := encapsulationCalculator.handlePool(p)
					Expect(err).To(Not(HaveOccurred()))
				}
				for _, p := range modelPoolsToAdd {
					err := encapsulationCalculator.handlePool(p)
					Expect(err).To(Not(HaveOccurred()))
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
				[]model.KVPair{*getAPIPool("192.168.1.0/24", apiv3.IPIPModeNever, apiv3.VXLANModeAlways), *getAPIPool("192.168.2.0/24", apiv3.IPIPModeCrossSubnet, apiv3.VXLANModeNever)},
				[]model.KVPair{*getModelPool("192.168.3.0/24", encap.Undefined, encap.Always), *getModelPool("192.168.4.0/24", encap.CrossSubnet, encap.Undefined)},
				false, false),
		)
	})
})

var _ = Describe("EncapsulationResolver", func() {
	var encapsulationResolver *EncapsulationResolver
	var conf *config.Config
	var callbacks *encapResolverCallbackRecorder

	BeforeEach(func() {
		conf = config.New()
		callbacks = &encapResolverCallbackRecorder{}
		encapsulationResolver = NewEncapsulationResolver(conf, callbacks)
	})

	Describe("OnStatusUpdate", func() {
		It("should not touch inSync to true when receiving other status updates", func() {
			encapsulationResolver.OnStatusUpdate(api.WaitForDatastore)
			Expect(encapsulationResolver.inSync).To(BeFalse())

			encapsulationResolver.OnStatusUpdate(api.ResyncInProgress)
			Expect(encapsulationResolver.inSync).To(BeFalse())
		})

		It("should update inSync to true when receiving InSync status update", func() {
			encapsulationResolver.OnStatusUpdate(api.InSync)
			Expect(encapsulationResolver.inSync).To(BeTrue())
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
		})
	})

	Describe("Not inSync", func() {
		It("should not send encapUpdates when adding pools with IPIP encap", func() {
			_, cidr, err := net.ParseCIDR("192.168.1.0/24")
			Expect(err).To(Not(HaveOccurred()))
			encapsulationResolver.OnPoolUpdate(addPoolUpdate(*cidr, encap.Always, encap.Undefined))
			Expect(callbacks.encapUpdates).To(BeNil())
		})

		It("should not send encapUpdates when adding pools with VXLAN encap", func() {
			_, cidr, err := net.ParseCIDR("192.168.1.0/24")
			Expect(err).To(Not(HaveOccurred()))
			encapsulationResolver.OnPoolUpdate(addPoolUpdate(*cidr, encap.Undefined, encap.CrossSubnet))
			Expect(callbacks.encapUpdates).To(BeNil())
		})
		It("should not send encapUpdates when adding and removing pools", func() {
			_, cidr, err := net.ParseCIDR("192.168.1.0/24")
			Expect(err).To(Not(HaveOccurred()))
			encapsulationResolver.OnPoolUpdate(addPoolUpdate(*cidr, encap.Always, encap.CrossSubnet))
			encapsulationResolver.OnPoolUpdate(removePoolUpdate(*cidr))
			Expect(callbacks.encapUpdates).To(BeNil())
		})
		It("should not send encapUpdates when changing encap in FelixConfig", func() {
			t := true
			conf.IpInIpEnabled = &t
			conf.VXLANEnabled = &t
			Expect(callbacks.encapUpdates).To(BeNil())
		})
	})

	Describe("Already inSync", func() {
		BeforeEach(func() {
			encapsulationResolver.OnStatusUpdate(api.InSync)
		})
		It("should send encapUpdates when adding pools with IPIP encap", func() {
			_, cidr, err := net.ParseCIDR("192.168.1.0/24")
			Expect(err).To(Not(HaveOccurred()))
			encapsulationResolver.OnPoolUpdate(addPoolUpdate(*cidr, encap.Always, encap.Undefined))
			Expect(callbacks.encapUpdates).To(Equal(
				[]*proto.Encapsulation{
					{IpipEnabled: false, VxlanEnabled: false},
					{IpipEnabled: true, VxlanEnabled: false},
				}))
		})
		It("should send encapUpdates when adding pools with VXLAN encap", func() {
			_, cidr, err := net.ParseCIDR("192.168.1.0/24")
			Expect(err).To(Not(HaveOccurred()))
			encapsulationResolver.OnPoolUpdate(addPoolUpdate(*cidr, encap.Undefined, encap.CrossSubnet))
			Expect(callbacks.encapUpdates).To(Equal(
				[]*proto.Encapsulation{
					{IpipEnabled: false, VxlanEnabled: false},
					{IpipEnabled: false, VxlanEnabled: true},
				}))
		})
		It("should send encapUpdates when removing pools", func() {
			Expect(callbacks.encapUpdates).To(Equal(
				[]*proto.Encapsulation{
					{IpipEnabled: false, VxlanEnabled: false},
				}))
			_, cidr1, err := net.ParseCIDR("192.168.1.0/24")
			Expect(err).To(Not(HaveOccurred()))
			encapsulationResolver.OnPoolUpdate(addPoolUpdate(*cidr1, encap.Always, encap.CrossSubnet))

			_, cidr2, err := net.ParseCIDR("192.168.2.0/24")
			Expect(err).To(Not(HaveOccurred()))
			encapsulationResolver.OnPoolUpdate(addPoolUpdate(*cidr2, encap.Undefined, encap.Always))
			Expect(callbacks.encapUpdates).To(Equal(
				[]*proto.Encapsulation{
					{IpipEnabled: false, VxlanEnabled: false},
					{IpipEnabled: true, VxlanEnabled: true},
					{IpipEnabled: true, VxlanEnabled: true},
				}))

			encapsulationResolver.OnStatusUpdate(api.InSync)

			encapsulationResolver.OnPoolUpdate(removePoolUpdate(*cidr1))
			Expect(callbacks.encapUpdates).To(Equal(
				[]*proto.Encapsulation{
					{IpipEnabled: false, VxlanEnabled: false},
					{IpipEnabled: true, VxlanEnabled: true},
					{IpipEnabled: true, VxlanEnabled: true},
					{IpipEnabled: false, VxlanEnabled: true},
				}))
		})
		It("should not send encapUpdates when changing encap in FelixConfig (Felix will restart through another code path)", func() {
			t := true
			conf.IpInIpEnabled = &t
			conf.VXLANEnabled = &t
			Expect(callbacks.encapUpdates).To(Equal(
				[]*proto.Encapsulation{
					{IpipEnabled: false, VxlanEnabled: false},
				}))
		})
	})

	Describe("Changing inSync", func() {
		It("should not send encapUpdates when adding pools before inSync, but should right after", func() {
			_, cidr, err := net.ParseCIDR("192.168.1.0/24")
			Expect(err).To(Not(HaveOccurred()))
			encapsulationResolver.OnPoolUpdate(addPoolUpdate(*cidr, encap.Always, encap.Undefined))
			Expect(callbacks.encapUpdates).To(BeNil())

			encapsulationResolver.OnStatusUpdate(api.InSync)
			Expect(callbacks.encapUpdates).To(Equal(
				[]*proto.Encapsulation{
					{IpipEnabled: true, VxlanEnabled: false},
				}))
		})
		It("should not send encapUpdates when changing FelixConfig before inSync, but should right after", func() {
			t := true
			f := false
			conf.IpInIpEnabled = &f
			conf.VXLANEnabled = &t

			encapsulationResolver.OnStatusUpdate(api.InSync)
			Expect(callbacks.encapUpdates).To(Equal(
				[]*proto.Encapsulation{
					{IpipEnabled: false, VxlanEnabled: true},
				}))
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

func getAPIPool(cidr string, ipipMode apiv3.IPIPMode, vxlanMode apiv3.VXLANMode) *model.KVPair {
	return &model.KVPair{
		Value: &apiv3.IPPool{
			Spec: apiv3.IPPoolSpec{
				CIDR:      cidr,
				IPIPMode:  ipipMode,
				VXLANMode: vxlanMode,
			},
		},
	}
}

func getModelPool(cidr string, ipipMode, vxlanMode encap.Mode) *model.KVPair {
	_, parsedCidr, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil
	}
	return &model.KVPair{
		Key: model.IPPoolKey{
			CIDR: *parsedCidr,
		},
		Value: &model.IPPool{
			CIDR:      *parsedCidr,
			IPIPMode:  ipipMode,
			VXLANMode: vxlanMode,
		},
	}
}

type encapResolverCallbackRecorder struct {
	encapUpdates []*proto.Encapsulation
}

func (e *encapResolverCallbackRecorder) OnEncapUpdate(encap config.Encapsulation) {
	e.encapUpdates = append(e.encapUpdates,
		&proto.Encapsulation{
			IpipEnabled:  encap.IPIPEnabled,
			VxlanEnabled: encap.VXLANEnabled,
		})
}

func (e *encapResolverCallbackRecorder) OnHostIPUpdate(hostname string, ip *net.IP) {
	Fail("HostIPUpdate received")
}

func (e *encapResolverCallbackRecorder) OnHostIPRemove(hostname string) {
	Fail("HostIPRemove received")
}

func (e *encapResolverCallbackRecorder) OnIPPoolUpdate(model.IPPoolKey, *model.IPPool) {
	Fail("IPPoolUpdate received")
}

func (e *encapResolverCallbackRecorder) OnIPPoolRemove(model.IPPoolKey) {
	Fail("IPPoolRemove received")
}

func (e *encapResolverCallbackRecorder) OnWireguardUpdate(string, *model.Wireguard) {
	Fail("OnWireguardUpdate received")
}

func (e *encapResolverCallbackRecorder) OnWireguardRemove(string) {
	Fail("OnWireguardRemove received")
}

func (e *encapResolverCallbackRecorder) OnServiceAccountUpdate(update *proto.ServiceAccountUpdate) {
	Fail("ServiceAccountUpdate received")
}

func (e *encapResolverCallbackRecorder) OnServiceAccountRemove(id proto.ServiceAccountID) {
	Fail("ServiceAccountRemove received")
}

func (e *encapResolverCallbackRecorder) OnNamespaceUpdate(update *proto.NamespaceUpdate) {
	Fail("NamespaceUpdate received")
}

func (e *encapResolverCallbackRecorder) OnNamespaceRemove(id proto.NamespaceID) {
	Fail("NamespaceRemove received")
}

func (e *encapResolverCallbackRecorder) OnGlobalBGPConfigUpdate(*v3.BGPConfiguration) {
	Fail("OnGlobalBGPConfigUpdate received")
}
