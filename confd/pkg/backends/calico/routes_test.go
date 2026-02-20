package calico

import (
	"fmt"
	"net"
	"strings"
	"sync"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	v1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

const (
	// Range and specific IP for external IP test.
	externalIPRange1 = "45.12.0.0/16"
	externalIP1      = "45.12.70.5"

	// Range and specific IP for external IP test.
	externalIPRange2 = "172.217.3.5/32"
	externalIP2      = "172.217.3.5"

	// Specific IP for loadbalancer IP test.
	loadBalancerIP1 = "172.217.4.10"

	// externalIP3 for single external IP test.
	externalIP3 = "45.12.70.7"
)

func addEndpointSubset(ep *discoveryv1.EndpointSlice, nodename string, address string) {
	ep.Endpoints = append(ep.Endpoints, discoveryv1.Endpoint{
		NodeName:  &nodename,
		Addresses: []string{address},
	})
}

func buildSimpleService() (svc *v1.Service, ep *discoveryv1.EndpointSlice) {
	meta := metav1.ObjectMeta{Namespace: "foo", Name: "bar", Labels: map[string]string{"kubernetes.io/service-name": "bar"}}
	svc = &v1.Service{
		ObjectMeta: meta,
		Spec: v1.ServiceSpec{
			Type:                  v1.ServiceTypeClusterIP,
			ClusterIP:             "127.0.0.1",
			ClusterIPs:            []string{"127.0.0.1", "::1"},
			ExternalTrafficPolicy: v1.ServiceExternalTrafficPolicyTypeLocal,
			ExternalIPs:           []string{externalIP1, externalIP2},
			IPFamilies:            []v1.IPFamily{v1.IPv4Protocol},
		},
	}
	ep = &discoveryv1.EndpointSlice{
		AddressType: discoveryv1.AddressType(v1.IPv4Protocol),
		ObjectMeta:  meta,
	}
	return
}

func buildSimpleService2() (svc *v1.Service, ep *discoveryv1.EndpointSlice) {
	meta := metav1.ObjectMeta{Namespace: "foo", Name: "rem", Labels: map[string]string{"kubernetes.io/service-name": "rem"}}
	svc = &v1.Service{
		ObjectMeta: meta,
		Spec: v1.ServiceSpec{
			Type:                  v1.ServiceTypeClusterIP,
			ClusterIP:             "127.0.0.5",
			ClusterIPs:            []string{"127.0.0.5", "::5"},
			ExternalTrafficPolicy: v1.ServiceExternalTrafficPolicyTypeLocal,
			ExternalIPs:           []string{externalIP1, externalIP2},
			IPFamilies:            []v1.IPFamily{v1.IPv4Protocol},
		},
	}
	ep = &discoveryv1.EndpointSlice{
		AddressType: discoveryv1.AddressType(v1.IPv4Protocol),
		ObjectMeta:  meta,
	}
	return
}

func buildSimpleService3() (svc *v1.Service, ep *discoveryv1.EndpointSlice) {
	meta := metav1.ObjectMeta{Namespace: "foo", Name: "lb", Labels: map[string]string{"kubernetes.io/service-name": "lb"}}
	svc = &v1.Service{
		ObjectMeta: meta,
		Spec: v1.ServiceSpec{
			Type:                  v1.ServiceTypeLoadBalancer,
			ClusterIP:             "127.0.0.10",
			ClusterIPs:            []string{"127.0.0.10", "::a"},
			ExternalTrafficPolicy: v1.ServiceExternalTrafficPolicyTypeLocal,
			LoadBalancerIP:        loadBalancerIP1,
			IPFamilies:            []v1.IPFamily{v1.IPv4Protocol},
		},
		Status: v1.ServiceStatus{
			LoadBalancer: v1.LoadBalancerStatus{
				Ingress: []v1.LoadBalancerIngress{{IP: loadBalancerIP1}},
			},
		},
	}
	ep = &discoveryv1.EndpointSlice{
		AddressType: discoveryv1.AddressType(v1.IPv4Protocol),
		ObjectMeta:  meta,
	}
	return
}

func buildSimpleService4() (svc *v1.Service, ep *discoveryv1.EndpointSlice) {
	meta := metav1.ObjectMeta{Namespace: "foo", Name: "ext", Labels: map[string]string{"kubernetes.io/service-name": "ext"}}
	svc = &v1.Service{
		ObjectMeta: meta,
		Spec: v1.ServiceSpec{
			Type:                  v1.ServiceTypeLoadBalancer,
			ClusterIP:             "127.0.0.11",
			ClusterIPs:            []string{"127.0.0.11", "::b"},
			ExternalTrafficPolicy: v1.ServiceExternalTrafficPolicyTypeLocal,
			ExternalIPs:           []string{externalIP3},
			IPFamilies:            []v1.IPFamily{v1.IPv4Protocol},
		},
	}
	ep = &discoveryv1.EndpointSlice{
		AddressType: discoveryv1.AddressType(v1.IPv4Protocol),
		ObjectMeta:  meta,
	}
	return
}

var _ = Describe("RouteGenerator", func() {
	var rg *routeGenerator
	var expectedSvcRouteMap map[string]bool
	var expectedSvc2RouteMap map[string]bool

	BeforeEach(func() {
		_, ipNet1, _ := net.ParseCIDR("104.244.42.129/32")
		_, ipNet2, _ := net.ParseCIDR("172.217.3.0/24")

		expectedSvcRouteMap = make(map[string]bool)
		expectedSvcRouteMap["127.0.0.1/32"] = true
		expectedSvcRouteMap["::1/128"] = true
		expectedSvcRouteMap["172.217.3.5/32"] = true

		expectedSvc2RouteMap = make(map[string]bool)
		expectedSvc2RouteMap["127.0.0.5/32"] = true
		expectedSvc2RouteMap["::5/128"] = true
		expectedSvc2RouteMap["172.217.3.5/32"] = true

		rg = &routeGenerator{
			nodeName:                   "foobar",
			svcIndexer:                 cache.NewIndexer(cache.MetaNamespaceKeyFunc, nil),
			epIndexer:                  cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{endpointSliceServiceIndex: endpointSliceServiceIndexFunc}),
			svcRouteMap:                make(map[string]map[string]bool),
			routeAdvertisementRefCount: make(map[string]int),
			client: &client{
				cache:                    make(map[string]string),
				syncedOnce:               true,
				clusterCIDRs:             []string{"10.0.0.0/16"},
				programmedRouteRefCount:  make(map[string]int),
				ExternalIPRouteIndex:     NewRouteIndex(),
				ClusterIPRouteIndex:      NewRouteIndex(),
				LoadBalancerIPRouteIndex: NewRouteIndex(),

				externalIPs: []string{
					ipNet1.String(),
					ipNet2.String(),
				},
				externalIPNets: []*net.IPNet{
					ipNet1,
					ipNet2,
				},
			},
		}
		rg.client.watcherCond = sync.NewCond(&rg.client.cacheLock)
	})
	Describe("getServiceForEndpoints", func() {
		It("should get corresponding service for endpoints", func() {
			// getServiceForEndpoints
			svc, ep := buildSimpleService()
			err := rg.svcIndexer.Add(svc)
			Expect(err).NotTo(HaveOccurred())
			fetchedSvc, key := rg.getServiceForEndpoints(ep)
			Expect(fetchedSvc.ObjectMeta).To(Equal(svc.ObjectMeta))
			Expect(key).To(Equal("foo/bar"))
		})
	})
	Describe("getEndpointsForService", func() {
		It("should get corresponding endpoints for service", func() {
			// getEndpointsForService
			svc, ep := buildSimpleService()
			err := rg.epIndexer.Add(ep)
			Expect(err).NotTo(HaveOccurred())
			fetchedEp, key := rg.getEndpointsForService(svc)
			Expect(fetchedEp[0].ObjectMeta).To(Equal(ep.ObjectMeta))
			Expect(key).To(Equal("foo/bar"))
		})
	})

	testRouteGeneratorUpdatesOnlyWithValidCIDRs := func(f func([]string)) {
		verifyInitialState := func() {
			Expect(rg.client.cache["/calico/staticroutes/192.168.0.0-16"]).To(Equal("192.168.0.0/16"))
			Expect(rg.client.cache["/calico/rejectcidrs/192.168.0.0-16"]).To(Equal("192.168.0.0/16"))
		}

		f([]string{"192.168.0.0/16"})
		verifyInitialState()

		invalidNets := [][]string{
			{"invalid"},
			{"10.10.1.0/24", "invalid"},
			{"10.10.1.0/24", "x.y.z.z/12"},
		}
		for _, n := range invalidNets {
			f(n)
			verifyInitialState()
		}

		f([]string{"10.10.1.0/24"})
		Expect(rg.client.cache["/calico/staticroutes/10.10.1.0-24"]).To(Equal("10.10.1.0/24"))
		Expect(rg.client.cache["/calico/rejectcidrs/10.10.1.0-24"]).To(Equal("10.10.1.0/24"))
	}

	Describe("onClusterIPsUpdate", func() {
		It("should do updates only if the new nets are valid", func() {
			testRouteGeneratorUpdatesOnlyWithValidCIDRs(rg.client.onClusterIPsUpdate)
		})
	})

	Describe("onExternalIPsUpdate", func() {
		It("should do updates only if the new nets are valid", func() {
			testRouteGeneratorUpdatesOnlyWithValidCIDRs(rg.client.onExternalIPsUpdate)
		})
	})

	Describe("(un)setRouteForSvc", func() {
		Context("svc = svc, ep = nil", func() {
			It("should set and unset routes for a service", func() {
				svc, ep := buildSimpleService()
				addEndpointSubset(ep, rg.nodeName, "1.1.1.1")

				err := rg.epIndexer.Add(ep)
				Expect(err).NotTo(HaveOccurred())
				rg.setRouteForSvc(svc, nil)
				_, err = fmt.Fprintln(GinkgoWriter, rg.svcRouteMap)
				Expect(err).NotTo(HaveOccurred())
				Expect(rg.svcRouteMap["foo/bar"]).To(Equal(expectedSvcRouteMap))
				rg.unsetRouteForSvc(ep)
				Expect(rg.svcRouteMap["foo/bar"]).To(BeEmpty())
			})
		})
		Context("svc = nil, ep = ep", func() {
			It("should set an unset routes for a service", func() {
				svc, ep := buildSimpleService()
				addEndpointSubset(ep, rg.nodeName, "1.1.1.111")

				err := rg.svcIndexer.Add(svc)
				Expect(err).NotTo(HaveOccurred())
				rg.setRouteForSvc(nil, ep)
				Expect(rg.svcRouteMap["foo/bar"]).To(Equal(expectedSvcRouteMap))
				rg.unsetRouteForSvc(ep)
				Expect(rg.svcRouteMap["foo/bar"]).To(BeEmpty())
			})
		})
	})

	Describe("resourceInformerHandlers", func() {
		var (
			svc, svc2, svc3, svc4 *v1.Service
			ep, ep2, ep3, ep4     *discoveryv1.EndpointSlice
		)

		BeforeEach(func() {
			svc, ep = buildSimpleService()
			svc2, ep2 = buildSimpleService2()
			svc3, ep3 = buildSimpleService3()
			svc4, ep4 = buildSimpleService4()

			addEndpointSubset(ep, rg.nodeName, "1.1.1.1")
			addEndpointSubset(ep2, rg.nodeName, "1.1.1.1")
			addEndpointSubset(ep3, rg.nodeName, "1.1.1.1")
			addEndpointSubset(ep4, rg.nodeName, "1.1.1.1")
			err := rg.epIndexer.Add(ep)
			Expect(err).NotTo(HaveOccurred())
			err = rg.epIndexer.Add(ep2)
			Expect(err).NotTo(HaveOccurred())
			err = rg.epIndexer.Add(ep3)
			Expect(err).NotTo(HaveOccurred())
			err = rg.epIndexer.Add(ep4)
			Expect(err).NotTo(HaveOccurred())
			err = rg.svcIndexer.Add(svc)
			Expect(err).NotTo(HaveOccurred())
			err = rg.svcIndexer.Add(svc2)
			Expect(err).NotTo(HaveOccurred())
			err = rg.svcIndexer.Add(svc3)
			Expect(err).NotTo(HaveOccurred())
			err = rg.svcIndexer.Add(svc4)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should remove advertised IPs when endpoints are deleted", func() {
			// Trigger a service add - it should update the cache with its route.
			initRevision := rg.client.cacheRevision
			rg.onSvcAdd(svc)
			Expect(rg.client.cacheRevision).To(Equal(initRevision + 3))
			Expect(rg.svcRouteMap["foo/bar"]).To(Equal(expectedSvcRouteMap))
			Expect(rg.routeAdvertisementRefCount["127.0.0.1/32"]).To(Equal(1))
			Expect(rg.routeAdvertisementRefCount["::1/128"]).To(Equal(1))
			Expect(rg.routeAdvertisementRefCount["172.217.3.5/32"]).To(Equal(1))
			Expect(rg.client.cache["/calico/staticroutes/127.0.0.1-32"]).To(Equal("127.0.0.1/32"))
			Expect(rg.client.cache["/calico/staticroutesv6/::1-128"]).To(Equal("::1/128"))
			Expect(rg.client.cache["/calico/staticroutes/172.217.3.5-32"]).To(Equal("172.217.3.5/32"))

			// Simulate the remove of the local endpoint. It should withdraw the routes.
			ep.Endpoints = []discoveryv1.Endpoint{}
			err := rg.epIndexer.Add(ep)
			Expect(err).NotTo(HaveOccurred())
			rg.onEPAdd(ep)
			Expect(rg.client.cacheRevision).To(Equal(initRevision + 6))
			Expect(rg.svcRouteMap["foo/bar"]).To(BeEmpty())
			Expect(rg.routeAdvertisementRefCount["127.0.0.1/32"]).To(Equal(0))
			Expect(rg.routeAdvertisementRefCount["::1/128"]).To(Equal(0))
			Expect(rg.routeAdvertisementRefCount["172.217.3.5/32"]).To(Equal(0))
			Expect(rg.client.cache["/calico/staticroutes/127.0.0.1-32"]).To(Equal(""))
			Expect(rg.client.cache["/calico/staticroutesv6/::1-128"]).To(Equal(""))
			Expect(rg.client.cache["/calico/staticroutes/172.217.3.5-32"]).To(Equal(""))
			Expect(rg.client.cache).To(Equal(map[string]string{}))

			// Add the endpoint back with an IPv6 address.  The service's cluster IPs
			// should remain non-advertised.
			ep.AddressType = discoveryv1.AddressType(v1.IPv6Protocol)
			ep.Endpoints = []discoveryv1.Endpoint{{
				Addresses: []string{"fd5f:1234::3"},
				NodeName:  &rg.nodeName,
			}}
			err = rg.epIndexer.Add(ep)
			Expect(err).NotTo(HaveOccurred())
			rg.onEPAdd(ep)
			Expect(rg.client.cacheRevision).To(Equal(initRevision + 6))
			Expect(rg.svcRouteMap["foo/bar"]).To(BeEmpty())
			Expect(rg.routeAdvertisementRefCount["127.0.0.1/32"]).To(Equal(0))
			Expect(rg.routeAdvertisementRefCount["::1/128"]).To(Equal(0))
			Expect(rg.routeAdvertisementRefCount["172.217.3.5/32"]).To(Equal(0))
			Expect(rg.client.cache["/calico/staticroutes/127.0.0.1-32"]).To(Equal(""))
			Expect(rg.client.cache["/calico/staticroutesv6/::1-128"]).To(Equal(""))
			Expect(rg.client.cache["/calico/staticroutes/172.217.3.5-32"]).To(Equal(""))
			Expect(rg.client.cache).To(Equal(map[string]string{}))

			// Add the endpoint again with an IPv4 address.  The service's cluster IPs
			// should now be advertised.
			ep.AddressType = discoveryv1.AddressType(v1.IPv4Protocol)
			ep.Endpoints = []discoveryv1.Endpoint{{
				Addresses: []string{"10.96.0.45"},
				NodeName:  &rg.nodeName,
			}}
			err = rg.epIndexer.Add(ep)
			Expect(err).NotTo(HaveOccurred())
			rg.onEPAdd(ep)
			Expect(rg.client.cacheRevision).To(Equal(initRevision + 9))
			Expect(rg.svcRouteMap["foo/bar"]).To(Equal(expectedSvcRouteMap))
			Expect(rg.routeAdvertisementRefCount["127.0.0.1/32"]).To(Equal(1))
			Expect(rg.routeAdvertisementRefCount["::1/128"]).To(Equal(1))
			Expect(rg.routeAdvertisementRefCount["172.217.3.5/32"]).To(Equal(1))
			Expect(rg.client.cache["/calico/staticroutes/127.0.0.1-32"]).To(Equal("127.0.0.1/32"))
			Expect(rg.client.cache["/calico/staticroutesv6/::1-128"]).To(Equal("::1/128"))
			Expect(rg.client.cache["/calico/staticroutes/172.217.3.5-32"]).To(Equal("172.217.3.5/32"))
		})

		Context("onSvc[Add|Delete]", func() {
			It("should add the service's cluster IPs and approved external IPs into the svcRouteMap", func() {
				// add
				initRevision := rg.client.cacheRevision
				rg.onSvcAdd(svc)
				Expect(rg.client.cacheRevision).To(Equal(initRevision + 3))
				Expect(rg.svcRouteMap["foo/bar"]).To(Equal(expectedSvcRouteMap))
				Expect(rg.routeAdvertisementRefCount["127.0.0.1/32"]).To(Equal(1))
				Expect(rg.routeAdvertisementRefCount["::1/128"]).To(Equal(1))
				Expect(rg.routeAdvertisementRefCount["172.217.3.5/32"]).To(Equal(1))
				Expect(rg.client.cache["/calico/staticroutes/127.0.0.1-32"]).To(Equal("127.0.0.1/32"))
				Expect(rg.client.cache["/calico/staticroutesv6/::1-128"]).To(Equal("::1/128"))
				Expect(rg.client.cache["/calico/staticroutes/172.217.3.5-32"]).To(Equal("172.217.3.5/32"))

				// delete
				rg.onSvcDelete(svc)
				Expect(rg.client.cacheRevision).To(Equal(initRevision + 6))
				Expect(rg.svcRouteMap["foo/bar"]).ToNot(HaveKey("172.217.3.5/32"))
				Expect(rg.svcRouteMap["foo/bar"]).ToNot(HaveKey("127.0.0.1/32"))
				Expect(rg.svcRouteMap["foo/bar"]).ToNot(HaveKey("::1/128"))
				Expect(rg.routeAdvertisementRefCount["127.0.0.1/32"]).To(Equal(0))
				Expect(rg.routeAdvertisementRefCount["::1/128"]).To(Equal(0))
				Expect(rg.routeAdvertisementRefCount["172.217.3.5/32"]).To(Equal(0))
				Expect(rg.client.cache).ToNot(HaveKey("/calico/staticroutes/172.217.3.5-32"))
				Expect(rg.client.cache).ToNot(HaveKey("/calico/staticroutes/127.0.0.1-32"))
				Expect(rg.client.cache).ToNot(HaveKey("/calico/staticroutesv6/::1-128"))
			})

			It("should handle two services advertising the same route correctly, only advertising the route once and only withdrawing the route when both services are removed.", func() {
				// add both services and make sure the duplicate route is counted twice
				initRevision := rg.client.cacheRevision
				rg.onSvcAdd(svc)
				rg.onSvcAdd(svc2)
				Expect(rg.client.cacheRevision).To(Equal(initRevision + 5))
				Expect(rg.svcRouteMap["foo/bar"]).To(Equal(expectedSvcRouteMap))
				Expect(rg.svcRouteMap["foo/rem"]).To(Equal(expectedSvc2RouteMap))
				Expect(rg.routeAdvertisementRefCount["127.0.0.1/32"]).To(Equal(1))
				Expect(rg.routeAdvertisementRefCount["::1/128"]).To(Equal(1))
				Expect(rg.routeAdvertisementRefCount["127.0.0.5/32"]).To(Equal(1))
				Expect(rg.routeAdvertisementRefCount["::5/128"]).To(Equal(1))
				Expect(rg.routeAdvertisementRefCount["172.217.3.5/32"]).To(Equal(2))
				Expect(rg.client.cache["/calico/staticroutes/127.0.0.1-32"]).To(Equal("127.0.0.1/32"))
				Expect(rg.client.cache["/calico/staticroutesv6/::1-128"]).To(Equal("::1/128"))
				Expect(rg.client.cache["/calico/staticroutes/127.0.0.5-32"]).To(Equal("127.0.0.5/32"))
				Expect(rg.client.cache["/calico/staticroutesv6/::5-128"]).To(Equal("::5/128"))
				Expect(rg.client.cache["/calico/staticroutes/172.217.3.5-32"]).To(Equal("172.217.3.5/32"))

				// We expect the client refcounter to have a single reference for each generated route, as
				// the route generator deduplicates route updates itself for duplicate service IPs.
				Expect(rg.client.programmedRouteRefCount["/calico/staticroutes/127.0.0.5-32"]).To(Equal(1))
				Expect(rg.client.programmedRouteRefCount["/calico/staticroutesv6/::5-128"]).To(Equal(1))
				Expect(rg.client.programmedRouteRefCount["/calico/staticroutes/127.0.0.1-32"]).To(Equal(1))
				Expect(rg.client.programmedRouteRefCount["/calico/staticroutesv6/::1-128"]).To(Equal(1))
				Expect(rg.client.programmedRouteRefCount["/calico/staticroutes/172.217.3.5-32"]).To(Equal(1))

				// delete one of the services, and make sure the duplicate route is still advertised
				// and we handle the counting logic correctly
				rg.onSvcDelete(svc2)
				Expect(rg.client.cacheRevision).To(Equal(initRevision + 7))
				Expect(rg.routeAdvertisementRefCount["127.0.0.1/32"]).To(Equal(1))
				Expect(rg.routeAdvertisementRefCount["::1/128"]).To(Equal(1))
				Expect(rg.routeAdvertisementRefCount["127.0.0.5/32"]).To(Equal(0))
				Expect(rg.routeAdvertisementRefCount["::5-128"]).To(Equal(0))
				Expect(rg.routeAdvertisementRefCount["172.217.3.5/32"]).To(Equal(1))
				Expect(rg.svcRouteMap["foo/bar"]).To(Equal(expectedSvcRouteMap))
				Expect(rg.svcRouteMap["foo/rem"]).ToNot(HaveKey("127.0.0.5/32"))
				Expect(rg.svcRouteMap["foo/rem"]).ToNot(HaveKey("::5/128"))
				Expect(rg.svcRouteMap["foo/rem"]).ToNot(HaveKey("172.217.3.5/32"))
				Expect(rg.client.cache["/calico/staticroutes/127.0.0.1-32"]).To(Equal("127.0.0.1/32"))
				Expect(rg.client.cache["/calico/staticroutesv6/::1-128"]).To(Equal("::1/128"))
				Expect(rg.client.cache["/calico/staticroutes/172.217.3.5-32"]).To(Equal("172.217.3.5/32"))
				Expect(rg.client.cache).ToNot(HaveKey("/calico/staticroutes/127.0.0.5-32"))
				Expect(rg.client.cache).ToNot(HaveKey("/calico/staticroutesv6/::5-128"))

				// The client refcount should be updated as well.
				Expect(rg.client.programmedRouteRefCount["/calico/staticroutes/127.0.0.1-32"]).To(Equal(1))
				Expect(rg.client.programmedRouteRefCount["/calico/staticroutesv6/::1-128"]).To(Equal(1))
				Expect(rg.client.programmedRouteRefCount["/calico/staticroutes/172.217.3.5-32"]).To(Equal(1))
				Expect(rg.client.programmedRouteRefCount).NotTo(HaveKey("/calico/staticroutes/127.0.0.5-32"))
				Expect(rg.client.programmedRouteRefCount).NotTo(HaveKey("/calico/staticroutesv6/::5-128"))

				// delete the other service and check that both routes are withdrawn and their counts are 0
				rg.onSvcDelete(svc)
				Expect(rg.client.cacheRevision).To(Equal(initRevision + 10))
				Expect(rg.svcRouteMap["foo/bar"]).ToNot(HaveKey("172.217.3.5/32"))
				Expect(rg.svcRouteMap["foo/bar"]).ToNot(HaveKey("127.0.0.1/32"))
				Expect(rg.svcRouteMap["foo/bar"]).ToNot(HaveKey("::1/128"))
				Expect(rg.routeAdvertisementRefCount["127.0.0.1/32"]).To(Equal(0))
				Expect(rg.routeAdvertisementRefCount["::1/128"]).To(Equal(0))
				Expect(rg.routeAdvertisementRefCount["172.217.3.5/32"]).To(Equal(0))
				Expect(rg.client.cache).ToNot(HaveKey("/calico/staticroutes/172.217.3.5-32"))
				Expect(rg.client.cache).ToNot(HaveKey("/calico/staticroutes/127.0.0.1-32"))
				Expect(rg.client.cache).ToNot(HaveKey("/calico/staticroutesv6/::1-128"))

				// The client refcount should be updated as well.
				Expect(rg.client.programmedRouteRefCount).NotTo(HaveKey("/calico/staticroutes/127.0.0.1-32"))
				Expect(rg.client.programmedRouteRefCount).NotTo(HaveKey("/calico/staticroutesv6/::1-128"))
				Expect(rg.client.programmedRouteRefCount).NotTo(HaveKey("/calico/staticroutes/172.217.3.5-32"))
				Expect(rg.client.programmedRouteRefCount).NotTo(HaveKey("/calico/staticroutes/127.0.0.5-32"))
				Expect(rg.client.programmedRouteRefCount).NotTo(HaveKey("/calico/staticroutesv6/::5-128"))
			})
		})

		Context("onSvcUpdate", func() {
			It("should add the service's cluster IPs and approved external IPs into the svcRouteMap and then remove them for unsupported service type", func() {
				initRevision := rg.client.cacheRevision
				rg.onSvcUpdate(nil, svc)
				Expect(rg.client.cacheRevision).To(Equal(initRevision + 3))
				Expect(rg.svcRouteMap["foo/bar"]).To(Equal(expectedSvcRouteMap))
				Expect(rg.routeAdvertisementRefCount["127.0.0.1/32"]).To(Equal(1))
				Expect(rg.routeAdvertisementRefCount["::1/128"]).To(Equal(1))
				Expect(rg.routeAdvertisementRefCount["172.217.3.5/32"]).To(Equal(1))
				Expect(rg.client.cache["/calico/staticroutes/127.0.0.1-32"]).To(Equal("127.0.0.1/32"))
				Expect(rg.client.cache["/calico/staticroutesv6/::1-128"]).To(Equal("::1/128"))
				Expect(rg.client.cache["/calico/staticroutes/172.217.3.5-32"]).To(Equal("172.217.3.5/32"))

				// set to unsupported service type
				svc.Spec.Type = v1.ServiceTypeExternalName
				rg.onSvcUpdate(nil, svc)
				Expect(rg.client.cacheRevision).To(Equal(initRevision + 6))
				Expect(rg.svcRouteMap["foo/bar"]).ToNot(HaveKey("172.217.3.5/32"))
				Expect(rg.svcRouteMap["foo/bar"]).ToNot(HaveKey("127.0.0.1-32"))
				Expect(rg.svcRouteMap["foo/bar"]).ToNot(HaveKey("::1-128"))
				Expect(rg.routeAdvertisementRefCount["127.0.0.1/32"]).To(Equal(0))
				Expect(rg.routeAdvertisementRefCount["::1/128"]).To(Equal(0))
				Expect(rg.routeAdvertisementRefCount["172.217.3.5/32"]).To(Equal(0))
				Expect(rg.client.cache).ToNot(HaveKey("/calico/staticroutes/172.217.3.5-32"))
				Expect(rg.client.cache).ToNot(HaveKey("/calico/staticroutes/127.0.0.1-32"))
				Expect(rg.client.cache).ToNot(HaveKey("/calico/staticroutesv6/::1-128"))
			})
		})

		Context("onEp[Add|Delete]", func() {
			It("should add the service's cluster IPs and approved external IPs into the svcRouteMap", func() {
				// add
				initRevision := rg.client.cacheRevision
				rg.onEPAdd(ep)
				Expect(rg.client.cacheRevision).To(Equal(initRevision + 3))
				Expect(rg.svcRouteMap["foo/bar"]).To(Equal(expectedSvcRouteMap))
				Expect(rg.routeAdvertisementRefCount["127.0.0.1/32"]).To(Equal(1))
				Expect(rg.routeAdvertisementRefCount["::1/128"]).To(Equal(1))
				Expect(rg.routeAdvertisementRefCount["172.217.3.5/32"]).To(Equal(1))
				Expect(rg.client.cache["/calico/staticroutes/127.0.0.1-32"]).To(Equal("127.0.0.1/32"))
				Expect(rg.client.cache["/calico/staticroutesv6/::1-128"]).To(Equal("::1/128"))
				Expect(rg.client.cache["/calico/staticroutes/172.217.3.5-32"]).To(Equal("172.217.3.5/32"))

				// delete
				rg.onEPDelete(ep)
				Expect(rg.client.cacheRevision).To(Equal(initRevision + 6))
				Expect(rg.svcRouteMap).ToNot(HaveKey("foo/bar"))
				Expect(rg.routeAdvertisementRefCount["127.0.0.1/32"]).To(Equal(0))
				Expect(rg.routeAdvertisementRefCount["::1/128"]).To(Equal(0))
				Expect(rg.routeAdvertisementRefCount["172.217.3.5/32"]).To(Equal(0))
				Expect(rg.client.cache).ToNot(HaveKey("/calico/staticroutes/127.0.0.1-32"))
				Expect(rg.client.cache).ToNot(HaveKey("/calico/staticroutesv6/::1-128"))
				Expect(rg.client.cache).ToNot(HaveKey("/calico/staticroutes/172.217.3.5-32"))
			})
		})

		Context("onEpDelete", func() {
			It("should add the service's cluster IPs and approved external IPs into the svcRouteMap and then remove it for unsupported service type", func() {
				initRevision := rg.client.cacheRevision
				rg.onEPUpdate(nil, ep)
				Expect(rg.client.cacheRevision).To(Equal(initRevision + 3))
				Expect(rg.svcRouteMap["foo/bar"]).To(Equal(expectedSvcRouteMap))
				Expect(rg.routeAdvertisementRefCount["127.0.0.1/32"]).To(Equal(1))
				Expect(rg.routeAdvertisementRefCount["::1/128"]).To(Equal(1))
				Expect(rg.routeAdvertisementRefCount["172.217.3.5/32"]).To(Equal(1))
				Expect(rg.client.cache["/calico/staticroutes/172.217.3.5-32"]).To(Equal("172.217.3.5/32"))
				Expect(rg.client.cache["/calico/staticroutes/127.0.0.1-32"]).To(Equal("127.0.0.1/32"))
				Expect(rg.client.cache["/calico/staticroutesv6/::1-128"]).To(Equal("::1/128"))

				// set to unsupported service type
				svc.Spec.Type = v1.ServiceTypeExternalName
				rg.onEPUpdate(nil, ep)
				Expect(rg.client.cacheRevision).To(Equal(initRevision + 6))
				Expect(rg.svcRouteMap["foo/bar"]).ToNot(HaveKey("172.217.3.5/32"))
				Expect(rg.routeAdvertisementRefCount["127.0.0.1/32"]).To(Equal(0))
				Expect(rg.routeAdvertisementRefCount["::1/128"]).To(Equal(0))
				Expect(rg.routeAdvertisementRefCount["172.217.3.5/32"]).To(Equal(0))
				Expect(rg.client.cache).ToNot(HaveKey("/calico/staticroutes/172.217.3.5-32"))
				Expect(rg.client.cache).ToNot(HaveKey("/calico/staticroutes/127.0.0.1-32"))
				Expect(rg.client.cache).ToNot(HaveKey("/calico/staticroutesv6/::1-128"))
			})
		})

		Context("On BGP configuration changes from the syncer", func() {
			It("should only advertise external IPs within the configured ranges", func() {
				// Simulate an event from the syncer which sets the External IP range containing the first IP.
				rg.client.onExternalIPsUpdate([]string{externalIPRange1})
				rg.resyncKnownRoutes()

				// We should now advertise the first external IP, but not the second.
				Expect(rg.client.cache["/calico/staticroutes/"+externalIP1+"-32"]).To(Equal(externalIP1 + "/32"))
				Expect(rg.client.cache["/calico/staticroutes/"+externalIP2+"-32"]).To(BeEmpty())

				// It should also reject the full range into the data plane.
				Expect(rg.client.cache["/calico/rejectcidrs/"+strings.ReplaceAll(externalIPRange1, "/", "-")]).To(Equal(externalIPRange1))

				// Simulate an event from the syncer which updates to use the second range (removing the first)
				rg.client.onExternalIPsUpdate([]string{externalIPRange2})
				rg.resyncKnownRoutes()

				// We should now advertise the second external IP, but not the first.
				Expect(rg.client.cache["/calico/staticroutes/"+externalIP1+"-32"]).To(BeEmpty())
				Expect(rg.client.cache["/calico/staticroutes/"+externalIP2+"-32"]).To(Equal(externalIP2 + "/32"))

				// It should now allow the range in the data plane.
				Expect(rg.client.cache["/calico/rejectcidrs/"+strings.ReplaceAll(externalIPRange1, "/", "-")]).To(BeEmpty())
			})

			It("should not advertise cluster IPs unless a range is specified", func() {
				// Show cluster CIDRs are advertised.
				rg.onSvcAdd(svc)
				rg.onEPAdd(ep)
				Expect(rg.client.cache["/calico/staticroutes/127.0.0.1-32"]).To(Equal("127.0.0.1/32"))
				Expect(rg.client.cache["/calico/staticroutesv6/::1-128"]).To(Equal("::1/128"))

				// Withdraw the cluster CIDR from the syncer.
				rg.client.onClusterIPsUpdate([]string{})
				rg.resyncKnownRoutes()

				// We should no longer see cluster CIDRs to be advertised.
				Expect(rg.client.cache["/calico/staticroutes/127.0.0.1-32"]).To(BeEmpty())
				Expect(rg.client.cache["/calico/staticroutesv6/::1-128"]).To(BeEmpty())
			})

			// This test simulates a situation where BGPConfiguration has a /32 route that exactly matches
			// a Service route, resulting in two references to said route. It asserts that when the BGPConfiguration
			// is modified to remove that route, the service entry is still properly advertised.
			It("should handle duplicate prefixes BGPConfiguration and Service generated routes", func() {
				// Create a /32 CIDR for the services first externalIP.
				externalIPRangeSingle := fmt.Sprintf("%s/32", externalIP1)
				key := "/calico/staticroutes/" + externalIP1 + "-32"

				// Trigger programming of valid routes from the route generator for any known services.
				// We don't have a BGPConfiguration update yet, so we shouldn't receive any routes.
				By("Resyncing routes at start of test")
				rg.resyncKnownRoutes()
				Expect(rg.client.cache[key]).To(Equal(""))
				Expect(rg.client.programmedRouteRefCount[key]).To(Equal(0))

				// Simulate an event from the syncer which sets the External IP range containing only the service's externalIP.
				By("onExternalIPsUpdate to include /32 route")
				rg.client.onExternalIPsUpdate([]string{externalIPRangeSingle})

				// Expect that we don't advertise the /32 given to us via BGPConfiguration. We do that via route generator.
				Expect(rg.client.cache[key]).To(Equal(""))
				Expect(rg.client.programmedRouteRefCount[key]).To(Equal(0))

				// Trigger programming of routes from the route generator again. This time, the service's externalIP
				// will be allowed by BGPConfiguration and so it should be programmed.
				By("Resyncing routes from route generator")
				rg.resyncKnownRoutes()

				// Expect that we continue to advertise the route, but the refcount should indicate a route received
				// from only the RouteGenerator.
				Expect(rg.client.cache[key]).To(Equal(externalIP1 + "/32"))
				Expect(rg.client.programmedRouteRefCount[key]).To(Equal(1))

				// Simulate an event from the syncer which updates the range. It still includes the original IP,
				// to ensure we don't trigger the route generator to withdraw its route.
				By("onExternalIPsUpdate to include /16 route")
				rg.client.onExternalIPsUpdate([]string{externalIPRange1})
				rg.resyncKnownRoutes()

				// The route should still exist, since the RouteGenerator's route is still valid.
				Expect(rg.client.cache[key]).To(Equal(externalIP1 + "/32"))
				Expect(rg.client.programmedRouteRefCount[key]).To(Equal(1))

				// Revert the BGPConfiguration change.
				By("onExternalIPsUpdate to include /32 route again")
				rg.client.onExternalIPsUpdate([]string{externalIPRangeSingle})
				rg.resyncKnownRoutes()
				Expect(rg.client.programmedRouteRefCount[key]).To(Equal(1))

				// Now, remove both services (since both contribute externalIP). Route should not be programmed anymore.
				By("Deleting svc")
				rg.onSvcDelete(svc)
				By("Deleting svc2")
				rg.onSvcDelete(svc2)
				Expect(rg.client.cache[key]).To(Equal(""))
				Expect(rg.client.programmedRouteRefCount[key]).To(Equal(0))

				// Finally, remove BGPConfiguration. It should withdraw the route
				// and delete the refcount entry.
				rg.client.onExternalIPsUpdate([]string{})
				Expect(rg.client.cache).NotTo(HaveKey(key))
				Expect(rg.client.programmedRouteRefCount).NotTo(HaveKey(key))
			})

			// This test simulates a situation where BGPConfiguration has a /32 route that exactly matches
			// a LoadBalancer with ExternalTrafficPolicy set to Local. The route should only be advertised
			// when the Service is created, and not when the BGPConfiguration is created.
			It("should handle /32 routes for LoadBalancerIPs", func() {
				// BeforeEach creates a service. Remove it before the test, since we want to start
				// this test without the service in place. svc3 is a LoadBalancer service with external traffic
				// policy of Local.
				err := rg.epIndexer.Delete(ep3)
				Expect(err).NotTo(HaveOccurred())
				err = rg.svcIndexer.Delete(svc3)
				Expect(err).NotTo(HaveOccurred())

				// The key we expect to be used for the LB IP.
				key := "/calico/staticroutes/" + loadBalancerIP1 + "-32"

				// Trigger programming of valid routes from the route generator for any known services.
				// We don't have a BGPConfiguration update or services yet, so we shouldn't receive any routes.
				By("Resyncing routes at start of test")
				rg.resyncKnownRoutes()
				Expect(rg.client.cache[key]).To(Equal(""))
				Expect(rg.client.programmedRouteRefCount[key]).To(Equal(0))

				// Simulate an event from the syncer which sets the LoadBalancer IP range containing only the service's loadBalancerIP.
				// We use a /32 route to trigger the situation under test.
				loadBalancerIPRangeSingle := fmt.Sprintf("%s/32", loadBalancerIP1)
				By("onLoadBalancerIPsUpdate to include /32 route")
				rg.client.onLoadBalancerIPsUpdate([]string{loadBalancerIPRangeSingle})
				rg.resyncKnownRoutes()

				// No routes should be advertised yet.
				Expect(rg.client.cache[key]).To(Equal(""))
				Expect(rg.client.programmedRouteRefCount[key]).To(Equal(0))

				// Now add the service.
				err = rg.epIndexer.Add(ep3)
				Expect(err).NotTo(HaveOccurred())
				err = rg.svcIndexer.Add(svc3)
				Expect(err).NotTo(HaveOccurred())

				// Expect that we advertise the /32 LB IP from the Service.
				By("Resyncing routes from route generator")
				rg.resyncKnownRoutes()
				Expect(rg.client.cache[key]).To(Equal(loadBalancerIP1 + "/32"))
				Expect(rg.client.programmedRouteRefCount[key]).To(Equal(1))

				// Finally, remove BGPConfiguration. It should withdraw the route
				// and delete the refcount entry.
				rg.client.onLoadBalancerIPsUpdate([]string{})
				rg.resyncKnownRoutes()
				Expect(rg.client.cache).NotTo(HaveKey(key))
				Expect(rg.client.programmedRouteRefCount).NotTo(HaveKey(key))
			})

			// This test simulates a situation where BGPConfiguration has a /32 route that exactly matches
			// externalIP of a LoadBalancer service with ExternalTrafficPolicy set to Local. The route should only be advertised
			// when the Service is created, and not when the BGPConfiguration is created.
			It("should handle /32 routes for externalIPs", func() {
				// BeforeEach creates a service. Remove it before the test, since we want to start
				// this test without the service in place. svc4 is a LoadBalancer service with external traffic
				// policy of Local and an externalIP.
				err := rg.epIndexer.Delete(ep4)
				Expect(err).NotTo(HaveOccurred())
				err = rg.svcIndexer.Delete(svc4)
				Expect(err).NotTo(HaveOccurred())

				// The key we expect to be used for the LB IP.
				key := "/calico/staticroutes/" + externalIP3 + "-32"

				// Trigger programming of valid routes from the route generator for any known services.
				// We don't have a BGPConfiguration update or services yet, so we shouldn't receive any routes.
				By("Resyncing routes at start of test")
				rg.resyncKnownRoutes()
				Expect(rg.client.cache[key]).To(Equal(""))
				Expect(rg.client.programmedRouteRefCount[key]).To(Equal(0))

				// Simulate an event from the syncer which sets the external IP range containing only the service's externalIP.
				// We use a /32 route to trigger the situation under test.
				externalIPRangeSingle := fmt.Sprintf("%s/32", externalIP3)
				By("onExternalIPsUpdate to include /32 route")
				rg.client.onExternalIPsUpdate([]string{externalIPRangeSingle})
				rg.resyncKnownRoutes()

				// No routes should be advertised yet.
				Expect(rg.client.cache[key]).To(Equal(""))
				Expect(rg.client.programmedRouteRefCount[key]).To(Equal(0))

				// Now add the service.
				err = rg.epIndexer.Add(ep4)
				Expect(err).NotTo(HaveOccurred())
				err = rg.svcIndexer.Add(svc4)
				Expect(err).NotTo(HaveOccurred())

				// Expect that we advertise the /32 external IP from the Service.
				By("Resyncing routes from route generator")
				rg.resyncKnownRoutes()
				Expect(rg.client.cache[key]).To(Equal(externalIP3 + "/32"))
				Expect(rg.client.programmedRouteRefCount[key]).To(Equal(1))

				// Finally, remove BGPConfiguration. It should withdraw the route
				// and delete the refcount entry.
				rg.client.onExternalIPsUpdate([]string{})
				rg.resyncKnownRoutes()
				Expect(rg.client.cache).NotTo(HaveKey(key))
				Expect(rg.client.programmedRouteRefCount).NotTo(HaveKey(key))
			})
		})
	})
})

var _ = Describe("Update BGP Config Cache", func() {
	c := &client{cache: make(map[string]string)}

	It("should update cache value when IgnoredInterfaces is set in BGPConfiguration", func() {
		By("No value cached")
		Expect(c.cache["/calico/bgp/v1/global/ignored_interfaces"]).To(BeEmpty())

		By("After updating")
		res := &apiv3.BGPConfiguration{
			Spec: apiv3.BGPConfigurationSpec{
				IgnoredInterfaces: []string{"iface-1", "iface-2"},
			},
		}
		c.getIgnoredInterfacesKVPair(res, model.GlobalBGPConfigKey{})
		Expect(c.cache["/calico/bgp/v1/global/ignored_interfaces"]).To(Equal("iface-1,iface-2"))
	})
})

var _ = Describe("Service Load Balancer Aggregation", func() {
	var rg *routeGenerator

	BeforeEach(func() {
		rg = &routeGenerator{}
	})

	Describe("advertiseThisService with ServiceLoadBalancerAggregation", func() {
		var mockClient *client

		BeforeEach(func() {
			mockClient = &client{
				cache:                    make(map[string]string),
				syncedOnce:               true,
				clusterCIDRs:             []string{"10.0.0.0/16"},
				programmedRouteRefCount:  make(map[string]int),
				ExternalIPRouteIndex:     NewRouteIndex(),
				ClusterIPRouteIndex:      NewRouteIndex(),
				LoadBalancerIPRouteIndex: NewRouteIndex(),
			}
			rg.client = mockClient
			rg.nodeName = "test-node"
		})

		Context("when ServiceLoadBalancerAggregation is Enabled", func() {
			BeforeEach(func() {
				mockClient.serviceLoadBalancerAggregation = apiv3.ServiceLoadBalancerAggregationEnabled
			})

			It("should skip Cluster services when aggregation is enabled", func() {
				svc := &v1.Service{
					ObjectMeta: metav1.ObjectMeta{Name: "test-svc", Namespace: "default"},
					Spec: v1.ServiceSpec{
						Type:                  v1.ServiceTypeLoadBalancer,
						ClusterIP:             "10.0.0.1",
						ExternalTrafficPolicy: v1.ServiceExternalTrafficPolicyTypeCluster,
					},
				}
				ep := &discoveryv1.EndpointSlice{
					ObjectMeta: metav1.ObjectMeta{Name: "test-svc", Namespace: "default"},
					Endpoints: []discoveryv1.Endpoint{
						{
							Addresses: []string{"10.0.0.2"},
						},
					},
				}

				result := rg.advertiseThisService(svc, []*discoveryv1.EndpointSlice{ep})
				Expect(result).To(BeFalse())
			})

			It("should still advertise Local services when aggregation is enabled", func() {
				svc := &v1.Service{
					ObjectMeta: metav1.ObjectMeta{Name: "test-svc", Namespace: "default"},
					Spec: v1.ServiceSpec{
						Type:                  v1.ServiceTypeLoadBalancer,
						ClusterIP:             "10.0.0.1",
						ExternalTrafficPolicy: v1.ServiceExternalTrafficPolicyTypeLocal,
						IPFamilies:            []v1.IPFamily{v1.IPv4Protocol},
					},
				}
				ep := &discoveryv1.EndpointSlice{
					ObjectMeta:  metav1.ObjectMeta{Name: "test-svc", Namespace: "default"},
					AddressType: discoveryv1.AddressType(v1.IPv4Protocol),
					Endpoints: []discoveryv1.Endpoint{
						{
							Addresses: []string{"10.0.0.2"},
							NodeName:  &rg.nodeName,
						},
					},
				}

				result := rg.advertiseThisService(svc, []*discoveryv1.EndpointSlice{ep})
				Expect(result).To(BeTrue())
			})
		})

		Context("when ServiceLoadBalancerAggregation is Disabled", func() {
			BeforeEach(func() {
				mockClient.serviceLoadBalancerAggregation = apiv3.ServiceLoadBalancerAggregationDisabled
			})

			It("should advertise Cluster services when aggregation is disabled", func() {
				svc := &v1.Service{
					ObjectMeta: metav1.ObjectMeta{Name: "test-svc", Namespace: "default"},
					Spec: v1.ServiceSpec{
						Type:                  v1.ServiceTypeLoadBalancer,
						ClusterIP:             "10.0.0.1",
						ExternalTrafficPolicy: v1.ServiceExternalTrafficPolicyTypeCluster,
						IPFamilies:            []v1.IPFamily{v1.IPv4Protocol},
					},
				}
				ep := &discoveryv1.EndpointSlice{
					ObjectMeta:  metav1.ObjectMeta{Name: "test-svc", Namespace: "default", Labels: map[string]string{"kubernetes.io/service-name": "test-svc"}},
					AddressType: discoveryv1.AddressType(v1.IPv4Protocol),
					Endpoints: []discoveryv1.Endpoint{
						{
							Addresses: []string{"10.0.0.2"},
						},
					},
				}

				result := rg.advertiseThisService(svc, []*discoveryv1.EndpointSlice{ep})
				Expect(result).To(BeTrue())
			})

			It("should not advertise Cluster services without endpoints", func() {
				svc := &v1.Service{
					ObjectMeta: metav1.ObjectMeta{Name: "test-svc", Namespace: "default"},
					Spec: v1.ServiceSpec{
						Type:                  v1.ServiceTypeLoadBalancer,
						ClusterIP:             "10.0.0.1",
						ExternalTrafficPolicy: v1.ServiceExternalTrafficPolicyTypeCluster,
						IPFamilies:            []v1.IPFamily{v1.IPv4Protocol},
					},
				}
				ep := &discoveryv1.EndpointSlice{
					ObjectMeta:  metav1.ObjectMeta{Name: "test-svc", Namespace: "default", Labels: map[string]string{"kubernetes.io/service-name": "test-svc"}},
					AddressType: discoveryv1.AddressType(v1.IPv4Protocol),
					Endpoints:   []discoveryv1.Endpoint{},
				}

				result := rg.advertiseThisService(svc, []*discoveryv1.EndpointSlice{ep})
				Expect(result).To(BeFalse())
			})
		})

		Context("IP version compatibility", func() {
			BeforeEach(func() {
				mockClient.serviceLoadBalancerAggregation = apiv3.ServiceLoadBalancerAggregationDisabled
			})

			It("should not advertise IPv4 service with IPv6 endpoints", func() {
				svc := &v1.Service{
					ObjectMeta: metav1.ObjectMeta{Name: "test-svc", Namespace: "default"},
					Spec: v1.ServiceSpec{
						Type:                  v1.ServiceTypeLoadBalancer,
						ClusterIP:             "10.0.0.1", // IPv4
						ExternalTrafficPolicy: v1.ServiceExternalTrafficPolicyTypeCluster,
						IPFamilies:            []v1.IPFamily{v1.IPv4Protocol},
					},
				}
				ep := &discoveryv1.EndpointSlice{
					ObjectMeta:  metav1.ObjectMeta{Name: "test-svc", Namespace: "default", Labels: map[string]string{"kubernetes.io/service-name": "test-svc"}},
					AddressType: discoveryv1.AddressType(v1.IPv6Protocol),
					Endpoints: []discoveryv1.Endpoint{
						{
							Addresses: []string{"2001:db8::1"}, // IPv6
						},
					},
				}

				result := rg.advertiseThisService(svc, []*discoveryv1.EndpointSlice{ep})
				Expect(result).To(BeFalse())
			})

			It("should advertise IPv6 service with IPv6 endpoints", func() {
				svc := &v1.Service{
					ObjectMeta: metav1.ObjectMeta{Name: "test-svc", Namespace: "default"},
					Spec: v1.ServiceSpec{
						Type:                  v1.ServiceTypeLoadBalancer,
						ClusterIP:             "2001:db8::1", // IPv6
						ExternalTrafficPolicy: v1.ServiceExternalTrafficPolicyTypeCluster,
						IPFamilies:            []v1.IPFamily{v1.IPv6Protocol},
					},
				}
				ep := &discoveryv1.EndpointSlice{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-svc",
						Namespace: "default",
						Labels:    map[string]string{"kubernetes.io/service-name": "test-svc"},
					},
					AddressType: discoveryv1.AddressType(v1.IPv6Protocol),
					Endpoints: []discoveryv1.Endpoint{
						{
							Addresses: []string{"2001:db8::2"}, // IPv6
						},
					},
				}

				result := rg.advertiseThisService(svc, []*discoveryv1.EndpointSlice{ep})
				Expect(result).To(BeTrue())
			})

			It("should advertise dual-stuck service when get IPv4 endpointSlice", func() {
				svc := &v1.Service{
					ObjectMeta: metav1.ObjectMeta{Name: "test-svc", Namespace: "default"},
					Spec: v1.ServiceSpec{
						Type:                  v1.ServiceTypeLoadBalancer,
						ClusterIP:             "2001:db8::1",
						ClusterIPs:            []string{"2001:db8::1", "1.1.1.1"},
						ExternalTrafficPolicy: v1.ServiceExternalTrafficPolicyTypeCluster,
						IPFamilies:            []v1.IPFamily{v1.IPv6Protocol, v1.IPv4Protocol},
					},
				}
				ep := &discoveryv1.EndpointSlice{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-svc",
						Namespace: "default",
						Labels:    map[string]string{"kubernetes.io/service-name": "test-svc"},
					},
					AddressType: discoveryv1.AddressType(v1.IPv4Protocol),
					Endpoints: []discoveryv1.Endpoint{
						{
							Addresses: []string{"10.10.10.10"}, // IPv6
						},
					},
				}

				result := rg.advertiseThisService(svc, []*discoveryv1.EndpointSlice{ep})
				Expect(result).To(BeTrue())
			})

			It("should advertise dual-stuck service when get IPv6 endpointSlice", func() {
				svc := &v1.Service{
					ObjectMeta: metav1.ObjectMeta{Name: "test-svc", Namespace: "default"},
					Spec: v1.ServiceSpec{
						Type:                  v1.ServiceTypeLoadBalancer,
						ClusterIP:             "2001:db8::1",
						ClusterIPs:            []string{"2001:db8::1", "1.1.1.1"},
						ExternalTrafficPolicy: v1.ServiceExternalTrafficPolicyTypeCluster,
						IPFamilies:            []v1.IPFamily{v1.IPv6Protocol, v1.IPv4Protocol},
					},
				}
				ep := &discoveryv1.EndpointSlice{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-svc",
						Namespace: "default",
						Labels:    map[string]string{"kubernetes.io/service-name": "test-svc"},
					},
					AddressType: discoveryv1.AddressType(v1.IPv6Protocol),
					Endpoints: []discoveryv1.Endpoint{
						{
							Addresses: []string{"2001:db8::2"}, // IPv6
						},
					},
				}

				result := rg.advertiseThisService(svc, []*discoveryv1.EndpointSlice{ep})
				Expect(result).To(BeTrue())
			})
		})
	})

})
