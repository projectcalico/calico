package calico

import (
	"fmt"
	"net"
	"strings"
	"sync"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
)

const (
	// Range and specific IP for external IP test.
	externalIPRange1 = "45.12.0.0/16"
	externalIP1      = "45.12.70.5"

	// Range and specific IP for external IP test.
	externalIPRange2 = "172.217.3.5/32"
	externalIP2      = "172.217.3.5"
)

func addEndpointSubset(ep *v1.Endpoints, nodename string) {
	ep.Subsets = append(ep.Subsets, v1.EndpointSubset{
		Addresses: []v1.EndpointAddress{
			v1.EndpointAddress{
				NodeName: &nodename}}})
}

func buildSimpleService() (svc *v1.Service, ep *v1.Endpoints) {
	meta := metav1.ObjectMeta{Namespace: "foo", Name: "bar"}
	svc = &v1.Service{
		ObjectMeta: meta,
		Spec: v1.ServiceSpec{
			Type:                  v1.ServiceTypeClusterIP,
			ClusterIP:             "127.0.0.1",
			ExternalTrafficPolicy: v1.ServiceExternalTrafficPolicyTypeLocal,
			ExternalIPs:           []string{externalIP1, externalIP2},
		}}
	ep = &v1.Endpoints{
		ObjectMeta: meta,
	}
	return
}

func buildSimpleService2() (svc *v1.Service, ep *v1.Endpoints) {
	meta := metav1.ObjectMeta{Namespace: "foo", Name: "rem"}
	svc = &v1.Service{
		ObjectMeta: meta,
		Spec: v1.ServiceSpec{
			Type:                  v1.ServiceTypeClusterIP,
			ClusterIP:             "127.0.0.5",
			ExternalTrafficPolicy: v1.ServiceExternalTrafficPolicyTypeLocal,
			ExternalIPs:           []string{externalIP1, externalIP2},
		}}
	ep = &v1.Endpoints{
		ObjectMeta: meta,
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
		expectedSvcRouteMap["172.217.3.5/32"] = true

		expectedSvc2RouteMap = make(map[string]bool)
		expectedSvc2RouteMap["127.0.0.5/32"] = true
		expectedSvc2RouteMap["172.217.3.5/32"] = true

		rg = &routeGenerator{
			nodeName:                "foobar",
			svcIndexer:              cache.NewIndexer(cache.MetaNamespaceKeyFunc, nil),
			epIndexer:               cache.NewIndexer(cache.MetaNamespaceKeyFunc, nil),
			svcRouteMap:             make(map[string]map[string]bool),
			routeAdvertisementCount: make(map[string]int),
			client: &client{
				cache:        make(map[string]string),
				syncedOnce:   true,
				clusterCIDRs: []string{"10.0.0.0/16"},
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
			Expect(fetchedEp.ObjectMeta).To(Equal(ep.ObjectMeta))
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
				addEndpointSubset(ep, rg.nodeName)

				err := rg.epIndexer.Add(ep)
				Expect(err).NotTo(HaveOccurred())
				rg.setRouteForSvc(svc, nil)
				fmt.Fprintln(GinkgoWriter, rg.svcRouteMap)
				Expect(rg.svcRouteMap["foo/bar"]).To(Equal(expectedSvcRouteMap))
				rg.unsetRouteForSvc(ep)
				Expect(rg.svcRouteMap["foo/bar"]).To(BeEmpty())
			})
		})
		Context("svc = nil, ep = ep", func() {
			It("should set an unset routes for a service", func() {
				svc, ep := buildSimpleService()
				addEndpointSubset(ep, rg.nodeName)

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
			svc, svc2 *v1.Service
			ep, ep2   *v1.Endpoints
		)

		BeforeEach(func() {
			svc, ep = buildSimpleService()
			svc2, ep2 = buildSimpleService2()

			addEndpointSubset(ep, rg.nodeName)
			addEndpointSubset(ep2, rg.nodeName)
			err := rg.epIndexer.Add(ep)
			Expect(err).NotTo(HaveOccurred())
			err = rg.epIndexer.Add(ep2)
			Expect(err).NotTo(HaveOccurred())
			err = rg.svcIndexer.Add(svc)
			Expect(err).NotTo(HaveOccurred())
			err = rg.svcIndexer.Add(svc2)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should remove advertised IPs when endpoints are deleted", func() {
			// Trigger a service add - it should update the cache with its route.
			initRevision := rg.client.cacheRevision
			rg.onSvcAdd(svc)
			Expect(rg.client.cacheRevision).To(Equal(initRevision + 2))
			Expect(rg.svcRouteMap["foo/bar"]).To(Equal(expectedSvcRouteMap))
			Expect(rg.routeAdvertisementCount["127.0.0.1/32"]).To(Equal(1))
			Expect(rg.routeAdvertisementCount["172.217.3.5/32"]).To(Equal(1))
			Expect(rg.client.cache["/calico/staticroutes/127.0.0.1-32"]).To(Equal("127.0.0.1/32"))
			Expect(rg.client.cache["/calico/staticroutes/172.217.3.5-32"]).To(Equal("172.217.3.5/32"))

			// Simulate the remove of the local endpoint. It should withdraw the routes.
			ep.Subsets = []v1.EndpointSubset{}
			err := rg.epIndexer.Add(ep)
			Expect(err).NotTo(HaveOccurred())
			rg.onEPAdd(ep)
			Expect(rg.client.cacheRevision).To(Equal(initRevision + 4))
			Expect(rg.svcRouteMap["foo/bar"]).To(BeEmpty())
			Expect(rg.routeAdvertisementCount["127.0.0.1/32"]).To(Equal(0))
			Expect(rg.routeAdvertisementCount["172.217.3.5/32"]).To(Equal(0))
			Expect(rg.client.cache["/calico/staticroutes/127.0.0.1-32"]).To(Equal(""))
			Expect(rg.client.cache["/calico/staticroutes/172.217.3.5-32"]).To(Equal(""))
			Expect(rg.client.cache).To(Equal(map[string]string{}))

			// Add the endpoint back with an IPv6 address.  The service's cluster IP
			// should remain non-advertised.
			ep.Subsets = []v1.EndpointSubset{{
				Addresses: []v1.EndpointAddress{{
					IP:       "fd5f:1234::3",
					NodeName: &rg.nodeName,
				}},
			}}
			err = rg.epIndexer.Add(ep)
			Expect(err).NotTo(HaveOccurred())
			rg.onEPAdd(ep)
			Expect(rg.client.cacheRevision).To(Equal(initRevision + 4))
			Expect(rg.svcRouteMap["foo/bar"]).To(BeEmpty())
			Expect(rg.routeAdvertisementCount["127.0.0.1/32"]).To(Equal(0))
			Expect(rg.routeAdvertisementCount["172.217.3.5/32"]).To(Equal(0))
			Expect(rg.client.cache["/calico/staticroutes/127.0.0.1-32"]).To(Equal(""))
			Expect(rg.client.cache["/calico/staticroutes/172.217.3.5-32"]).To(Equal(""))
			Expect(rg.client.cache).To(Equal(map[string]string{}))

			// Add the endpoint again with an IPv4 address.  The service's cluster IP
			// should now be advertised.
			ep.Subsets = []v1.EndpointSubset{{
				Addresses: []v1.EndpointAddress{{
					IP:       "10.96.0.45",
					NodeName: &rg.nodeName,
				}},
			}}
			err = rg.epIndexer.Add(ep)
			Expect(err).NotTo(HaveOccurred())
			rg.onEPAdd(ep)
			Expect(rg.client.cacheRevision).To(Equal(initRevision + 6))
			Expect(rg.svcRouteMap["foo/bar"]).To(Equal(expectedSvcRouteMap))
			Expect(rg.routeAdvertisementCount["127.0.0.1/32"]).To(Equal(1))
			Expect(rg.routeAdvertisementCount["172.217.3.5/32"]).To(Equal(1))
			Expect(rg.client.cache["/calico/staticroutes/127.0.0.1-32"]).To(Equal("127.0.0.1/32"))
			Expect(rg.client.cache["/calico/staticroutes/172.217.3.5-32"]).To(Equal("172.217.3.5/32"))
		})

		Context("onSvc[Add|Delete]", func() {
			It("should add the service's cluster IP and whitelisted external IPs into the svcRouteMap", func() {
				// add
				initRevision := rg.client.cacheRevision
				rg.onSvcAdd(svc)
				Expect(rg.client.cacheRevision).To(Equal(initRevision + 2))
				Expect(rg.svcRouteMap["foo/bar"]).To(Equal(expectedSvcRouteMap))
				Expect(rg.routeAdvertisementCount["127.0.0.1/32"]).To(Equal(1))
				Expect(rg.routeAdvertisementCount["172.217.3.5/32"]).To(Equal(1))
				Expect(rg.client.cache["/calico/staticroutes/127.0.0.1-32"]).To(Equal("127.0.0.1/32"))
				Expect(rg.client.cache["/calico/staticroutes/172.217.3.5-32"]).To(Equal("172.217.3.5/32"))

				// delete
				rg.onSvcDelete(svc)
				Expect(rg.client.cacheRevision).To(Equal(initRevision + 4))
				Expect(rg.svcRouteMap["foo/bar"]).ToNot(HaveKey("172.217.3.5/32"))
				Expect(rg.svcRouteMap["foo/bar"]).ToNot(HaveKey("127.0.0.1/32"))
				Expect(rg.routeAdvertisementCount["127.0.0.1/32"]).To(Equal(0))
				Expect(rg.routeAdvertisementCount["172.217.3.5/32"]).To(Equal(0))
				Expect(rg.client.cache).ToNot(HaveKey("/calico/staticroutes/172.217.3.5-32"))
				Expect(rg.client.cache).ToNot(HaveKey("/calico/staticroutes/127.0.0.1-32"))
			})

			It("should handle two services advertising the same route correctly, only advertising the route once and only withdrawing the route when both services are removed.", func() {
				// add both services and make sure the duplicate route is counted twice
				initRevision := rg.client.cacheRevision
				rg.onSvcAdd(svc)
				rg.onSvcAdd(svc2)
				Expect(rg.client.cacheRevision).To(Equal(initRevision + 4))
				Expect(rg.svcRouteMap["foo/bar"]).To(Equal(expectedSvcRouteMap))
				Expect(rg.svcRouteMap["foo/rem"]).To(Equal(expectedSvc2RouteMap))
				Expect(rg.routeAdvertisementCount["127.0.0.1/32"]).To(Equal(1))
				Expect(rg.routeAdvertisementCount["127.0.0.5/32"]).To(Equal(1))
				Expect(rg.routeAdvertisementCount["172.217.3.5/32"]).To(Equal(2))
				Expect(rg.client.cache["/calico/staticroutes/127.0.0.1-32"]).To(Equal("127.0.0.1/32"))
				Expect(rg.client.cache["/calico/staticroutes/127.0.0.5-32"]).To(Equal("127.0.0.5/32"))
				Expect(rg.client.cache["/calico/staticroutes/172.217.3.5-32"]).To(Equal("172.217.3.5/32"))

				// delete one of the services, and make sure the duplicate route is still advertised
				// and we handle the counting logic correctly
				rg.onSvcDelete(svc2)
				Expect(rg.client.cacheRevision).To(Equal(initRevision + 5))
				Expect(rg.routeAdvertisementCount["127.0.0.1/32"]).To(Equal(1))
				Expect(rg.routeAdvertisementCount["127.0.0.5/32"]).To(Equal(0))
				Expect(rg.routeAdvertisementCount["172.217.3.5/32"]).To(Equal(1))
				Expect(rg.svcRouteMap["foo/bar"]).To(Equal(expectedSvcRouteMap))
				Expect(rg.svcRouteMap["foo/rem"]).ToNot(HaveKey("127.0.0.5/32"))
				Expect(rg.svcRouteMap["foo/rem"]).ToNot(HaveKey("172.217.3.5/32"))
				Expect(rg.client.cache["/calico/staticroutes/127.0.0.1-32"]).To(Equal("127.0.0.1/32"))
				Expect(rg.client.cache["/calico/staticroutes/172.217.3.5-32"]).To(Equal("172.217.3.5/32"))
				Expect(rg.client.cache).ToNot(HaveKey("/calico/staticroutes/127.0.0.5-32"))

				// delete the other service and check that both routes are withdrawn and their counts are 0
				rg.onSvcDelete(svc)
				Expect(rg.client.cacheRevision).To(Equal(initRevision + 7))
				Expect(rg.svcRouteMap["foo/bar"]).ToNot(HaveKey("172.217.3.5/32"))
				Expect(rg.svcRouteMap["foo/bar"]).ToNot(HaveKey("127.0.0.1/32"))
				Expect(rg.routeAdvertisementCount["127.0.0.1/32"]).To(Equal(0))
				Expect(rg.routeAdvertisementCount["172.217.3.5/32"]).To(Equal(0))
				Expect(rg.client.cache).ToNot(HaveKey("/calico/staticroutes/172.217.3.5-32"))
				Expect(rg.client.cache).ToNot(HaveKey("/calico/staticroutes/127.0.0.1-32"))
			})
		})

		Context("onSvcUpdate", func() {
			It("should add the service's cluster IP and whitelisted external IPs into the svcRouteMap and then remove them for unsupported service type", func() {
				initRevision := rg.client.cacheRevision
				rg.onSvcUpdate(nil, svc)
				Expect(rg.client.cacheRevision).To(Equal(initRevision + 2))
				Expect(rg.svcRouteMap["foo/bar"]).To(Equal(expectedSvcRouteMap))
				Expect(rg.routeAdvertisementCount["127.0.0.1/32"]).To(Equal(1))
				Expect(rg.routeAdvertisementCount["172.217.3.5/32"]).To(Equal(1))
				Expect(rg.client.cache["/calico/staticroutes/127.0.0.1-32"]).To(Equal("127.0.0.1/32"))
				Expect(rg.client.cache["/calico/staticroutes/172.217.3.5-32"]).To(Equal("172.217.3.5/32"))

				// set to unsupported service type
				svc.Spec.Type = v1.ServiceTypeExternalName
				rg.onSvcUpdate(nil, svc)
				Expect(rg.client.cacheRevision).To(Equal(initRevision + 4))
				Expect(rg.svcRouteMap["foo/bar"]).ToNot(HaveKey("172.217.3.5/32"))
				Expect(rg.svcRouteMap["foo/bar"]).ToNot(HaveKey("127.0.0.1-32"))
				Expect(rg.routeAdvertisementCount["127.0.0.1/32"]).To(Equal(0))
				Expect(rg.routeAdvertisementCount["172.217.3.5/32"]).To(Equal(0))
				Expect(rg.client.cache).ToNot(HaveKey("/calico/staticroutes/172.217.3.5-32"))
				Expect(rg.client.cache).ToNot(HaveKey("/calico/staticroutes/127.0.0.1-32"))
			})
		})

		Context("onEp[Add|Delete]", func() {
			It("should add the service's cluster IP and whitelisted external IPs into the svcRouteMap", func() {
				// add
				initRevision := rg.client.cacheRevision
				rg.onEPAdd(ep)
				Expect(rg.client.cacheRevision).To(Equal(initRevision + 2))
				Expect(rg.svcRouteMap["foo/bar"]).To(Equal(expectedSvcRouteMap))
				Expect(rg.routeAdvertisementCount["127.0.0.1/32"]).To(Equal(1))
				Expect(rg.routeAdvertisementCount["172.217.3.5/32"]).To(Equal(1))
				Expect(rg.client.cache["/calico/staticroutes/127.0.0.1-32"]).To(Equal("127.0.0.1/32"))
				Expect(rg.client.cache["/calico/staticroutes/172.217.3.5-32"]).To(Equal("172.217.3.5/32"))

				// delete
				rg.onEPDelete(ep)
				Expect(rg.client.cacheRevision).To(Equal(initRevision + 4))
				Expect(rg.svcRouteMap).ToNot(HaveKey("foo/bar"))
				Expect(rg.routeAdvertisementCount["127.0.0.1/32"]).To(Equal(0))
				Expect(rg.routeAdvertisementCount["172.217.3.5/32"]).To(Equal(0))
				Expect(rg.client.cache).ToNot(HaveKey("/calico/staticroutes/127.0.0.1-32"))
				Expect(rg.client.cache).ToNot(HaveKey("/calico/staticroutes/172.217.3.5-32"))
			})
		})

		Context("onEpDelete", func() {
			It("should add the service's cluster IP and whitelisted external IPs into the svcRouteMap and then remove it for unsupported service type", func() {
				initRevision := rg.client.cacheRevision
				rg.onEPUpdate(nil, ep)
				Expect(rg.client.cacheRevision).To(Equal(initRevision + 2))
				Expect(rg.svcRouteMap["foo/bar"]).To(Equal(expectedSvcRouteMap))
				Expect(rg.routeAdvertisementCount["127.0.0.1/32"]).To(Equal(1))
				Expect(rg.routeAdvertisementCount["172.217.3.5/32"]).To(Equal(1))
				Expect(rg.client.cache["/calico/staticroutes/172.217.3.5-32"]).To(Equal("172.217.3.5/32"))
				Expect(rg.client.cache["/calico/staticroutes/127.0.0.1-32"]).To(Equal("127.0.0.1/32"))

				// set to unsupported service type
				svc.Spec.Type = v1.ServiceTypeExternalName
				rg.onEPUpdate(nil, ep)
				Expect(rg.client.cacheRevision).To(Equal(initRevision + 4))
				Expect(rg.svcRouteMap["foo/bar"]).ToNot(HaveKey("172.217.3.5/32"))
				Expect(rg.routeAdvertisementCount["127.0.0.1/32"]).To(Equal(0))
				Expect(rg.routeAdvertisementCount["172.217.3.5/32"]).To(Equal(0))
				Expect(rg.client.cache).ToNot(HaveKey("/calico/staticroutes/172.217.3.5-32"))
				Expect(rg.client.cache).ToNot(HaveKey("/calico/staticroutes/127.0.0.1-32"))
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
				Expect(rg.client.cache["/calico/rejectcidrs/"+strings.Replace(externalIPRange1, "/", "-", -1)]).To(Equal(externalIPRange1))

				// Simulate an event from the syncer which updates to use the second range (removing the first)
				rg.client.onExternalIPsUpdate([]string{externalIPRange2})
				rg.resyncKnownRoutes()

				// We should now advertise the second external IP, but not the first.
				Expect(rg.client.cache["/calico/staticroutes/"+externalIP1+"-32"]).To(BeEmpty())
				Expect(rg.client.cache["/calico/staticroutes/"+externalIP2+"-32"]).To(Equal(externalIP2 + "/32"))

				// It should now allow the range in the data plane.
				Expect(rg.client.cache["/calico/rejectcidrs/"+strings.Replace(externalIPRange1, "/", "-", -1)]).To(BeEmpty())
			})

			It("should not advertise cluster IPs unless a range is specified", func() {
				// Show cluster CIDRs are advertised.
				rg.onSvcAdd(svc)
				rg.onEPAdd(ep)
				Expect(rg.client.cache["/calico/staticroutes/127.0.0.1-32"]).To(Equal("127.0.0.1/32"))

				// Withdraw the cluster CIDR from the syncer.
				rg.client.onClusterIPsUpdate([]string{})
				rg.resyncKnownRoutes()

				// We should no longer see cluster CIDRs to be advertised.
				Expect(rg.client.cache["/calico/staticroutes/127.0.0.1-32"]).To(BeEmpty())
			})
		})
	})
})
