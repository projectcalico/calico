package calico

import (
	"sync"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
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
		}}
	ep = &v1.Endpoints{
		ObjectMeta: meta,
	}
	return
}

var _ = Describe("RouteGenerator", func() {
	var rg *routeGenerator
	BeforeEach(func() {
		rg = &routeGenerator{
			nodeName:    "foobar",
			svcIndexer:  cache.NewIndexer(cache.MetaNamespaceKeyFunc, nil),
			epIndexer:   cache.NewIndexer(cache.MetaNamespaceKeyFunc, nil),
			svcRouteMap: make(map[string]string),
			client: &client{
				cache:  make(map[string]string),
				synced: true,
			},
		}
		rg.client.watcherCond = sync.NewCond(&rg.client.cacheLock)
	})
	Describe("getServiceForEndpoints", func() {
		It("should get corresponding service for endpoints", func() {
			// getServiceForEndpoints
			svc, ep := buildSimpleService()
			rg.svcIndexer.Add(svc)
			fetchedSvc, key := rg.getServiceForEndpoints(ep)
			Expect(fetchedSvc.ObjectMeta).To(Equal(svc.ObjectMeta))
			Expect(key).To(Equal("foo/bar"))
		})
	})
	Describe("getEndpointsForService", func() {
		It("should get corresponding endpoints for service", func() {
			// getEndpointsForService
			svc, ep := buildSimpleService()
			rg.epIndexer.Add(ep)
			fetchedEp, key := rg.getEndpointsForService(svc)
			Expect(fetchedEp.ObjectMeta).To(Equal(ep.ObjectMeta))
			Expect(key).To(Equal("foo/bar"))
		})
	})

	Describe("(un)setRouteForSvc", func() {
		Context("svc = svc, ep = nil", func() {
			It("should set an unset routes for a service", func() {
				svc, ep := buildSimpleService()
				addEndpointSubset(ep, rg.nodeName)

				rg.epIndexer.Add(ep)
				rg.setRouteForSvc(svc, nil)
				Expect(rg.svcRouteMap["foo/bar"]).To(Equal("127.0.0.1/32"))
				rg.unsetRouteForSvc(ep)
				Expect(rg.svcRouteMap["foo/bar"]).To(BeEmpty())
			})
		})
		Context("svc = nil, ep = ep", func() {
			It("should set an unset routes for a service", func() {
				svc, ep := buildSimpleService()
				addEndpointSubset(ep, rg.nodeName)

				rg.svcIndexer.Add(svc)
				rg.setRouteForSvc(nil, ep)
				Expect(rg.svcRouteMap["foo/bar"]).To(Equal("127.0.0.1/32"))
				rg.unsetRouteForSvc(ep)
				Expect(rg.svcRouteMap["foo/bar"]).To(BeEmpty())
			})
		})
	})

	Describe("resourceInformerHandlers", func() {
		var (
			svc *v1.Service
			ep  *v1.Endpoints
		)

		BeforeEach(func() {
			svc, ep = buildSimpleService()

			addEndpointSubset(ep, rg.nodeName)
			rg.epIndexer.Add(ep)
			rg.svcIndexer.Add(svc)
		})

		It("should remove clusterIPs when endpoints are deleted", func() {
			// Trigger a service add - it should update the cache with its route.
			initRevision := rg.client.cacheRevision
			rg.onSvcAdd(svc)
			Expect(rg.client.cacheRevision).To(Equal(initRevision + 1))
			Expect(rg.svcRouteMap["foo/bar"]).To(Equal("127.0.0.1/32"))
			Expect(rg.client.cache["/calico/staticroutes/127.0.0.1-32"]).To(Equal("127.0.0.1/32"))

			// Simulate the remove of the local endpoint. It should withdraw the route.
			ep.Subsets = []v1.EndpointSubset{}
			rg.epIndexer.Add(ep)
			rg.onEPAdd(ep)
			Expect(rg.client.cacheRevision).To(Equal(initRevision + 2))
			Expect(rg.svcRouteMap["foo/bar"]).To(Equal(""))
			Expect(rg.client.cache["/calico/staticroutes/127.0.0.1-32"]).To(Equal(""))
			Expect(rg.client.cache).To(Equal(map[string]string{}))
		})

		Context("onSvc[Add|Delete]", func() {
			It("should add the service's clusterIP into the svcRouteMap", func() {
				// add
				initRevision := rg.client.cacheRevision
				rg.onSvcAdd(svc)
				Expect(rg.client.cacheRevision).To(Equal(initRevision + 1))
				Expect(rg.svcRouteMap["foo/bar"]).To(Equal("127.0.0.1/32"))
				Expect(rg.client.cache["/calico/staticroutes/127.0.0.1-32"]).To(Equal("127.0.0.1/32"))

				// delete
				rg.onSvcDelete(svc)
				Expect(rg.client.cacheRevision).To(Equal(initRevision + 2))
				Expect(rg.svcRouteMap).ToNot(HaveKey("foo/bar"))
				Expect(rg.client.cache).ToNot(HaveKey("/calico/staticroutes/127.0.0.1-32"))
			})
		})

		Context("onSvcUpdate", func() {
			It("should add the service's clusterIP into the svcRouteMap and then remove it for unsupported service type", func() {
				initRevision := rg.client.cacheRevision
				rg.onSvcUpdate(nil, svc)
				Expect(rg.client.cacheRevision).To(Equal(initRevision + 1))
				Expect(rg.svcRouteMap["foo/bar"]).To(Equal("127.0.0.1/32"))
				Expect(rg.client.cache["/calico/staticroutes/127.0.0.1-32"]).To(Equal("127.0.0.1/32"))

				// set to unsupport service type
				svc.Spec.Type = v1.ServiceTypeExternalName
				rg.onSvcUpdate(nil, svc)
				Expect(rg.client.cacheRevision).To(Equal(initRevision + 2))
				Expect(rg.svcRouteMap).ToNot(HaveKey("foo/bar"))
				Expect(rg.client.cache).ToNot(HaveKey("/calico/staticroutes/127.0.0.1-32"))
			})
		})

		Context("onEp[Add|Delete]", func() {
			It("should add the service's clusterIP into the svcRouteMap", func() {
				// add
				initRevision := rg.client.cacheRevision
				rg.onEPAdd(ep)
				Expect(rg.client.cacheRevision).To(Equal(initRevision + 1))
				Expect(rg.svcRouteMap["foo/bar"]).To(Equal("127.0.0.1/32"))
				Expect(rg.client.cache["/calico/staticroutes/127.0.0.1-32"]).To(Equal("127.0.0.1/32"))

				// delete
				rg.onEPDelete(ep)
				Expect(rg.client.cacheRevision).To(Equal(initRevision + 2))
				Expect(rg.svcRouteMap).ToNot(HaveKey("foo/bar"))
				Expect(rg.client.cache).ToNot(HaveKey("/calico/staticroutes/127.0.0.1-32"))
			})
		})

		Context("onEpDelete", func() {
			It("should add the service's clusterIP into the svcRouteMap and then remove it for unsupported service type", func() {
				initRevision := rg.client.cacheRevision
				rg.onEPUpdate(nil, ep)
				Expect(rg.client.cacheRevision).To(Equal(initRevision + 1))
				Expect(rg.svcRouteMap["foo/bar"]).To(Equal("127.0.0.1/32"))
				Expect(rg.client.cache["/calico/staticroutes/127.0.0.1-32"]).To(Equal("127.0.0.1/32"))

				// set to unsupport service type
				svc.Spec.Type = v1.ServiceTypeExternalName
				rg.onEPUpdate(nil, ep)
				Expect(rg.client.cacheRevision).To(Equal(initRevision + 2))
				Expect(rg.svcRouteMap).ToNot(HaveKey("foo/bar"))
				Expect(rg.client.cache).ToNot(HaveKey("/calico/staticroutes/127.0.0.1-32"))
			})
		})
	})
})
