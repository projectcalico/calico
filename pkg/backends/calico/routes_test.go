package calico

import (
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
				cache: make(map[string]string),
			},
		}
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
			svc, svc2 *v1.Service
			ep, ep2   *v1.Endpoints
		)
		BeforeEach(func() {
			svc, ep = buildSimpleService()
			svc2, ep2 = buildSimpleService()

			addEndpointSubset(ep, rg.nodeName)
			rg.epIndexer.Add(ep)

			addEndpointSubset(&ep2, "barfoo")
			rg.epIndexer.Add(ep2)
		})
		Context("onSvcAdd", func() {
			It("should add the service's clusterIP into the svcRouteMap", func() {
				addEndpointSubset(ep, rg.nodeName)
				rg.epIndexer.Add(ep)
				rg.onSvcAdd(svc)
				Expect(rg.svcRouteMap["foo/bar"]).To(Equal("127.0.0.1/32"))
				Expect(rg.client.cache["/calico/staticroutes/127.0.0.1-32"]).To(Equal("127.0.0.1/32"))
			})
		})

		Context("onSvcUpdate", func() {
			// TODO
		})

		Context("onSvcDelete", func() {
			// TODO
		})

		Context("onEpAdd", func() {
			// TODO
		})

		Context("onEpUpdate", func() {
			// TODO
		})

		Context("onEpDelete", func() {
			// TODO
		})
	})
})
