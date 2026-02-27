// Copyright (c) 2018-2024 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package calico

import (
	"fmt"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	"github.com/projectcalico/calico/confd/pkg/resource/template"
	"github.com/projectcalico/calico/libcalico-go/lib/winutils"
)

const (
	envAdvertiseClusterIPs    = "CALICO_ADVERTISE_CLUSTER_IPS"
	endpointSliceServiceIndex = "svcKey"
)

func endpointSliceServiceIndexFunc(obj interface{}) ([]string, error) {
	ep, ok := obj.(*discoveryv1.EndpointSlice)
	if !ok {
		return nil, nil
	}
	svcName, ok := ep.Labels[discoveryv1.LabelServiceName]
	if !ok || svcName == "" {
		return nil, nil
	}
	return []string{ep.Namespace + "/" + svcName}, nil
}

// routeGenerator defines the data fields
// necessary for monitoring the services/endpoints resources for
// valid service ips to advertise
type routeGenerator struct {
	sync.Mutex
	client                     *client
	nodeName                   string
	svcInformer, epInformer    cache.Controller
	svcIndexer, epIndexer      cache.Store
	svcRouteMap                map[string]map[string]bool
	routeAdvertisementRefCount map[string]int
	resyncKnownRoutesTrigger   chan struct{}
}

// NewRouteGenerator initializes a kube-api client and the informers
func NewRouteGenerator(c *client) (rg *routeGenerator, err error) {
	// Determine the node name we'll use to check for local endpoints.
	// This value should match the name of the node in the Kubernetes API.
	// Prefer CALICO_K8S_NODE_REF, and fall back to the Calico node name.
	nodename := template.NodeName
	if n := os.Getenv("CALICO_K8S_NODE_REF"); n != "" {
		nodename = n
	}
	log.Debugf("Route generator configured to use node name %s", nodename)

	// initialize empty route generator
	rg = &routeGenerator{
		client:                     c,
		nodeName:                   nodename,
		svcRouteMap:                make(map[string]map[string]bool),
		routeAdvertisementRefCount: make(map[string]int),
		resyncKnownRoutesTrigger:   make(chan struct{}, 1),
	}

	// set up k8s client
	// attempt 1: KUBECONFIG env var
	cfgFile := os.Getenv("KUBECONFIG")
	cfg, err := winutils.BuildConfigFromFlags("", cfgFile)
	if err != nil {
		log.WithError(err).Info("KUBECONFIG environment variable not found, attempting in-cluster")
		// attempt 2: in cluster config
		if cfg, err = winutils.GetInClusterConfig(); err != nil {
			return
		}
	}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return
	}

	// set up services informer
	svcWatcher := cache.NewListWatchFromClient(client.CoreV1().RESTClient(), "services", "", fields.Everything())
	svcHandler := cache.ResourceEventHandlerFuncs{AddFunc: rg.onSvcAdd, UpdateFunc: rg.onSvcUpdate, DeleteFunc: rg.onSvcDelete}
	rg.svcIndexer, rg.svcInformer = cache.NewInformerWithOptions(cache.InformerOptions{
		ListerWatcher: svcWatcher,
		ObjectType:    &v1.Service{},
		ResyncPeriod:  0,
		Handler:       svcHandler,
		Indexers:      cache.Indexers{},
	})

	// set up endpoints informer
	epWatcher := cache.NewListWatchFromClient(client.DiscoveryV1().RESTClient(), "endpointslices", "", fields.Everything())
	epHandler := cache.ResourceEventHandlerFuncs{AddFunc: rg.onEPAdd, UpdateFunc: rg.onEPUpdate, DeleteFunc: rg.onEPDelete}
	rg.epIndexer, rg.epInformer = cache.NewInformerWithOptions(cache.InformerOptions{
		ListerWatcher: epWatcher,
		ObjectType:    &discoveryv1.EndpointSlice{},
		ResyncPeriod:  0,
		Handler:       epHandler,
		Indexers:      cache.Indexers{endpointSliceServiceIndex: endpointSliceServiceIndexFunc},
	})

	return
}

// Start starts the RouteGenerator so that it will monitor Kubernetes services.
func (rg *routeGenerator) Start() {
	ch := make(chan struct{})
	go rg.svcInformer.Run(ch)
	go rg.epInformer.Run(ch)

	// Wait for informers to sync, then notify the main client.
	log.Info("Starting RouteGenerator for Kubernetes services")
	go func() {
		for !rg.svcInformer.HasSynced() || !rg.epInformer.HasSynced() {
			time.Sleep(100 * time.Millisecond)
		}

		// Notify the main client we're in sync now.
		rg.client.OnSyncChange(SourceRouteGenerator, true)
		log.Info("RouteGenerator in sync")

		// Loop waiting for trigger to recheck node-specific routes.
		for range rg.resyncKnownRoutesTrigger {
			rg.resyncKnownRoutes()
		}
	}()
}

// Called by the client to trigger us to recheck and advertise or withdraw node-specific routes.
// Must not block since this is called by the client while it holds its lock.
func (rg *routeGenerator) TriggerResync() {
	select {
	case rg.resyncKnownRoutesTrigger <- struct{}{}:
		log.Debug("Triggered route generator to resync known routes")
	default:
		log.Debug("Route generator already has pending resync trigger")
	}
}

// getServiceForEndpoints retrieves the corresponding svc for the given ep
func (rg *routeGenerator) getServiceForEndpoints(ep *discoveryv1.EndpointSlice) (*v1.Service, string) {
	svcName, ok := ep.Labels[discoveryv1.LabelServiceName]
	if !ok {
		log.WithField("ep", ep.Name).Debug("getServiceForEndpoints: endpointslice missing service name label, passing")
		return nil, ""
	}

	// construct a dummy svc using the service name from endpointslice to get the key
	svc := &v1.Service{ObjectMeta: metav1.ObjectMeta{Name: svcName, Namespace: ep.Namespace}}
	key, err := cache.MetaNamespaceKeyFunc(svc)
	if err != nil {
		log.WithField("ep", ep.Name).WithError(err).Warn("getServiceForEndpoints: error on retrieving key for endpoint, passing")
		return nil, ""
	}
	// get svc
	svcIface, exists, err := rg.svcIndexer.GetByKey(key)
	if err != nil {
		log.WithField("key", key).WithError(err).Warn("getServiceForEndpoints: error on retrieving service for key, passing")
		return nil, key
	} else if !exists {
		log.WithField("key", key).Debug("getServiceForEndpoints: service for key not found, passing")
		return nil, key
	}
	return svcIface.(*v1.Service), key
}

// getEndpointsForService retrieves the corresponding ep for the given svc
func (rg *routeGenerator) getEndpointsForService(svc *v1.Service) ([]*discoveryv1.EndpointSlice, string) {
	key, err := cache.MetaNamespaceKeyFunc(svc)
	if err != nil {
		log.WithField("svc", svc.Name).WithError(err).Warn("getEndpointsForService: error on retrieving key for service, passing")
		return nil, ""
	}

	objs, err := rg.epIndexer.(cache.Indexer).ByIndex(endpointSliceServiceIndex, key)
	if err != nil {
		log.WithField("key", key).WithError(err).Error("getEndpointsForService: error reading endpointslice index")
		return nil, key
	}

	var eps []*discoveryv1.EndpointSlice
	for _, obj := range objs {
		ep, ok := obj.(*discoveryv1.EndpointSlice)
		if !ok {
			log.Warn("getEndpointsForService: failed to assert type to endpointslice, passing")
			continue
		}
		eps = append(eps, ep)
	}
	return eps, key
}

// setRouteForSvc handles the main logic to check if a specified service or endpoint
// should have its route advertised by the node running this code
func (rg *routeGenerator) setRouteForSvc(svc *v1.Service, ep *discoveryv1.EndpointSlice) {
	// ensure both are not nil
	if svc == nil && ep == nil {
		log.Error("setRouteForSvc: both service and endpoint cannot be nil, passing...")
		return
	}

	var key string
	var eps []*discoveryv1.EndpointSlice
	if svc == nil {
		eps = append(eps, ep)
		// ep received but svc nil
		if svc, key = rg.getServiceForEndpoints(ep); svc == nil {
			return
		}
	} else if ep == nil {
		// svc received but ep nil
		if eps, key = rg.getEndpointsForService(svc); len(eps) == 0 {
			return
		}
	}

	// see if any endpoints are on this node and advertise if so
	// else remove the route if it also already exists
	logCtx := log.WithField("svc", fmt.Sprintf("%s/%s", svc.Namespace, svc.Name))
	rg.Lock()
	defer rg.Unlock()

	advertise := rg.advertiseThisService(svc, eps)
	logCtx.WithField("advertise", advertise).Debug("Checking routes for service")
	if advertise {
		routes := rg.getAllRoutesForService(svc)
		rg.setRoutesForKey(key, routes)
	} else {
		routes := rg.getAdvertisedRoutes(key)
		rg.withdrawRoutesForKey(key, routes)
	}
}

func (rg *routeGenerator) resyncKnownRoutes() {
	// Get all the services that we know about and check if
	// we need to change advertisement for them.
	svcIfaces := rg.svcIndexer.List()
	for _, svcIface := range svcIfaces {
		svc, ok := svcIface.(*v1.Service)
		if !ok {
			log.Error("Type assertion failed for rg.svcIndexer result member. Will not process updates to routes advertised for service.")
			continue
		}
		// Update the routes advertised for this service
		rg.setRouteForSvc(svc, nil)
	}
}

// getAllRoutesForService returns all the routes that should be advertised
// for the given service.
func (rg *routeGenerator) getAllRoutesForService(svc *v1.Service) []string {
	routes := make([]string, 0)
	if rg.client.AdvertiseClusterIPs() {
		// Only advertise cluster IPs if we've been told to.
		routes = append(routes, svc.Spec.ClusterIPs...)
	}
	svcID := fmt.Sprintf("%s/%s", svc.Namespace, svc.Name)

	if svc.Spec.ExternalIPs != nil {
		for _, externalIP := range svc.Spec.ExternalIPs {
			// Only advertise allowed external IPs
			if !rg.isAllowedExternalIP(externalIP) {
				log.WithFields(log.Fields{"ip": externalIP, "svc": svcID}).Info("Cannot advertise External IP - not in allow list")
				continue
			}
			routes = append(routes, externalIP)
		}
	}

	if svc.Status.LoadBalancer.Ingress != nil {
		for _, lbIngress := range svc.Status.LoadBalancer.Ingress {
			if len(lbIngress.IP) > 0 {
				// Only advertise allowed LB IPs
				if !rg.isAllowedLoadBalancerIP(lbIngress.IP) {
					log.WithFields(log.Fields{"ip": lbIngress.IP, "svc": svcID}).Info("Cannot advertise LoadBalancer IP - not in allow list")
					continue
				}
				routes = append(routes, lbIngress.IP)
			}
		}
	}

	return addFullIPLength(routes)
}

// getAdvertisedRoutes returns the routes that are currently advertised and
// associated with the given key.
func (rg *routeGenerator) getAdvertisedRoutes(key string) []string {
	routes := make([]string, 0)

	if rg.svcRouteMap[key] != nil {
		for route := range rg.svcRouteMap[key] {
			routes = append(routes, route)
		}
	}

	return routes
}

// setRoutesForKey associates only the given routes with the given key,
// and advertises the given routes. It also withdraws any routes that are no
// longer associated with the given key.
func (rg *routeGenerator) setRoutesForKey(key string, routes []string) {
	advertisedRoutes := rg.svcRouteMap[key]
	if advertisedRoutes == nil {
		advertisedRoutes = make(map[string]bool)
	}
	log.WithFields(log.Fields{"key": key, "routes": routes}).Debug("Setting routes for key")

	// Withdraw any routes we are advertising that are no longer associated
	// with this key.
	for route := range advertisedRoutes {
		if !contains(routes, route) {
			rg.withdrawRoute(key, route)
		}
	}

	// Advertise all routes that are not already advertised.
	for _, route := range routes {
		// Advertise route if not already advertised for this key.
		if _, ok := advertisedRoutes[route]; !ok {
			rg.advertiseRoute(key, route)
		}
	}
}

// isAllowedExternalIP determines if the given IP is in the list of
// allowed External IP CIDRs given in the default bgpconfiguration.
func (rg *routeGenerator) isAllowedExternalIP(externalIP string) bool {
	if externalIP == "" {
		log.Debug("Skip empty service External IP")
		return false
	}
	ip := net.ParseIP(externalIP)
	if ip == nil {
		log.Errorf("Could not parse service External IP: %s", externalIP)
		return false
	}

	for _, allowedNet := range rg.client.GetExternalIPs() {
		if allowedNet.Contains(ip) {
			return true
		}
	}

	// Guilty until proven innocent
	return false
}

// isAllowedLoadBalancerIP determines if the given IP is in the list of
// allowed LoadBalancer CIDRs given in the default bgpconfiguration.
func (rg *routeGenerator) isAllowedLoadBalancerIP(loadBalancerIP string) bool {
	if loadBalancerIP == "" {
		log.Debug("Skip empty service LB IP")
		return false
	}
	ip := net.ParseIP(loadBalancerIP)
	if ip == nil {
		log.Errorf("Could not parse service LB IP: %s", loadBalancerIP)
		return false
	}

	for _, allowedNet := range rg.client.GetLoadBalancerIPs() {
		if allowedNet.Contains(ip) {
			return true
		}
	}

	// Guilty until proven innocent
	return false
}

// hasAnySingleLoadBalancerIP checks whether the service has any LoadBalancer IP
// that matches a single-IP (/32 or /128) entry in serviceLoadBalancerIPs.
// It checks both svc.Spec.LoadBalancerIP (deprecated but still used) and the
// actual assigned IPs from svc.Status.LoadBalancer.Ingress, since IPs assigned
// from a Calico IPPool only appear in status, not spec.
func (rg *routeGenerator) hasAnySingleLoadBalancerIP(svc *v1.Service) bool {
	if rg.isSingleLoadBalancerIP(svc.Spec.LoadBalancerIP) {
		return true
	}
	for _, ingress := range svc.Status.LoadBalancer.Ingress {
		if rg.isSingleLoadBalancerIP(ingress.IP) {
			return true
		}
	}
	return false
}

// isSingleLoadBalancerIP determines if the given IP is in the list of
// allowed LoadBalancer CIDRs given in the default bgpconfiguration
// and is a single IP entry (/32 for IPV4 or /128 for IPV6)
func (rg *routeGenerator) isSingleLoadBalancerIP(loadBalancerIP string) bool {
	if loadBalancerIP == "" {
		log.Debug("Skip empty service LB IP")
		return false
	}
	ip := net.ParseIP(loadBalancerIP)
	if ip == nil {
		log.Errorf("Could not parse service LB IP: %s", loadBalancerIP)
		return false
	}

	for _, allowedNet := range rg.client.GetLoadBalancerIPs() {
		if allowedNet.Contains(ip) {
			if ones, bits := allowedNet.Mask.Size(); ones == bits {
				return true
			}
		}
	}

	// Guilty until proven innocent
	return false
}

// isSingleExternalIP determines if the given IP is in the list of
// allowed ExternalIP CIDRs given in the default bgpconfiguration
// and is a single IP entry (/32 for IPV4 or /128 for IPV6)
func (rg *routeGenerator) isSingleExternalIP(externalIP string) bool {
	if externalIP == "" {
		log.Debug("Skip empty service External IP")
		return false
	}
	ip := net.ParseIP(externalIP)
	if ip == nil {
		log.Errorf("Could not parse service External IP: %s", externalIP)
		return false
	}

	for _, allowedNet := range rg.client.GetExternalIPs() {
		if allowedNet.Contains(ip) {
			if ones, bits := allowedNet.Mask.Size(); ones == bits {
				return true
			}
		}
	}

	// Guilty until proven innocent
	return false
}

// addFullIPLength returns a new slice, with the full IP length appended onto every item.
func addFullIPLength(items []string) []string {
	res := make([]string, 0)
	for _, item := range items {
		if strings.Contains(item, ":") {
			res = append(res, item+"/128")
		} else {
			res = append(res, item+"/32")
		}
	}
	return res
}

// contains returns true if items contains the target.
func contains(items []string, target string) bool {
	return slices.Contains(items, target)
}

// advertiseThisService returns true if this service should be advertised on this node,
// false otherwise.
func (rg *routeGenerator) advertiseThisService(svc *v1.Service, eps []*discoveryv1.EndpointSlice) bool {
	logc := log.WithField("svc", fmt.Sprintf("%s/%s", svc.Namespace, svc.Name))

	// Don't advertise routes if this node is explicitly excluded from load balancers.
	if rg.client.ExcludeServiceAdvertisement() {
		logc.Debug("Skipping service because node is explicitly excluded from load balancers")
		return false
	}

	// do nothing if the svc is not a relevant type
	if (svc.Spec.Type != v1.ServiceTypeClusterIP) && (svc.Spec.Type != v1.ServiceTypeNodePort) && (svc.Spec.Type != v1.ServiceTypeLoadBalancer) {
		logc.Debugf("Skipping service with type %s", svc.Spec.Type)
		return false
	}

	// also do nothing if no cluster IPs are assigned
	if svc.Spec.ClusterIP == "" || svc.Spec.ClusterIP == "None" {
		logc.Debug("Skipping service with no cluster IPs")
		return false
	}

	// we need to announce single IPs for services of type externalTrafficPolicy Cluster.
	// There are 2 cases inside this type:
	// - LoadBalancer with a single IP.
	// - Any one of the externalIPs are a single IP.
	if svc.Spec.ExternalTrafficPolicy == v1.ServiceExternalTrafficPolicyTypeCluster {
		if svc.Spec.Type == v1.ServiceTypeLoadBalancer && rg.hasAnySingleLoadBalancerIP(svc) {
			logc.Debug("Advertising load balancer of type cluster because of single IP definition")
			return true
		}

		// Advertise if there is a fully qualified (i.e., /32 or /128) external IP defined.
		if slices.ContainsFunc(svc.Spec.ExternalIPs, rg.isSingleExternalIP) {
			logc.Debug("Advertising external IP of type cluster because of single IP definition")
			return true
		}
	}

	// For Cluster services, check aggregation setting to determine if we should proceed with endpoint-based logic.
	// When aggregation is enabled, Cluster services are handled by global CIDR advertisement instead of individual routes.
	if svc.Spec.ExternalTrafficPolicy != v1.ServiceExternalTrafficPolicyTypeLocal && rg.client.ShouldAggregateLoadBalancerServices() {
		logc.Debugf("Skipping service with non-local external traffic policy '%s'", svc.Spec.ExternalTrafficPolicy)
		return false
	}

	// Build a lookup table of IP families supported by the Service.
	// Example: ["IPv4"], ["IPv6"], or ["IPv4","IPv6"] for dual-stack.
	svcIPFamilies := make(map[string]struct{})
	for _, fam := range svc.Spec.IPFamilies {
		svcIPFamilies[string(fam)] = struct{}{}
	}

	for _, ep := range eps {
		// We only consider EndpointSlices whose addressType matches one of the Service’s families.
		epFamily := string(ep.AddressType)
		// Skip EndpointSlices with incompatible address families.
		if _, ok := svcIPFamilies[epFamily]; !ok {
			continue
		}
		for _, subset := range ep.Endpoints {
			// not interested in subset.NotReadyAddresses
			if svc.Spec.ExternalTrafficPolicy != v1.ServiceExternalTrafficPolicyTypeLocal {
				// For Cluster services, advertise if we have any endpoints
				logc.Debugf("Advertising cluster service")
				return true
			} else {
				// For Local services, only advertise if we have local endpoints
				if subset.NodeName != nil && *subset.NodeName == rg.nodeName {
					logc.Debugf("Advertising local service")
					return true
				}
			}
		}
	}
	logc.Debugf("Skipping service with no local endpoints")
	return false
}

// unsetRouteForSvc removes the route from the svcClusterRouteMap
// but checks to see if it wasn't already deleted by its sibling resource
func (rg *routeGenerator) unsetRouteForSvc(obj any) {
	// generate key
	key, err := cache.MetaNamespaceKeyFunc(obj)
	if err != nil {
		log.WithError(err).Warn("unsetRouteForSvc: error on retrieving key for object, passing")
		return
	}

	// mutex
	rg.Lock()
	defer rg.Unlock()

	routes := rg.getAdvertisedRoutes(key)
	rg.withdrawRoutesForKey(key, routes)
}

// advertiseRoute advertises a route associated with the given key and
// caches it.
func (rg *routeGenerator) advertiseRoute(key, route string) {
	if _, hasKey := rg.svcRouteMap[key]; !hasKey {
		rg.svcRouteMap[key] = make(map[string]bool)
	}
	rg.svcRouteMap[key][route] = true

	// We need to reference count routes. We may have multiple services that
	// trigger advertisement of this prefix, however we only ever want to send
	// a single static route advertisement as a result.
	if rg.routeAdvertisementRefCount[route] == 0 {
		// First time we've seen this route - advertise it.
		rg.client.AddStaticRoutes([]string{route})
	}

	// Increment the ref count.
	rg.routeAdvertisementRefCount[route]++
}

// withdrawRoute withdraws a route associated with the given key and
// removes it from the cache.
func (rg *routeGenerator) withdrawRoute(key, route string) {
	// Only remove the advertisement if there are no other reasons this route
	// should be advertised. For example, k8s will allow you to manually assign
	// the same External IP to two different services; assign an External IP to
	// a service which is the same as the service's cluster IP,
	// and assign the same External IP twice to a service. In all of these
	// scenarios, you would end up in a situation where the same route is
	// "legitimately" being advertised twice from a node.
	if rg.routeAdvertisementRefCount[route] == 1 {
		rg.client.DeleteStaticRoutes([]string{route})
		delete(rg.routeAdvertisementRefCount, route)
	} else {
		rg.routeAdvertisementRefCount[route]--
	}

	if rg.svcRouteMap[key] != nil {
		delete(rg.svcRouteMap[key], route)
		if len(rg.svcRouteMap[key]) == 0 {
			delete(rg.svcRouteMap, key)
		}
	}
}

// withdrawRoutesForKey withdraws the given routes associated with the given key
// and removes them from the cache.
func (rg *routeGenerator) withdrawRoutesForKey(key string, routes []string) {
	for _, route := range routes {
		rg.withdrawRoute(key, route)
	}
}

// onSvcAdd is called when a k8s service is created
func (rg *routeGenerator) onSvcAdd(obj any) {
	svc, ok := obj.(*v1.Service)
	if !ok {
		log.Warn("onSvcAdd: failed to assert type to service, passing")
		return
	}
	rg.setRouteForSvc(svc, nil)
}

// onSvcUpdate is called when a k8s service is updated
func (rg *routeGenerator) onSvcUpdate(_, obj any) {
	svc, ok := obj.(*v1.Service)
	if !ok {
		log.Warn("onSvcUpdate: failed to assert type to service, passing")
		return
	}
	rg.setRouteForSvc(svc, nil)
}

// onSvcUpdate is called when a k8s service is deleted
func (rg *routeGenerator) onSvcDelete(obj any) {
	rg.unsetRouteForSvc(obj)
}

// onEPAdd is called when a k8s endpoint is created
func (rg *routeGenerator) onEPAdd(obj any) {
	ep, ok := obj.(*discoveryv1.EndpointSlice)
	if !ok {
		log.Warn("onEPAdd: failed to assert type to endpoint, passing")
		return
	}
	rg.setRouteForSvc(nil, ep)
}

// onEPUpdate is called when a k8s endpoint is updated
func (rg *routeGenerator) onEPUpdate(_, obj any) {
	ep, ok := obj.(*discoveryv1.EndpointSlice)
	if !ok {
		log.Warn("onEPUpdate: failed to assert type to endpoints, passing")
		return
	}
	rg.setRouteForSvc(nil, ep)
}

// onEPDelete is called when a k8s endpoint is deleted
func (rg *routeGenerator) onEPDelete(obj any) {
	rg.unsetRouteForSvc(obj)
}

// parseIPNets takes a v1 formatted, comma separated string of CIDRs and
// returns a list of net.IPNet object pointers.
func parseIPNets(ipCIDRs []string) []*net.IPNet {
	ipNets := make([]*net.IPNet, 0)
	for _, CIDR := range ipCIDRs {
		_, ipNet, err := net.ParseCIDR(CIDR)
		if err != nil {
			log.WithError(err).Errorf("Failed to parse CIDR: %s.", CIDR)
			continue
		}

		ipNets = append(ipNets, ipNet)
	}

	return ipNets
}
