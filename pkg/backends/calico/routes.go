// Copyright (c) 2018 Tigera, Inc. All rights reserved.
//
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
package calico

import (
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/kelseyhightower/confd/pkg/resource/template"
)

const (
	envAdvertiseClusterIPs = "CALICO_ADVERTISE_CLUSTER_IPS"
)

// routeGenerator defines the data fields
// necessary for monitoring the services/endpoints resources for
// valid service ips to advertise
type routeGenerator struct {
	sync.Mutex
	client                  *client
	nodeName                string
	svcInformer, epInformer cache.Controller
	svcIndexer, epIndexer   cache.Indexer
	svcRouteMap             map[string][]string // maps service name to ip
	clusterCIDR             string
}

// NewRouteGenerator initializes a kube-api client and the informers
func NewRouteGenerator(c *client, clusterCIDR string) (rg *routeGenerator, err error) {
	// Parse clusterCIDR to make sure it is valid.
	cidr := strings.TrimSpace(clusterCIDR)
	if _, _, err := net.ParseCIDR(cidr); err != nil {
		return nil, fmt.Errorf("failed to parse cluster CIDR %s: %s", clusterCIDR, err)
	}

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
		client:      c,
		nodeName:    nodename,
		svcRouteMap: make(map[string][]string),
		clusterCIDR: clusterCIDR,
	}

	// set up k8s client
	// attempt 1: KUBECONFIG env var
	cfgFile := os.Getenv("KUBECONFIG")
	cfg, err := clientcmd.BuildConfigFromFlags("", cfgFile)
	if err != nil {
		log.WithError(err).Info("KUBECONFIG environment variable not found, attempting in-cluster")
		// attempt 2: in cluster config
		if cfg, err = rest.InClusterConfig(); err != nil {
			return
		}
	}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return
	}

	// set up services informer
	svcWatcher := cache.NewListWatchFromClient(client.Core().RESTClient(), "services", "", fields.Everything())
	svcHandler := cache.ResourceEventHandlerFuncs{AddFunc: rg.onSvcAdd, UpdateFunc: rg.onSvcUpdate, DeleteFunc: rg.onSvcDelete}
	rg.svcIndexer, rg.svcInformer = cache.NewIndexerInformer(svcWatcher, &v1.Service{}, 0, svcHandler, cache.Indexers{})

	// set up endpoints informer
	epWatcher := cache.NewListWatchFromClient(client.Core().RESTClient(), "endpoints", "", fields.Everything())
	epHandler := cache.ResourceEventHandlerFuncs{AddFunc: rg.onEPAdd, UpdateFunc: rg.onEPUpdate, DeleteFunc: rg.onEPDelete}
	rg.epIndexer, rg.epInformer = cache.NewIndexerInformer(epWatcher, &v1.Endpoints{}, 0, epHandler, cache.Indexers{})

	return
}

// Start starts the RouteGenerator so that it will monitor Kubernetes services.
func (rg *routeGenerator) Start() {
	ch := make(chan struct{})
	go rg.svcInformer.Run(ch)
	go rg.epInformer.Run(ch)

	// Don't program routes within the cluster CIDR.
	rg.client.AddRejectCIDRs([]string{rg.clusterCIDR})

	// But, do advertise it.
	rg.client.AddStaticRoutes([]string{rg.clusterCIDR})

	// Wait for informers to sync, then notify the main client.
	go func() {
		for !rg.svcInformer.HasSynced() || !rg.epInformer.HasSynced() {
			time.Sleep(100 * time.Millisecond)
		}

		// Notify the main client we're in sync now.
		rg.client.OnInSync(SourceRouteGenerator)
	}()

	return
}

// getServiceForEndpoints retrieves the corresponding svc for the given ep
func (rg *routeGenerator) getServiceForEndpoints(ep *v1.Endpoints) (*v1.Service, string) {
	// get key
	key, err := cache.MetaNamespaceKeyFunc(ep)
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
func (rg *routeGenerator) getEndpointsForService(svc *v1.Service) (*v1.Endpoints, string) {
	// get key
	key, err := cache.MetaNamespaceKeyFunc(svc)
	if err != nil {
		log.WithField("svc", svc.Name).WithError(err).Warn("getEndpointsForService: error on retrieving key for service, passing")
		return nil, ""
	}
	// get ep
	epIface, exists, err := rg.epIndexer.GetByKey(key)
	if err != nil {
		log.WithField("key", key).WithError(err).Warn("getEndpointsForService: error on retrieving endpoint for key, passing")
		return nil, key
	} else if !exists {
		log.WithField("key", key).Debug("getEndpointsForService: service for endpoint not found, passing")
		return nil, key
	}
	return epIface.(*v1.Endpoints), key
}

// setRouteForSvc handles the main logic to check if a specified service or endpoint
// should have its route advertised by the node running this code
func (rg *routeGenerator) setRouteForSvc(svc *v1.Service, ep *v1.Endpoints) {

	// ensure both are not nil
	if svc == nil && ep == nil {
		log.Error("setRouteForSvc: both service and endpoint cannot be nil, passing...")
		return
	}

	var key string
	if svc == nil {
		// ep received but svc nil
		if svc, key = rg.getServiceForEndpoints(ep); svc == nil {
			return
		}
	} else if ep == nil {
		// svc received but ep nil
		if ep, key = rg.getEndpointsForService(svc); ep == nil {
			return
		}
	}

	// see if any endpoints are on this node and advertise if so
	// else remove the route if it also already exists
	rg.Lock()
	if rg.advertiseThisService(svc, ep) {
		rg.svcRouteMap[key] = []string{svc.Spec.ClusterIP + "/32"}
		rg.client.AddStaticRoutes([]string{svc.Spec.ClusterIP + "/32"})
	} else if routes, exists := rg.svcRouteMap[key]; exists {
		rg.client.DeleteStaticRoutes(routes)
		delete(rg.svcRouteMap, key)
	}
	rg.Unlock()
}

// advertiseThisService returns true if this service should be advertised on this node,
// false otherwise.
func (rg *routeGenerator) advertiseThisService(svc *v1.Service, ep *v1.Endpoints) bool {
	logc := log.WithField("svc", fmt.Sprintf("%s/%s", svc.Namespace, svc.Name))

	// do nothing if the svc is not a relevant type
	if (svc.Spec.Type != v1.ServiceTypeClusterIP) && (svc.Spec.Type != v1.ServiceTypeNodePort) && (svc.Spec.Type != v1.ServiceTypeLoadBalancer) {
		logc.Debugf("Skipping service with cluster type %s", svc.Spec.Type)
		return false
	}

	// also do nothing if the clusterIP is empty or None
	if svc.Spec.ClusterIP == "" || svc.Spec.ClusterIP == "None" {
		logc.Debugf("Skipping service with no cluster IP %s", svc.Spec.Type)
		return false
	}

	// we only need to advertise local services, since we advertise the entire cluster IP range.
	if svc.Spec.ExternalTrafficPolicy != v1.ServiceExternalTrafficPolicyTypeLocal {
		logc.Debugf("Skipping service with non-local external traffic policy '%s'", svc.Spec.ExternalTrafficPolicy)
		return false
	}

	// advertise clusterIP if node contains at least one endpoint for svc
	for _, subset := range ep.Subsets {
		// not interested in subset.NotReadyAddresses
		for _, address := range subset.Addresses {
			if address.NodeName == nil || *address.NodeName != rg.nodeName {
				continue
			}
			logc.Debugf("Advertising local service")
			return true
		}
	}
	logc.Debugf("Skipping service with no local endpoints")
	return false
}

// unsetRouteForSvc removes the route from the svcRouteMap
// but checks to see if it wasn't already deleted by its sibling resource
func (rg *routeGenerator) unsetRouteForSvc(obj interface{}) {
	// generate key
	key, err := cache.MetaNamespaceKeyFunc(obj)
	if err != nil {
		log.WithError(err).Warn("unsetRouteForSvc: error on retrieving key for object, passing")
		return
	}

	// mutex
	rg.Lock()
	defer rg.Unlock()

	// Remove any routes that might exist.
	if routes, exists := rg.svcRouteMap[key]; exists {
		rg.client.DeleteStaticRoutes(routes)
		delete(rg.svcRouteMap, key)
	}
}

// onSvcAdd is called when a k8s service is created
func (rg *routeGenerator) onSvcAdd(obj interface{}) {
	svc, ok := obj.(*v1.Service)
	if !ok {
		log.Warn("onSvcAdd: failed to assert type to service, passing")
		return
	}
	rg.setRouteForSvc(svc, nil)
}

// onSvcUpdate is called when a k8s service is updated
func (rg *routeGenerator) onSvcUpdate(_, obj interface{}) {
	svc, ok := obj.(*v1.Service)
	if !ok {
		log.Warn("onSvcUpdate: failed to assert type to service, passing")
		return
	}
	rg.setRouteForSvc(svc, nil)
}

// onSvcUpdate is called when a k8s service is deleted
func (rg *routeGenerator) onSvcDelete(obj interface{}) {
	rg.unsetRouteForSvc(obj)
}

// onEPAdd is called when a k8s endpoint is created
func (rg *routeGenerator) onEPAdd(obj interface{}) {
	ep, ok := obj.(*v1.Endpoints)
	if !ok {
		log.Warn("onEPAdd: failed to assert type to endpoints, passing")
		return
	}
	rg.setRouteForSvc(nil, ep)
}

// onEPUpdate is called when a k8s endpoint is updated
func (rg *routeGenerator) onEPUpdate(_, obj interface{}) {
	ep, ok := obj.(*v1.Endpoints)
	if !ok {
		log.Warn("onEPUpdate: failed to assert type to endpoints, passing")
		return
	}
	rg.setRouteForSvc(nil, ep)
}

// onEPDelete is called when a k8s endpoint is deleted
func (rg *routeGenerator) onEPDelete(obj interface{}) {
	rg.unsetRouteForSvc(obj)
}
