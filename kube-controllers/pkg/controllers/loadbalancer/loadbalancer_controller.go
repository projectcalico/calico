// Copyright (c) 2019-2024 Tigera, Inc. All rights reserved.
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

package loadbalancer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"reflect"
	"slices"
	"strings"
	"time"

	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/calico/kube-controllers/pkg/config"
	"github.com/projectcalico/calico/kube-controllers/pkg/controllers/controller"
	"github.com/projectcalico/calico/kube-controllers/pkg/controllers/node"
	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8svalidation "k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/wait"

	rcache "github.com/projectcalico/calico/kube-controllers/pkg/cache"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"

	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	uruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

const (
	annotationIpv4Pools      = "projectcalico.org/ipv4pools"
	annotationIpv6Pools      = "projectcalico.org/ipv6pools"
	annotationLoadBalancerIp = "projectcalico.org/loadBalancerIPs"
	timer                    = 1 * time.Minute
)

// loadBalancerController implements the Controller interface for managing Kubernetes services
// and endpoints, syncing them to the Calico datastore as NetworkSet.
type loadBalancerController struct {
	informer        cache.Controller
	lbResourceCache rcache.ResourceCache
	calicoClient    client.Interface
	dataFeed        *node.DataFeed
	ctx             context.Context
	cfg             config.LoadBalancerControllerConfig
	clientSet       *kubernetes.Clientset
	syncerUpdates   chan interface{}
	syncStatus      bapi.SyncStatus
	syncChan        chan interface{}
	ipamBlocks      map[string]model.KVPair
	ipPools         map[string]api.IPPool
}

// NewLoadBalancerController returns a controller which manages Service LoadBalancer objects.
func NewLoadBalancerController(ctx context.Context, clientset *kubernetes.Clientset, calicoClient client.Interface, cfg config.LoadBalancerControllerConfig) controller.Controller {
	// set up service informer
	svcWatcher := cache.NewListWatchFromClient(clientset.CoreV1().RESTClient(), "services", "", fields.Everything())

	listFunc := func() (map[string]interface{}, error) {
		log.Debugf("Listing profiles from Calico datastore")
		filteredServices := make(map[string]interface{})

		// Get all profile objects from Calico datastore.
		serviceList, err := clientset.CoreV1().Services("").List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}

		// Filter out only services of type LoadBalancer
		for _, svc := range serviceList.Items {
			if svc.Spec.Type == v1.ServiceTypeLoadBalancer {
				key := createHandle(&svc)
				filteredServices[key] = svc
			}
		}
		log.Debugf("Found %d Service LoadBalancer in Calico datastore", len(filteredServices))
		return filteredServices, nil
	}

	cacheArgs := rcache.ResourceCacheArgs{
		ListFunc:    listFunc,
		ObjectType:  reflect.TypeOf(&v1.Service{}),
		LogTypeDesc: "Service",
	}
	ccache := rcache.NewResourceCache(cacheArgs)

	svcHandler := cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			log.Debugf("Got ADD event for service")
			svc := obj.(*v1.Service)
			if isCalicoManagedLoadBalancer(svc, cfg.AssignIPs) {
				ccache.Set(createHandle(svc), svc)
			}
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			log.Debugf("Got UPDATE event for service")
			log.Debugf("Old object: %v", oldObj)
			log.Debugf("New object: %v", newObj)
			svcNew := newObj.(*v1.Service)
			svcOld := oldObj.(*v1.Service)

			// Service changed type, we need to release the addresses used by the service
			if svcNew.Spec.Type != v1.ServiceTypeLoadBalancer &&
				svcOld.Spec.Type == v1.ServiceTypeLoadBalancer {
				ccache.Delete(createHandle(svcOld))
			} else if svcOld.Annotations[annotationIpv4Pools] != svcNew.Annotations[annotationIpv4Pools] ||
				svcOld.Annotations[annotationIpv6Pools] != svcNew.Annotations[annotationIpv6Pools] ||
				svcOld.Annotations[annotationLoadBalancerIp] != svcNew.Annotations[annotationLoadBalancerIp] {
				// Calico annotations have changed, get new address based on new conditions.
				ccache.Set(createHandle(svcNew), svcNew)
			}
		},
		DeleteFunc: func(obj interface{}) {
			log.Debugf("Got DELETE event for service")
			svc := obj.(*v1.Service)
			if isCalicoManagedLoadBalancer(svc, cfg.AssignIPs) {
				ccache.Delete(createHandle(svc))
			}
		},
	}
	_, informer := cache.NewIndexerInformer(svcWatcher, &v1.Service{}, 0, svcHandler, cache.Indexers{})

	return &loadBalancerController{
		calicoClient:    calicoClient,
		ctx:             ctx,
		cfg:             cfg,
		clientSet:       clientset,
		dataFeed:        node.NewDataFeed(calicoClient),
		lbResourceCache: ccache,
		informer:        informer,
		syncerUpdates:   make(chan interface{}),
		syncChan:        make(chan interface{}),
		ipamBlocks:      make(map[string]model.KVPair),
		ipPools:         make(map[string]api.IPPool),
	}
}

// Run starts the controller.
func (c *loadBalancerController) Run(stopCh chan struct{}) {
	defer uruntime.HandleCrash()

	// Start the Kubernetes informer, which will start syncing with the Kubernetes API.
	log.Info("Starting LoadBalancer controller")
	go c.informer.Run(stopCh)

	// Wait until we are in sync with the Kubernetes API before starting the
	// resource cache.
	log.Debug("Waiting to sync with Kubernetes API (Service)")
	for !c.informer.HasSynced() {
		time.Sleep(100 * time.Millisecond)
	}
	log.Debug("Finished syncing with Kubernetes API (Service)")
	c.lbResourceCache.Run(timer.String())

	for i := 0; i < c.cfg.NumberOfWorkers; i++ {
		go wait.Until(c.runWorker, time.Second, stopCh)
	}

	log.Info("LoadBalancer controller is now running")

	// Register to the syncer datafeed for updates to ippools and ipamBlocks
	c.RegisterWith(c.dataFeed)
	c.dataFeed.Start()
	go c.acceptScheduledRequests(stopCh)

	<-stopCh
	log.Info("Stopping Service controller")
}

func (c *loadBalancerController) RegisterWith(f *node.DataFeed) {
	f.RegisterForNotification(model.BlockKey{}, c.onUpdate)
	f.RegisterForNotification(model.ResourceKey{}, c.onUpdate)
	f.RegisterForSyncStatus(c.onStatusUpdate)
}

func (c *loadBalancerController) onStatusUpdate(s bapi.SyncStatus) {
	c.syncerUpdates <- s
}

func (c *loadBalancerController) onUpdate(update bapi.Update) {
	switch update.KVPair.Key.(type) {
	case model.ResourceKey:
		switch update.KVPair.Key.(model.ResourceKey).Kind {
		case api.KindIPPool:
			c.syncerUpdates <- update.KVPair
		}
	case model.BlockKey:
		c.syncerUpdates <- update.KVPair
	default:
		log.Warnf("Unexpected kind received over syncer: %s", update.KVPair.Key)
	}
}

func (c *loadBalancerController) acceptScheduledRequests(stopCh <-chan struct{}) {
	log.Infof("Will run periodic IPAM sync every %s", timer)
	t := time.NewTicker(timer)
	for {
		select {
		case update := <-c.syncerUpdates:
			c.handleUpdate(update)
		case <-t.C:
			log.Infof("Running periodic IPAM sync of Service LoadBalancer")
			c.syncIPAM()
		case <-stopCh:
			return
		}
	}
}

func (c *loadBalancerController) handleUpdate(update interface{}) {
	switch update := update.(type) {
	case bapi.SyncStatus:
		c.syncStatus = update
		switch update {
		case bapi.InSync:
			log.WithField("status", update).Info("Syncer is InSync, kicking sync channel")
			kick(c.syncChan)
		}
		return
	case model.KVPair:
		switch update.Key.(type) {
		case model.ResourceKey:
			switch update.Key.(model.ResourceKey).Kind {
			case api.KindIPPool:
				log.Infof("Running periodic IPAM sync of Service LoadBalancer")
				c.handleIPPoolUpdate(update)
				return
			}
		case model.BlockKey:
			c.handleBlockUpdate(update)
			return
		}
	}

}

func (c *loadBalancerController) handleBlockUpdate(kvp model.KVPair) {
	if kvp.Value != nil {
		host := kvp.Value.(*model.AllocationBlock).Affinity
		if host != nil && *host == fmt.Sprintf("host:%s", api.VirtualLoadBalancer) {
			c.ipamBlocks[kvp.Key.String()] = kvp
		}
	} else {
		delete(c.ipamBlocks, kvp.Key.String())
	}
}

func (c *loadBalancerController) handleIPPoolUpdate(kvp model.KVPair) {
	log.Infof("Addind IPPOOL")
	if kvp.Value != nil {
		pool := kvp.Value.(*api.IPPool)
		if slices.Contains(pool.Spec.AllowedUses, api.IPPoolAllowedUseLoadBalancer) {
			c.ipPools[kvp.Key.String()] = *pool
		}
	} else {
		delete(c.ipPools, kvp.Key.String())
	}
}

// syncIpam has two main uses. It functions as a garbage collection for leaked IP addresses from Service LoadBalancer
// The other use case is to update IPs for any Service LoadBalancer that do not have IPs assigned, this could be caused by the user
// creating Service LoadBalancer before any valid pools were created
func (c *loadBalancerController) syncIPAM() {
	// Garbage collection
	// Check all ipamBlocks with loadBalancer affinity
	for _, block := range c.ipamBlocks {
		attributes := block.Value.(*model.AllocationBlock).Attributes
		for _, attr := range attributes {
			obj, empty := c.lbResourceCache.Get(*attr.AttrPrimary)
			service := obj.(*v1.Service)
			if !empty {
				// Service with handle exists, we need to check that all assigned IPs with the handle are still in use by the service
				log.Infof("Service found for handle: %s. Check if all IPs allocated by the handle are in use.", *attr.AttrPrimary)
				ips, err := c.calicoClient.IPAM().IPsByHandle(c.ctx, *attr.AttrPrimary)
				if err != nil {
					log.Errorf("Error getting IPs for handle: %s", *attr.AttrPrimary)
					break
				}
				for _, ingressIP := range service.Status.LoadBalancer.Ingress {
					inUse := false
					for _, handleIP := range ips {
						if handleIP.String() == ingressIP.IP {
							inUse = true
						}
						if !inUse {
							releaseOptions := ipam.ReleaseOptions{
								Address: ingressIP.IP,
							}
							_, err = c.calicoClient.IPAM().ReleaseIPs(c.ctx, releaseOptions)
							if err != nil {
								log.Errorf("Error releasing IP(%s) for service: %s", ingressIP.IP, service.Name)
							}
						}
					}
				}
			} else {
				// Service no longer exists, leak confirmed. Release all IPs allocated with the specific handle
				log.Infof("Service not found for handle: %s. Releasing unused IPs", *attr.AttrPrimary)
				err := c.releaseIP(*attr.AttrPrimary)
				if err != nil {
					log.Errorf("Error releasing IPAM for handle %s: %s", *attr.AttrPrimary, err)
				}
			}
		}
	}

	// Check that all services have assigned IPs as requested, skip if there are no ippools
	if len(c.ipPools) != 0 {
		for _, key := range c.lbResourceCache.ListKeys() {
			obj, empty := c.lbResourceCache.Get(key)
			if !empty {
				service := obj.(*v1.Service)
				if isCalicoManagedLoadBalancer(service, c.cfg.AssignIPs) {
					if service.Status.LoadBalancer.Ingress == nil ||
						(len(service.Status.LoadBalancer.Ingress) == 1 &&
							(*service.Spec.IPFamilyPolicy == v1.IPFamilyPolicyRequireDualStack) || *service.Spec.IPFamilyPolicy == v1.IPFamilyPolicyPreferDualStack) {
						err := c.assignIP(service)
						if err != nil {
							log.Errorf("Error assigning IP to service %s: %s", service.Name, err)
						}
					}
				}
			}
		}
	}
}

func (c *loadBalancerController) runWorker() {
	for c.processNextItem() {
	}
}

func (c *loadBalancerController) processNextItem() bool {
	workqueue := c.lbResourceCache.GetQueue()
	key, quit := workqueue.Get()
	if quit {
		return false
	}

	err := c.syncToDatastore(key.(string))
	c.handleErr(err, key.(string))

	workqueue.Done(key)
	return true
}

// syncToDatastore processes the next item in queue
func (c *loadBalancerController) syncToDatastore(key string) error {
	obj, exists := c.lbResourceCache.Get(key)

	if !exists {
		// Service does not exist release the IPs
		return c.releaseIP(key)
	} else {
		svc := obj.(*v1.Service)
		// We don't have IP, assign one
		if svc.Status.LoadBalancer.Ingress == nil {
			return c.assignIP(svc)
		} else {
			// Service was updated
			return c.checkStatus(svc)
		}
	}
}

func (c *loadBalancerController) handleErr(err error, key string) {
	workqueue := c.lbResourceCache.GetQueue()
	if err == nil {
		// Forget about the #AddRateLimited history of the key on every successful synchronization.
		// This ensures that future processing of updates for this key is not delayed because of
		// an outdated error history.
		workqueue.Forget(key)
		return
	}

	// This controller retries 5 times if something goes wrong. After that, it stops trying.
	if workqueue.NumRequeues(key) < 5 {
		// Re-enqueue the key rate limited. Based on the rate limiter on the
		// queue and the re-enqueue history, the key will be processed later again.
		log.WithError(err).Errorf("Error syncing Service LoadBalancer %v: %v", key, err)
		workqueue.AddRateLimited(key)
		return
	}

	workqueue.Forget(key)

	// Report to an external entity that, even after several retries, we could not successfully process this key
	uruntime.HandleError(err)
	log.WithError(err).Errorf("Dropping Service LoadBalancer %q out of the queue: %v", key, err)
}

// assignIP tries to assign IP address for Service.
func (c *loadBalancerController) assignIP(svc *v1.Service) error {
	if len(c.ipPools) == 0 {
		return nil
	}
	handle := createHandle(svc)

	metadataAttrs := map[string]string{
		ipam.AttributeService:   svc.Name,
		ipam.AttributeNamespace: svc.Namespace,
		ipam.AttributeType:      string(svc.Spec.Type),
		ipam.AttributeTimestamp: time.Now().UTC().String(),
	}

	// User requested specific IP, attempt to allocate
	if svc.Annotations[annotationLoadBalancerIp] != "" {
		ipAddrs, err := validateAnnotation(parseAnnotation(svc.Annotations[annotationLoadBalancerIp]))
		if err != nil {
			return err
		}

		ingress := svc.Status.LoadBalancer.Ingress

		for _, addrs := range ipAddrs {
			for _, lbingress := range ingress {
				// We must be trying to assign missing address due to an error,
				// skip this assignment as it's already assigned and move onto the next one
				if lbingress.IP == addrs.String() {
					continue
				}
			}

			ipamArgs := ipam.AssignIPArgs{
				IP:       addrs,
				Hostname: api.VirtualLoadBalancer,
				HandleID: &handle,
				Attrs:    metadataAttrs,
			}

			err = c.calicoClient.IPAM().AssignIP(c.ctx, ipamArgs)
			if err != nil {
				log.WithField("ip", addrs).WithError(err).Warn("failed to assign ip to node")
				return err
			}

			ingress = append(ingress, v1.LoadBalancerIngress{IP: addrs.String()})
		}

		svc.Status.LoadBalancer.Ingress = ingress
		_, err = c.clientSet.CoreV1().Services(svc.Namespace).UpdateStatus(c.ctx, svc, metav1.UpdateOptions{})
		return err
	}

	// Build AssignArgs based on Service IP family attr
	num4 := 0
	num6 := 0

	for _, ipFamily := range svc.Spec.IPFamilies {
		if ipFamily == v1.IPv4Protocol {
			num4++
		}
		if ipFamily == v1.IPv6Protocol {
			num6++
		}
	}

	// Check if IP from ipfamily is already assigned, skip it as we're trying to assign only the missing one.
	// This can happen when error happened during the initial assignment, and now we're trying to assign ip again from the syncIPAM func
	ingressList := svc.Status.LoadBalancer.Ingress
	if ingressList != nil {
		for _, ingress := range ingressList {
			if ip := cnet.ParseIP(ingress.IP); ip != nil {
				if ip.To4() != nil {
					num4 = 0
				}
				if ip.To16() != nil {
					num6 = 0
				}
			}
		}

		if num4 == 0 && num6 == 0 {
			return errors.New("No new IPs to assign, Service already has ipv4 and ipv6 address")
		}
	}

	args := ipam.AutoAssignArgs{
		Num4:        num4,
		Num6:        num6,
		IntendedUse: api.IPPoolAllowedUseLoadBalancer,
		Hostname:    api.VirtualLoadBalancer,
		HandleID:    &handle,
		Attrs:       metadataAttrs,
	}

	if svc.Annotations[annotationIpv4Pools] != "" {
		args.IPv4Pools, _ = c.resolvePools(parseAnnotation(svc.Annotations[annotationIpv4Pools]), true)
		if args.IPv4Pools == nil {
			return errors.New("no IPv4 pools found from annotation")
		}
	}

	if svc.Annotations[annotationIpv6Pools] != "" {
		args.IPv6Pools, _ = c.resolvePools(parseAnnotation(svc.Annotations[annotationIpv6Pools]), false)
		if args.IPv6Pools == nil {
			return errors.New("no IPv6 pools found from annotation")
		}
	}

	v4Assignments, v6assignments, err := c.calicoClient.IPAM().AutoAssign(c.ctx, args)
	if err != nil {
		log.WithField("svc", svc.Name).WithError(err).Warn("error on assigning IPAM to service")
	}

	var ingress []v1.LoadBalancerIngress

	if v4Assignments != nil {
		for _, assignment := range v4Assignments.IPs {
			ingress = append(ingress, v1.LoadBalancerIngress{
				IP: assignment.IP.String(),
			})
		}
	}

	if v6assignments != nil {
		for _, assignment := range v6assignments.IPs {
			ingress = append(ingress, v1.LoadBalancerIngress{
				IP: assignment.IP.String(),
			})
		}
	}

	svc.Status.LoadBalancer.Ingress = ingress

	_, err = c.clientSet.CoreV1().Services(svc.Namespace).UpdateStatus(c.ctx, svc, metav1.UpdateOptions{})
	if err != nil {
		log.Infof("LoadBalancer Error updating service %s/%s: %v", svc.Namespace, svc.Name, err)
		return err
	}
	return nil
}

// releaseIP tries to release all IPs allocated with the Service unique handle
func (c *loadBalancerController) releaseIP(handle string) error {
	log.Info("Service type LoadBalancer deleted, releasing assigned IP address")

	err := c.calicoClient.IPAM().ReleaseByHandle(c.ctx, handle)
	if err != nil {
		log.Errorf("error on removing assigned IP for handle %s", handle)
		return err
	}
	return nil
}

// checkStatus determines what has changed about the Service. Service can change it's type, if that happens
// we want to release the IP previously used. If calico annotations have changed we try to assign new IP address to the Service
func (c *loadBalancerController) checkStatus(svc *v1.Service) error {
	// Service type has changed, release the ip by the handle
	if svc.Spec.Type != v1.ServiceTypeLoadBalancer {
		return c.releaseIP(createHandle(svc))
	} else {
		// Type is load balancer, this means calico annotations have changed, and we need to re-assign IPs from this service
		err := c.releaseIP(createHandle(svc))
		if err != nil {
			return err
		}
		// We can only assign new IP if we are still managing the address assignment
		if isCalicoManagedLoadBalancer(svc, c.cfg.AssignIPs) {
			return c.assignIP(svc)
		} else {
			// No longer managed by Calico, clean up our assigned IP from Service
			svc.Status.LoadBalancer.Ingress = []v1.LoadBalancerIngress{}

			_, err = c.clientSet.CoreV1().Services(svc.Namespace).UpdateStatus(c.ctx, svc, metav1.UpdateOptions{})
			if err != nil {
				return err
			}
		}
		return nil
	}
}

// resolvePools valid IPpool range when specific pool is requested by the user
func (c *loadBalancerController) resolvePools(pools []string, isv4 bool) ([]cnet.IPNet, error) {
	// Iterate through the provided pools. If it parses as a CIDR, just use that.
	// If it does not parse as a CIDR, then attempt to lookup an IP pool with a matching name.
	result := []cnet.IPNet{}
	for _, p := range pools {
		_, cidr, err := net.ParseCIDR(p)
		if err != nil {
			// Didn't parse as a CIDR - check if it's the name
			// of a configured IP pool.
			for _, ipp := range c.ipPools {
				if ipp.Name == p {
					// Found a match. Use the CIDR from the matching pool.
					_, cidr, err = net.ParseCIDR(ipp.Spec.CIDR)
					if err != nil {
						return nil, fmt.Errorf("failed to parse IP pool cidr: %s", err)
					}
					log.Infof("Resolved pool name %s to cidr %s", ipp.Name, cidr)
				}
			}

			if cidr == nil {
				// Unable to resolve this pool to a CIDR - return an error.
				return nil, fmt.Errorf("error parsing pool %q: %s", p, err)
			}
		}

		ip := cidr.IP
		if isv4 && ip.To4() == nil {
			return nil, fmt.Errorf("%q isn't a IPv4 address", ip)
		}
		if !isv4 && ip.To4() != nil {
			return nil, fmt.Errorf("%q isn't a IPv6 address", ip)
		}
		result = append(result, cnet.IPNet{IPNet: *cidr})
	}
	return result, nil
}

// isCalicoManagedLoadBalancer returns if Calico should try to assign IP address for the LoadBalancer
// We assign IPs only if the loadBalancer controller assignIP is set to AllService
// or in RequestedOnlyServices if the service has calico annotation
func isCalicoManagedLoadBalancer(svc *v1.Service, assignIPs string) bool {
	if svc.Spec.Type == v1.ServiceTypeLoadBalancer {
		if assignIPs == api.AllServices {
			return true
		}

		if assignIPs == api.RequestedServicesOnly {
			if svc.Annotations[annotationIpv4Pools] != "" ||
				svc.Annotations[annotationIpv6Pools] != "" ||
				svc.Annotations[annotationLoadBalancerIp] != "" {
				return true
			}
		}
	}
	return false
}

// validateAnnotation checks if the ips specified in the calico annotation are valid.
// Each service can have at most one ipv4 and one ipv6 address
func validateAnnotation(ipAddrs []string) ([]cnet.IP, error) {
	parsedIPs := make([]cnet.IP, 0)
	ipv4 := 0
	ipv6 := 0
	for _, ipAddr := range ipAddrs {
		curr := cnet.ParseIP(ipAddr)
		if curr == nil {
			return nil, errors.New(fmt.Sprintf("Could not parse %s as a valid IP address", curr))
		}
		if curr.To4() != nil {
			ipv4++
		} else if curr.To16() != nil {
			ipv6++
		}
		parsedIPs = append(parsedIPs, *curr)
	}

	if ipv6 > 1 || ipv4 > 1 {
		return nil, errors.New(fmt.Sprintf("At max only one ipv4 and one ipv6 address can be specified. Recieved %d ipv4 and %d ipv6 addresses", ipv4, ipv6))
	}
	return parsedIPs, nil
}

func parseAnnotation(str string) []string {
	str = strings.TrimPrefix(str, "[")
	str = strings.TrimSuffix(str, "]")
	return strings.Split(str, ",")
}

// createHandle Returns a handle to use for IP allocation for the service
func createHandle(svc *v1.Service) string {
	handle := strings.ToLower(fmt.Sprintf("lb.%s.%s", svc.Name, svc.UID))
	if len(handle) > k8svalidation.DNS1123SubdomainMaxLength {
		return handle[:k8svalidation.DNS1123SubdomainMaxLength]
	}
	return handle
}

func kick(c chan<- interface{}) {
	select {
	case c <- nil:
		// pass
	default:
		// pass
	}
}
