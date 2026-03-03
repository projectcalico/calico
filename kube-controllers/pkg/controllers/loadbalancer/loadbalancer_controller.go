// Copyright (c) 2019-2025 Tigera, Inc. All rights reserved.
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
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"
	"regexp"
	"slices"
	"strings"
	"time"

	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	uruntime "k8s.io/apimachinery/pkg/util/runtime"
	k8svalidation "k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes"
	v1lister "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/projectcalico/calico/kube-controllers/pkg/config"
	"github.com/projectcalico/calico/kube-controllers/pkg/controllers/utils"
	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
	"github.com/projectcalico/calico/libcalico-go/lib/json"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

const (
	annotationIPv4Pools      = "projectcalico.org/ipv4pools"
	annotationIPv6Pools      = "projectcalico.org/ipv6pools"
	annotationLoadBalancerIP = "projectcalico.org/loadBalancerIPs"
	calicoLoadBalancerClass  = "calico"
	timer                    = 5 * time.Minute
)

type serviceKey struct {
	handle    string
	name      string
	namespace string
}

type allocationTracker struct {
	servicesByIP map[string]serviceKey
	ipsByService map[serviceKey]map[string]bool
	ipsByBlock   map[string]map[string]bool
}

func (t *allocationTracker) assignAddressToBlock(key string, ip string, svcKey serviceKey) {
	if t.ipsByBlock[key] == nil {
		t.ipsByBlock[key] = make(map[string]bool)
	}
	t.ipsByBlock[key][ip] = true
	t.assignAddressToService(svcKey, ip)
}

func (t *allocationTracker) releaseAddressFromBlock(key string, ip string) {
	delete(t.ipsByBlock[key], ip)
	t.releaseAddressFromService(t.servicesByIP[ip], ip)
}

func (t *allocationTracker) deleteBlock(key string) {
	for ip := range t.ipsByBlock[key] {
		t.releaseAddressFromService(t.servicesByIP[ip], ip)
	}
	delete(t.ipsByBlock, key)
}

func (t *allocationTracker) assignAddressToService(svcKey serviceKey, ip string) {
	t.servicesByIP[ip] = svcKey

	if t.ipsByService[svcKey] == nil {
		t.ipsByService[svcKey] = make(map[string]bool)
	}
	t.ipsByService[svcKey][ip] = true
}

func (t *allocationTracker) releaseAddressFromService(svcKey serviceKey, ip string) {
	delete(t.servicesByIP, ip)
	delete(t.ipsByService[svcKey], ip)
}

func (t *allocationTracker) deleteService(svcKey serviceKey) {
	for ip := range t.ipsByService[svcKey] {
		delete(t.servicesByIP, ip)
	}
	delete(t.ipsByService, svcKey)
}

// loadBalancerController implements the Controller interface for managing Kubernetes services
// and endpoints, syncing them to the Calico datastore as NetworkSet.
type loadBalancerController struct {
	calicoClient      client.Interface
	dataFeed          *utils.DataFeed
	cfg               config.LoadBalancerControllerConfig
	clientSet         kubernetes.Interface
	syncerUpdates     chan any
	syncStatus        bapi.SyncStatus
	syncChan          chan any
	serviceUpdates    chan serviceKey
	ipPools           map[string]api.IPPool
	serviceInformer   cache.SharedIndexInformer
	serviceLister     v1lister.ServiceLister
	namespaceInformer cache.SharedIndexInformer
	namespaceLister   v1lister.NamespaceLister
	allocationTracker allocationTracker
	datastoreUpgraded bool
}

// NewLoadBalancerController returns a controller which manages Service LoadBalancer objects.
func NewLoadBalancerController(clientset kubernetes.Interface, calicoClient client.Interface, cfg config.LoadBalancerControllerConfig, serviceInformer cache.SharedIndexInformer, namespaceInformer cache.SharedIndexInformer, dataFeed *utils.DataFeed) *loadBalancerController {
	c := &loadBalancerController{
		calicoClient:      calicoClient,
		cfg:               cfg,
		clientSet:         clientset,
		dataFeed:          dataFeed,
		syncerUpdates:     make(chan any, utils.BatchUpdateSize),
		syncChan:          make(chan any, 1),
		serviceUpdates:    make(chan serviceKey, utils.BatchUpdateSize),
		ipPools:           make(map[string]api.IPPool),
		serviceInformer:   serviceInformer,
		serviceLister:     v1lister.NewServiceLister(serviceInformer.GetIndexer()),
		namespaceInformer: namespaceInformer,
		namespaceLister:   v1lister.NewNamespaceLister(namespaceInformer.GetIndexer()),
		allocationTracker: allocationTracker{
			servicesByIP: make(map[string]serviceKey),
			ipsByService: make(map[serviceKey]map[string]bool),
			ipsByBlock:   make(map[string]map[string]bool),
		},
	}

	c.RegisterWith(c.dataFeed)

	_, err := c.serviceInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.onServiceAdd,
		UpdateFunc: c.onServiceUpdate,
		DeleteFunc: c.onServiceDelete,
	})
	if err != nil {
		log.WithError(err).Fatal("Failed to add event handler for Service LoadBalancer")
		return nil
	}
	return c
}

// Run starts the controller.
func (c *loadBalancerController) Run(stopCh chan struct{}) {
	defer uruntime.HandleCrash()

	log.Debug("Waiting to sync with Kubernetes API (Services and Namespaces)")
	if !cache.WaitForCacheSync(stopCh, c.serviceInformer.HasSynced, c.namespaceInformer.HasSynced) {
		log.Info("Failed to sync resources, received signal for controller to shut down.")
		return
	}
	log.Debug("Finished syncing with Kubernetes API (Services and Namespaces)")

	go c.acceptScheduledRequests(stopCh)

	<-stopCh
	log.Info("Stopping Service controller")
}

func (c *loadBalancerController) onServiceAdd(objNew any) {
	if svc, ok := objNew.(*v1.Service); ok {
		svcKey, err := serviceKeyFromService(svc)
		if err != nil {
			return
		}
		c.serviceUpdates <- *svcKey
	}
}

func (c *loadBalancerController) onServiceUpdate(objNew any, objOld any) {
	if svc, ok := objNew.(*v1.Service); ok {
		svcKey, err := serviceKeyFromService(svc)
		if err != nil {
			return
		}
		c.serviceUpdates <- *svcKey
	}
}

func (c *loadBalancerController) onServiceDelete(objNew any) {
	if svc, ok := objNew.(*v1.Service); ok {
		svcKey, err := serviceKeyFromService(svc)
		if err != nil {
			return
		}
		c.serviceUpdates <- *svcKey
	}
}

func (c *loadBalancerController) RegisterWith(f *utils.DataFeed) {
	f.RegisterForNotification(model.BlockKey{}, c.onUpdate)
	f.RegisterForNotification(model.ResourceKey{}, c.onUpdate)
	f.RegisterForSyncStatus(c.onStatusUpdate)
}

func (c *loadBalancerController) onStatusUpdate(s bapi.SyncStatus) {
	c.syncerUpdates <- s
}

func (c *loadBalancerController) onUpdate(update bapi.Update) {
	switch update.Key.(type) {
	case model.ResourceKey:
		switch update.KVPair.Key.(model.ResourceKey).Kind {
		case api.KindIPPool:
			c.syncerUpdates <- update.KVPair
		}
	case model.BlockKey:
		c.syncerUpdates <- update.KVPair
	}
}

func (c *loadBalancerController) acceptScheduledRequests(stopCh <-chan struct{}) {
	log.Infof("Will run periodic IPAM sync every %s", timer)
	t := time.NewTicker(timer)
	for {
		if err := c.ensureDatastoreUpgraded(); err != nil {
			log.WithError(err).Error("Failed to upgrade load balancer's IPAM block affinities.  Unable to sync load balancer services.  Will retry.")
			time.Sleep(10 * time.Second)
			continue
		}
		break
	}
	for {
		select {
		case update := <-c.syncerUpdates:
			c.handleUpdate(update)
		case <-t.C:
			log.Infof("Running periodic IPAM sync of Service LoadBalancer")
			c.syncIPAM()
		case <-c.syncChan:
			c.syncIPAM()
		case svcKey := <-c.serviceUpdates:
			logEntry := log.WithFields(log.Fields{"controller": "LoadBalancer", "type": "serviceUpdate"})
			utils.ProcessBatch(c.serviceUpdates, svcKey, c.syncService, logEntry)
		case <-stopCh:
			return
		}
	}
}

func (c *loadBalancerController) handleUpdate(update any) {
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
				c.handleIPPoolUpdate(update)
				kick(c.syncChan)
				return
			}
		case model.BlockKey:
			c.handleBlockUpdate(update)
			kick(c.syncChan)
			return
		}
	}
}

func (c *loadBalancerController) handleBlockUpdate(kvp model.KVPair) {
	block, ok := kvp.Value.(*model.AllocationBlock)
	if !ok {
		log.WithField("key", kvp.Key.String()).Errorf("unexpected type for AllocationBlock value: %T", kvp.Value)
		c.allocationTracker.deleteBlock(kvp.Key.String())
		return
	}
	if block == nil {
		c.allocationTracker.deleteBlock(kvp.Key.String())
		return
	}

	affinity := block.Affinity
	key := kvp.Key.String()

	if affinity == nil || *affinity != fmt.Sprintf("%s:%s", ipam.AffinityTypeVirtual, api.VirtualLoadBalancer) {
		c.allocationTracker.deleteBlock(key)
		return
	}

	allocatedIPs := make(map[string]bool)

	for i := range block.Allocations {
		if block.Allocations[i] != nil {
			if _, ok := block.Attributes[*block.Allocations[i]].ActiveOwnerAttrs[ipam.AttributeNamespace]; !ok {
				log.Warnf("no %s attribute found for block with handle %s", ipam.AttributeNamespace, *block.Attributes[*block.Allocations[i]].HandleID)
				continue
			}

			if _, ok := block.Attributes[*block.Allocations[i]].ActiveOwnerAttrs[ipam.AttributeService]; !ok {
				log.Warnf("no %s attribute found for block with handle %s", ipam.AttributeService, *block.Attributes[*block.Allocations[i]].HandleID)
				continue
			}

			ip := block.OrdinalToIP(i)
			svcKey := serviceKey{
				handle:    *block.Attributes[*block.Allocations[i]].HandleID,
				namespace: block.Attributes[*block.Allocations[i]].ActiveOwnerAttrs[ipam.AttributeNamespace],
				name:      block.Attributes[*block.Allocations[i]].ActiveOwnerAttrs[ipam.AttributeService],
			}

			c.allocationTracker.assignAddressToBlock(key, ip.String(), svcKey)
			allocatedIPs[ip.String()] = true
		}
	}

	for ip := range c.allocationTracker.ipsByBlock[key] {
		if _, ok := allocatedIPs[ip]; !ok {
			c.allocationTracker.releaseAddressFromBlock(key, ip)
		}
	}
}

func (c *loadBalancerController) handleIPPoolUpdate(kvp model.KVPair) {
	if kvp.Value == nil {
		delete(c.ipPools, kvp.Key.String())
		return
	}

	pool := kvp.Value.(*api.IPPool)

	if pool.DeletionTimestamp != nil {
		// Pool is being deleted, remove it from our map.
		delete(c.ipPools, kvp.Key.String())
		return
	}

	if slices.Contains(pool.Spec.AllowedUses, api.IPPoolAllowedUseLoadBalancer) {
		c.ipPools[kvp.Key.String()] = *pool
	} else {
		delete(c.ipPools, kvp.Key.String())
	}
}

// syncIPAM has two main uses. It functions as a garbage collection for leaked IP addresses from Service LoadBalancer
// The other use case is to update IPs for any Service LoadBalancer that do not have IPs assigned, this could be caused by the user
// creating Service LoadBalancer before any valid pools were created
func (c *loadBalancerController) syncIPAM() {
	if c.syncStatus != bapi.InSync {
		log.WithField("status", c.syncStatus).Debug("Have not yet received InSync notification, skipping IPAM sync.")
		return
	}

	svcKeys := make(map[serviceKey]bool)
	services, err := c.serviceLister.Services("").List(labels.Everything())
	if err != nil {
		log.WithError(err).Error("Error getting service list")
		return
	}

	for _, svc := range services {
		if IsCalicoManagedLoadBalancer(svc, c.cfg.AssignIPs) {
			svcKey, err := serviceKeyFromService(svc)
			if err != nil {
				log.WithError(err).Error("Error getting service object from service")
				continue
			}
			svcKeys[*svcKey] = true
		}
	}

	for svcKey := range c.allocationTracker.ipsByService {
		svcKeys[svcKey] = true
	}

	for svcKey := range svcKeys {
		c.syncService(svcKey)
	}
}

func (c *loadBalancerController) ensureDatastoreUpgraded() error {
	if c.datastoreUpgraded {
		return nil
	}
	err := c.calicoClient.IPAM().UpgradeHost(context.Background(), api.VirtualLoadBalancer)
	if err != nil {
		return err
	}
	c.datastoreUpgraded = true
	return nil
}

// syncService does the following:
// - Releases any IP addresses in the IPAM DB associated with the Service that are not in the Service status.
// - Allocates any addresses necessary to satisfy the Service LB request
// - Updates the controllers internal state tracking of which IP addresses are allocated.
// - Updates the IP addresses in the Service Status to match the IPAM DB.
func (c *loadBalancerController) syncService(svcKey serviceKey) {
	if len(c.ipPools) == 0 {
		if _, ok := c.allocationTracker.ipsByService[svcKey]; ok {
			// Last LoadBalancer IPPool was deleted, and we have previously assigned IPs to this service. We need to release the IPs now and update the service status
			log.Warnf("No ippools with allowedUse LoadBalancer found. Releasing previously assigned IPs for Service %s/%s", svcKey.namespace, svcKey.name)
			err := c.releaseIPsByHandle(svcKey)
			if err != nil {
				log.WithError(err).Errorf("Error releasing previously assigned IPs for Service %s/%s", svcKey.namespace, svcKey.name)
				return
			}

			svc, err := c.serviceLister.Services(svcKey.namespace).Get(svcKey.name)
			if apierrors.IsNotFound(err) {
				// No need to update the status, service no longer exists
				return
			} else if err != nil {
				log.WithError(err).Errorf("Error getting service %s/%s", svcKey.namespace, svcKey.name)
				return
			}

			err = c.updateServiceStatus(svc, svcKey)
			if err != nil {
				log.WithError(err).Errorf("Failed to update service status for %s/%s", svc.Namespace, svc.Name)
				return
			}
		} else {
			// We can skip service sync if there are no ippools defined that can be used for Service LoadBalancer
			svc, err := c.serviceLister.Services(svcKey.namespace).Get(svcKey.name)
			if apierrors.IsNotFound(err) {
				return
			}
			if err != nil {
				log.WithError(err).Errorf("Error getting service %s/%s", svcKey.namespace, svcKey.name)
				return
			}
			if IsCalicoManagedLoadBalancer(svc, c.cfg.AssignIPs) {
				// Only warn the user if the service is managed by Calico and should have IP assigned
				log.Warnf("No ippools with allowedUse LoadBalancer found. Skipping IP assignment for Service %s/%s", svcKey.namespace, svcKey.name)
			}
		}
		return
	}

	svc, err := c.serviceLister.Services(svcKey.namespace).Get(svcKey.name)
	if apierrors.IsNotFound(err) {
		// service was deleted, we release all IPs that we have assigned to the service
		err = c.releaseIPsByHandle(svcKey)
		if err != nil {
			log.WithError(err).Errorf("Failed to release IP for %s/%s", svcKey.namespace, svcKey.name)
			return
		}
		return
	}
	if err != nil {
		log.WithError(err).Error("Error getting service from serviceLister")
		return
	}

	if !IsCalicoManagedLoadBalancer(svc, c.cfg.AssignIPs) {
		if c.allocationTracker.ipsByService[svcKey] == nil {
			// not managed by Calico, and no IP for the service is in our IPAM storage. It's safe to return
			return
		}

		// Calico assigned IP previously, no longer managed by us, release IPs assigned by calico and update service status
		// this also catches a case where the service used to be a LoadBalancer but no longer is
		calicoIPs := c.allocationTracker.ipsByService[svcKey]
		err = c.releaseIPsByHandle(svcKey)
		if err != nil {
			log.WithError(err).Errorf("Error releasing previously assigned IPs for Service %s/%s", svcKey.namespace, svcKey.name)
			return
		}

		if svc.Spec.Type == v1.ServiceTypeLoadBalancer {
			err = c.removeCalicoIPFromStatus(svc, calicoIPs)
			if err != nil {
				log.WithError(err).Errorf("Error updating status for service %s/%s", svcKey.namespace, svcKey.name)
				return
			}
		}

		return
	}

	loadBalancerIPs, ipv4pools, ipv6pools, err := c.parseAnnotations(svc.Annotations)
	if err != nil {
		log.WithError(err).Errorf("Failed to parse annotations for service %s/%s", svc.Namespace, svc.Name)
		return
	}

	if loadBalancerIPs != nil {
		// Check that service has assigned IPs to the ones specified in annotations
		lbIPs := make(map[string]bool)
		for _, ip := range loadBalancerIPs {
			lbIPs[ip.String()] = true
		}
		for ip := range c.allocationTracker.ipsByService[svcKey] {
			if _, ok := lbIPs[ip]; !ok {
				log.Infof("Removing IP assignment (%s) for Service %s/%s; no longer in annotations.", ip, svc.Namespace, svc.Name)
				err = c.releaseIP(svcKey, ip)
				if err != nil {
					log.WithError(err).Errorf("Failed to release IP for %s/%s", svc.Namespace, svc.Name)
					return
				}
			}
		}
	} else if ipv4pools != nil || ipv6pools != nil {
		// If pool annotations are specified, we need to check that the IPs assigned are from the specified pools
		for ip := range c.allocationTracker.ipsByService[svcKey] {
			if !poolContains(ip, ipv4pools) && !poolContains(ip, ipv6pools) {
				log.Infof("Removing IP assignment (%s) for Service %s/%s: not from specified pools (%v, %v).", ip, svc.Namespace, svc.Name, ipv4pools, ipv6pools)
				err = c.releaseIP(svcKey, ip)
				if err != nil {
					log.WithError(err).Errorf("Failed to release IP for %s/%s", svc.Namespace, svc.Name)
					return
				}
			}
		}
	} else {
		// No annotations are specified, check that the IPs assigned aren't from Manual pool from earlier assignment
		for ip := range c.allocationTracker.ipsByService[svcKey] {
			pool, err := c.poolForIP(ip)
			if err != nil {
				log.WithError(err).Error("Error syncing service object, will retry during next IPAM sync")
				return
			}
			if pool != nil {
				// We want to release the address if annotation changed and we are no longer requesting IP from manual pool,
				// if pool is nil we can skip this and the address will be removed during the next IPAM sync
				//
				// AssignmentMode should never be nil due to defaulting, but we check it just in case.
				if pool.Spec.AssignmentMode != nil && *pool.Spec.AssignmentMode == api.Manual {
					log.Infof("Removing IP assignment (%s) for Service %s/%s. No annotations but IP is from a 'Manual' IP pool.", ip, svc.Namespace, svc.Name)
					err = c.releaseIP(svcKey, ip)
					if err != nil {
						log.WithError(err).Errorf("Failed to release IP for %s/%s", svc.Namespace, svc.Name)
						return
					}
				}
			}
		}
	}

	if c.needsIPsAssigned(svc, svcKey) {
		log.Infof("Service requires an IP assignment %s/%s", svc.Namespace, svc.Name)
		ips, err := c.assignIP(svc)
		if err != nil {
			log.WithError(err).Errorf("Failed to assign IP for %s/%s", svc.Namespace, svc.Name)
		} else {
			log.Infof("Assigned IPs %s for Service %s/%s", ips, svc.Namespace, svc.Name)
		}
	}

	if c.needsStatusUpdate(svc, svcKey) {
		err = c.updateServiceStatus(svc, svcKey)
		if err != nil {
			log.WithError(err).Errorf("Failed to update service status for %s/%s", svc.Namespace, svc.Name)
			return
		}
	}
}

// needsIPsAssigned determines if service IPFamilyPolicy is requirement is fulfilled by number of assigned IPs in IPAM storage
// We assume that the given Service is a LoadBalancer type and was checked by the calling code.
func (c *loadBalancerController) needsIPsAssigned(svc *v1.Service, svcKey serviceKey) bool {
	switch *svc.Spec.IPFamilyPolicy {
	case v1.IPFamilyPolicySingleStack:
		return len(c.allocationTracker.ipsByService[svcKey]) != 1
	case v1.IPFamilyPolicyRequireDualStack, v1.IPFamilyPolicyPreferDualStack:
		return len(c.allocationTracker.ipsByService[svcKey]) != 2
	default:
		return true
	}
}

// needsStatusUpdate checks if the service needs status update.
// service needs status update if the IPs in our IPAM tracker do not match what's in the status of the service
func (c *loadBalancerController) needsStatusUpdate(svc *v1.Service, svcKey serviceKey) bool {
	if len(svc.Status.LoadBalancer.Ingress) != len(c.allocationTracker.ipsByService[svcKey]) {
		return true
	}

	for _, ingress := range svc.Status.LoadBalancer.Ingress {
		if _, ok := c.allocationTracker.ipsByService[svcKey][ingress.IP]; !ok {
			return true
		}
	}

	return false
}

// updateServiceStatus updates the status of the service with IPs from our IPAM storage
func (c *loadBalancerController) updateServiceStatus(svc *v1.Service, svcKey serviceKey) error {
	var svcIngress []v1.LoadBalancerIngress
	for ip := range c.allocationTracker.ipsByService[svcKey] {
		svcIngress = append(svcIngress, v1.LoadBalancerIngress{IP: ip})
	}
	svc.Status.LoadBalancer.Ingress = svcIngress

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := c.clientSet.CoreV1().Services(svc.Namespace).UpdateStatus(ctx, svc, metav1.UpdateOptions{})
	if err != nil {
		log.WithError(err).Errorf("Failed to update service status %s/%s", svc.Namespace, svc.Name)
		return err
	}

	return nil
}

// removeCalicoIPFromStatus updates the service status by removing IPs allocated by Calico previously. We assume that another IPAM
// service is now managing the service status and keep any IPs not allocated by us in the service status
func (c *loadBalancerController) removeCalicoIPFromStatus(svc *v1.Service, calicoIPs map[string]bool) error {
	var svcIngress []v1.LoadBalancerIngress
	for _, ingress := range svc.Status.LoadBalancer.Ingress {
		if _, ok := calicoIPs[ingress.IP]; !ok {
			svcIngress = append(svcIngress, ingress)
		}
	}
	svc.Status.LoadBalancer.Ingress = svcIngress

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := c.clientSet.CoreV1().Services(svc.Namespace).UpdateStatus(ctx, svc, metav1.UpdateOptions{})
	if err != nil {
		log.WithError(err).Errorf("Failed to update service status %s/%s", svc.Namespace, svc.Name)
		return err
	}

	return nil
}

// assignIP tries to assign IP address for Service.
func (c *loadBalancerController) assignIP(svc *v1.Service) ([]string, error) {
	svcKey, err := serviceKeyFromService(svc)
	if err != nil {
		return nil, err
	}

	loadBalancerIPs, ipv4Pools, ipv6Pools, err := c.parseAnnotations(svc.Annotations)
	if err != nil {
		return nil, err
	}

	var assignedIPs []string

	metadataAttrs := map[string]string{
		ipam.AttributeService:   svc.Name,
		ipam.AttributeNamespace: svc.Namespace,
		ipam.AttributeType:      string(svc.Spec.Type),
		ipam.AttributeTimestamp: time.Now().UTC().String(),
	}

	if loadBalancerIPs != nil {
		// User requested specific IP, attempt to allocate
		log.Infof("Trying to assign requested IPs %v to Service %s/%s", loadBalancerIPs, svc.Namespace, svc.Name)
		for _, addr := range loadBalancerIPs {
			if _, exists := c.allocationTracker.ipsByService[*svcKey][addr.String()]; exists {
				// We must be trying to assign missing address due to an error,
				// skip this assignment as it's already assigned and move onto the next one
				continue
			}

			ipamArgs := ipam.AssignIPArgs{
				IP:          addr,
				Hostname:    api.VirtualLoadBalancer,
				HandleID:    &svcKey.handle,
				Attrs:       metadataAttrs,
				IntendedUse: api.IPPoolAllowedUseLoadBalancer,
			}

			err = c.calicoClient.IPAM().AssignIP(context.Background(), ipamArgs)
			if err != nil {
				log.WithFields(log.Fields{"ip": addr, "svc": svc.Name, "ns": svc.Namespace}).WithError(err).Warn("failed to assign ip to service")
				return nil, err
			}
			assignedIPs = append(assignedIPs, addr.String())
			c.allocationTracker.assignAddressToService(*svcKey, addr.String())
		}
		return assignedIPs, err
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
	log.Infof("Service %s/%s requires %v IPv4 and %v IPv6 addresses.", svc.Namespace, svc.Name, num4, num6)

	// Check if IP from ipFamily is already assigned, skip it as we're trying to assign only the missing one.
	// This can happen when error happened during the initial assignment, and now we're trying to assign ip again from the syncIPAM func
	for ingress := range c.allocationTracker.ipsByService[*svcKey] {
		if ip := cnet.ParseIP(ingress); ip != nil {
			if ip.To4() != nil {
				log.Infof("Service already has an IPv4 address: %s", ip.String())
				num4 = 0
			}
			if ip.To16() != nil {
				log.Infof("Service already has an IPv6 address: %s", ip.String())
				num6 = 0
			}
		}
	}

	if num4 == 0 && num6 == 0 {
		log.WithFields(log.Fields{"svc": svc.Name}).Info("No new IPs to assign, Service already has desired LB addresses")
		return nil, nil
	}

	// Get the namespace object for namespaceSelector support
	namespaceObj, err := c.namespaceLister.Get(svc.Namespace)
	if err != nil {
		log.WithError(err).WithField("namespace", svc.Namespace).Error("Failed to get namespace for LoadBalancer IP assignment")
		return nil, fmt.Errorf("failed to get namespace %s: %w", svc.Namespace, err)
	}

	args := ipam.AutoAssignArgs{
		Num4:        num4,
		Num6:        num6,
		IntendedUse: api.IPPoolAllowedUseLoadBalancer,
		Hostname:    api.VirtualLoadBalancer,
		HandleID:    &svcKey.handle,
		Attrs:       metadataAttrs,
		Namespace:   namespaceObj,
	}

	if ipv4Pools != nil {
		args.IPv4Pools = ipv4Pools
	}

	if ipv6Pools != nil {
		args.IPv6Pools = ipv6Pools
	}

	v4Assignments, v6assignments, err := c.calicoClient.IPAM().AutoAssign(context.Background(), args)
	if err != nil {
		log.WithField("svc", svc.Name).WithError(err).Warn("error on assigning IP address to service")
		return nil, err
	}

	if v4Assignments != nil {
		for _, assignment := range v4Assignments.IPs {
			log.Infof("Service %s/%s now has IP: %s", svcKey.namespace, svcKey.name, assignment.IP.String())
			assignedIPs = append(assignedIPs, assignment.IP.String())
			c.allocationTracker.assignAddressToService(*svcKey, assignment.IP.String())
		}
	}

	if v6assignments != nil {
		for _, assignment := range v6assignments.IPs {
			log.Infof("Service %s/%s now has IP: %s", svcKey.namespace, svcKey.name, assignment.IP.String())
			assignedIPs = append(assignedIPs, assignment.IP.String())
			c.allocationTracker.assignAddressToService(*svcKey, assignment.IP.String())
		}
	}

	return assignedIPs, nil
}

// releaseIPByHandle tries to release all IPs allocated with the Service unique handle
func (c *loadBalancerController) releaseIPsByHandle(svcKey serviceKey) error {
	log.Infof("Releasing all IPs assigned to Service %s/%s", svcKey.namespace, svcKey.name)

	err := c.calicoClient.IPAM().ReleaseByHandle(context.Background(), svcKey.handle)
	if err != nil {
		log.Errorf("error on removing assigned IPs for handle %s", svcKey.handle)
		return err
	}

	c.allocationTracker.deleteService(svcKey)
	return nil
}

func (c *loadBalancerController) releaseIP(svcKey serviceKey, ip string) error {
	releaseOptions := ipam.ReleaseOptions{
		Address: ip,
	}
	_, _, err := c.calicoClient.IPAM().ReleaseIPs(context.Background(), releaseOptions)
	if err != nil {
		log.Errorf("error on removing assigned IP %s", ip)
		return err
	}

	c.allocationTracker.releaseAddressFromService(svcKey, ip)
	return nil
}

// resolvePools valid IPPool range when specific pool is requested by the user
func (c *loadBalancerController) resolvePools(poolIDs []string, isv4 bool) ([]cnet.IPNet, error) {
	// Iterate through the provided poolIDs. If it parses as a CIDR, just use that.
	// If it does not parse as a CIDR, then attempt to lookup an IP pool with a matching name.
	poolCIDRs := []cnet.IPNet{}
	for _, p := range poolIDs {
		_, cidr, err := net.ParseCIDR(p)
		if err != nil {
			// Didn't parse as a CIDR - check if it's the name
			// of a configured IP pool.
			for _, ipPool := range c.ipPools {
				if ipPool.Name == p {
					// Found a match. Use the CIDR from the matching pool.
					_, cidr, err = net.ParseCIDR(ipPool.Spec.CIDR)
					if err != nil {
						return nil, fmt.Errorf("failed to parse IP pool cidr: %s", err)
					}
					log.Infof("Resolved pool name %s to cidr %s", ipPool.Name, cidr)
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
		poolCIDRs = append(poolCIDRs, cnet.IPNet{IPNet: *cidr})
	}
	return poolCIDRs, nil
}

// IsCalicoManagedLoadBalancer returns if Calico should try to assign IP address for the LoadBalancer
// We assign IPs only if the loadBalancer controller assignIP is set to AllService
// or in RequestedOnlyServices if the service has calico annotation
func IsCalicoManagedLoadBalancer(svc *v1.Service, assignIPs api.AssignIPs) bool {
	if svc.Spec.Type != v1.ServiceTypeLoadBalancer {
		return false
	}

	if assignIPs == api.AllServices {
		if svc.Spec.LoadBalancerClass != nil && *svc.Spec.LoadBalancerClass != calicoLoadBalancerClass {
			return false
		}
		return true
	}

	if assignIPs == api.RequestedServicesOnly {
		if svc.Spec.LoadBalancerClass != nil && *svc.Spec.LoadBalancerClass == calicoLoadBalancerClass {
			return true
		}

		if svc.Annotations[annotationIPv4Pools] != "" ||
			svc.Annotations[annotationIPv6Pools] != "" ||
			svc.Annotations[annotationLoadBalancerIP] != "" {

			if svc.Spec.LoadBalancerClass != nil && *svc.Spec.LoadBalancerClass != calicoLoadBalancerClass {
				log.WithFields(log.Fields{"svc": svc.Name, "ns": svc.Namespace}).Warn("calico LoadBalancer annotation set with spec.LoadBalancerClass != calico is not supported")
				return false
			}
			return true
		}
	}
	return false
}

// parseAnnotations checks if calico annotations for the service are valid
// Each service can have at most one ipv4 and one ipv6 address
func (c *loadBalancerController) parseAnnotations(annotations map[string]string) ([]cnet.IP, []cnet.IPNet, []cnet.IPNet, error) {
	var loadBalancerIPs []cnet.IP
	var ipv4Pools []cnet.IPNet
	var ipv6Pools []cnet.IPNet

	for key, annotation := range annotations {
		switch key {
		case annotationIPv4Pools:
			poolCIDRs := []string{}
			err := json.Unmarshal([]byte(annotation), &poolCIDRs)
			if err != nil {
				return nil, nil, nil, err
			}
			ipv4Pools, err = c.resolvePools(poolCIDRs, true)
			if err != nil {
				return nil, nil, nil, err
			}
			if ipv4Pools == nil {
				return nil, nil, nil, fmt.Errorf("failed to resolve pools for IPv4 addresses from annotation")
			}
		case annotationIPv6Pools:
			poolCIDRs := []string{}
			err := json.Unmarshal([]byte(annotation), &poolCIDRs)
			if err != nil {
				return nil, nil, nil, err
			}
			ipv6Pools, err = c.resolvePools(poolCIDRs, false)
			if err != nil {
				return nil, nil, nil, err
			}
			if ipv6Pools == nil {
				return nil, nil, nil, fmt.Errorf("failed to resolve pools for IPv6 addresses from annotation")
			}
		case annotationLoadBalancerIP:
			ipAddrs := []string{}
			err := json.Unmarshal([]byte(annotation), &ipAddrs)
			if err != nil {
				return nil, nil, nil, err
			}
			ipv4 := 0
			ipv6 := 0
			for _, ipAddr := range ipAddrs {
				curr := cnet.ParseIP(ipAddr)
				if curr == nil {
					return nil, nil, nil, fmt.Errorf("could not parse %s as a valid IP address", ipAddr)
				}
				if curr.To4() != nil {
					ipv4++
				} else if curr.To16() != nil {
					ipv6++
				}
				loadBalancerIPs = append(loadBalancerIPs, *curr)
			}

			if ipv6 > 1 || ipv4 > 1 {
				return nil, nil, nil, fmt.Errorf("at max only one ipv4 and one ipv6 address can be specified. Received %d ipv4 and %d ipv6 addresses", ipv4, ipv6)
			}
		}
	}
	return loadBalancerIPs, ipv4Pools, ipv6Pools, nil
}

// serviceKeyFromService parses service into a serviceKey
func serviceKeyFromService(svc *v1.Service) (*serviceKey, error) {
	handle, err := createHandle(svc)
	if err != nil {
		return nil, err
	}

	svcKey := &serviceKey{
		handle:    handle,
		namespace: svc.Namespace,
		name:      svc.Name,
	}

	return svcKey, nil
}

// createHandle returns a handle to use for IP allocation for the service
func createHandle(svc *v1.Service) (string, error) {
	prefix := "lb-"
	handle := strings.ToLower(fmt.Sprintf("%s-%s-%s", svc.Name, svc.Namespace, svc.UID))

	hasher := sha256.New()
	_, err := hasher.Write([]byte(handle))
	if err != nil {
		log.WithError(err).Panic("Failed to generate hash from handle")
		return "", err
	}

	hash := base64.RawURLEncoding.EncodeToString(hasher.Sum(nil))
	regex := regexp.MustCompile("([-_.])")
	hash = regex.ReplaceAllString(hash, "")
	handle = prefix + hash
	if len(handle) > k8svalidation.DNS1123SubdomainMaxLength {
		handle = handle[:k8svalidation.DNS1123SubdomainMaxLength]
	}

	return handle, nil
}

// poolContains check if the given IP is part of the given pool
func poolContains(ipAddr string, cidrs []cnet.IPNet) bool {
	if cidrs == nil {
		return false
	}
	ip := net.ParseIP(ipAddr)
	if ip == nil {
		// Invalid IP address, cannot be in any pool
		log.Warnf("Invalid IP address encountered in IPAM allocation tracker: %q (treating as not in any pool)", ipAddr)
		return false
	}
	for _, cidr := range cidrs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// poolForIP searches for pool in LoadBalancer controller ipPool storage and returns a pool that contains the given ip
func (c *loadBalancerController) poolForIP(ipAddr string) (*api.IPPool, error) {
	ip := net.ParseIP(ipAddr)
	for _, ippool := range c.ipPools {
		_, cidr, err := net.ParseCIDR(ippool.Spec.CIDR)
		if err != nil {
			return nil, err
		}
		if cidr.Contains(ip) {
			return &ippool, nil
		}
	}
	return nil, nil
}

func kick(c chan<- any) {
	select {
	case c <- nil:
		// pass
	default:
		// pass
	}
}
