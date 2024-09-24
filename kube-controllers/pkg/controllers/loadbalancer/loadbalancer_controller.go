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
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	uruntime "k8s.io/apimachinery/pkg/util/runtime"
	k8svalidation "k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes"
	v1lister "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"

	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/kube-controllers/pkg/config"
	"github.com/projectcalico/calico/kube-controllers/pkg/controllers/controller"
	"github.com/projectcalico/calico/kube-controllers/pkg/controllers/node"
	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
	"github.com/projectcalico/calico/libcalico-go/lib/json"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

const (
	annotationIPv4Pools      = "projectcalico.org/ipv4pools"
	annotationIPv6Pools      = "projectcalico.org/ipv6pools"
	annotationLoadBalancerIP = "projectcalico.org/loadBalancerIPs"
	timer                    = 5 * time.Minute
)

type serviceObject struct {
	handle         string
	updateType     serviceUpdateType
	namespacedName types.NamespacedName
	service        *v1.Service
}

type serviceUpdateType string

const (
	serviceUpdateTypeADD    serviceUpdateType = "ADD"
	serviceUpdateTypeUPDATE serviceUpdateType = "UPDATE"
	serviceUpdateTypeDELETE serviceUpdateType = "DELETE"
)

type allocationTracker struct {
	servicesByIp map[string]types.NamespacedName
	ipsByService map[types.NamespacedName]map[string]bool
}

func (t *allocationTracker) assignAddress(svc *v1.Service, ip string) {
	namespacedName := types.NamespacedName{
		Namespace: svc.Namespace,
		Name:      svc.Name,
	}
	t.servicesByIp[ip] = namespacedName
	if t.ipsByService[namespacedName] == nil {
		t.ipsByService[namespacedName] = make(map[string]bool)
		t.ipsByService[namespacedName][ip] = true
	} else {
		t.ipsByService[namespacedName][ip] = true
	}
}

func (t *allocationTracker) releaseAddress(svc *v1.Service, ip string) {
	namespacedName := types.NamespacedName{
		Namespace: svc.Namespace,
		Name:      svc.Name,
	}
	delete(t.servicesByIp, ip)
	delete(t.ipsByService[namespacedName], ip)
}

func (t *allocationTracker) deleteService(namespacedName types.NamespacedName) {
	for ip := range t.ipsByService[namespacedName] {
		delete(t.servicesByIp, ip)
	}
	delete(t.ipsByService, namespacedName)
}

// loadBalancerController implements the Controller interface for managing Kubernetes services
// and endpoints, syncing them to the Calico datastore as NetworkSet.
type loadBalancerController struct {
	calicoClient      client.Interface
	dataFeed          *node.DataFeed
	cfg               config.LoadBalancerControllerConfig
	clientSet         *kubernetes.Clientset
	syncerUpdates     chan interface{}
	syncStatus        bapi.SyncStatus
	syncChan          chan interface{}
	serviceUpdates    chan serviceObject
	ipamBlocks        map[string]model.KVPair
	ipPools           map[string]api.IPPool
	serviceInformer   cache.SharedIndexInformer
	serviceLister     v1lister.ServiceLister
	allocationTracker allocationTracker
}

// NewLoadBalancerController returns a controller which manages Service LoadBalancer objects.
func NewLoadBalancerController(clientset *kubernetes.Clientset, calicoClient client.Interface, cfg config.LoadBalancerControllerConfig, serviceInformer cache.SharedIndexInformer, dataFeed *node.DataFeed) controller.Controller {
	lbc := &loadBalancerController{
		calicoClient:    calicoClient,
		cfg:             cfg,
		clientSet:       clientset,
		dataFeed:        dataFeed,
		syncerUpdates:   make(chan interface{}),
		syncChan:        make(chan interface{}, 1),
		serviceUpdates:  make(chan serviceObject, 1),
		ipamBlocks:      make(map[string]model.KVPair),
		ipPools:         make(map[string]api.IPPool),
		serviceInformer: serviceInformer,
		serviceLister:   v1lister.NewServiceLister(serviceInformer.GetIndexer()),
		allocationTracker: allocationTracker{
			servicesByIp: make(map[string]types.NamespacedName),
			ipsByService: make(map[types.NamespacedName]map[string]bool),
		},
	}

	lbc.RegisterWith(lbc.dataFeed)

	serviceAdd := func(obj interface{}) {
		if svc, ok := obj.(*v1.Service); ok {
			handle, err := createHandle(svc)
			if err != nil {
				log.WithError(err).Error("Error creating handle for service")
				return
			}
			lbc.serviceUpdates <- serviceObject{
				handle:     handle,
				updateType: serviceUpdateTypeADD,
				namespacedName: types.NamespacedName{
					Namespace: svc.Namespace,
					Name:      svc.Name,
				},
			}
		}
	}

	serviceUpdate := func(objNew interface{}, objOld interface{}) {
		if svc, ok := objNew.(*v1.Service); ok {
			handle, err := createHandle(svc)
			if err != nil {
				log.WithError(err).Error("Error creating handle for service")
				return
			}
			lbc.serviceUpdates <- serviceObject{
				handle:     handle,
				updateType: serviceUpdateTypeUPDATE,
				namespacedName: types.NamespacedName{
					Namespace: svc.Namespace,
					Name:      svc.Name,
				},
			}
		}
	}

	serviceDelete := func(objNew interface{}) {
		if svc, ok := objNew.(*v1.Service); ok {
			handle, err := createHandle(svc)
			if err != nil {
				log.WithError(err).Error("Error creating handle for service")
				return
			}
			lbc.serviceUpdates <- serviceObject{
				handle:     handle,
				updateType: serviceUpdateTypeDELETE,
				namespacedName: types.NamespacedName{
					Namespace: svc.Namespace,
					Name:      svc.Name,
				},
			}
		}
	}

	_, err := lbc.serviceInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    serviceAdd,
		UpdateFunc: serviceUpdate,
		DeleteFunc: serviceDelete,
	})
	if err != nil {
		log.WithError(err).Fatal("Failed to add event handle for Service LoadBalancer")
		return nil
	}
	return lbc
}

// Run starts the controller.
func (c *loadBalancerController) Run(stopCh chan struct{}) {
	defer uruntime.HandleCrash()

	log.Debug("Waiting to sync with Kubernetes API (Service)")
	if !cache.WaitForNamedCacheSync("loadbalancer", stopCh, c.serviceInformer.HasSynced) {
		log.Info("Failed to sync resources, received signal for controller to shut down.")
		return
	}

	// Load services and assigned IPs into cache
	svcObjs, err := c.getServiceObjectList()
	if err != nil {
		log.WithError(err).Fatal("Failed to get service objects")
	}
	for _, svcObj := range svcObjs {
		if IsCalicoManagedLoadBalancer(svcObj.service, c.cfg.AssignIPs) {
			for _, ingress := range svcObj.service.Status.LoadBalancer.Ingress {
				c.allocationTracker.assignAddress(svcObj.service, ingress.IP)
			}
		}
	}

	// Load LoadBalancer ipPools into cache
	ippools, err := c.calicoClient.IPPools().List(context.Background(), options.ListOptions{})
	if err != nil {
		log.Error("Failed to get IpPools.")
		return
	}
	for _, pool := range ippools.Items {
		if slices.Contains(pool.Spec.AllowedUses, api.IPPoolAllowedUseLoadBalancer) {
			c.ipPools[pool.Name] = pool
		}
	}

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
		case <-c.syncChan:
			c.syncIPAM()
		case svcObj := <-c.serviceUpdates:
			err := c.syncService(svcObj)
			if err != nil {
				log.WithError(err).Error("Error syncing service object, will retry during next IPAM sync")
			}
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
				c.handleIPPoolUpdate(update)
				kick(c.syncChan)
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
		affinity := kvp.Value.(*model.AllocationBlock).Affinity

		if affinity != nil && *affinity == fmt.Sprintf("%s:%s", ipam.AffinityTypeVirtual, api.VirtualLoadBalancer) {
			c.ipamBlocks[kvp.Key.String()] = kvp
		}
	} else {
		delete(c.ipamBlocks, kvp.Key.String())
	}
}

func (c *loadBalancerController) handleIPPoolUpdate(kvp model.KVPair) {
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
	svcObjs, err := c.getServiceObjectList()
	if err != nil {
		return
	}

	for _, svcObj := range svcObjs {
		err = c.syncService(svcObj)
		if err != nil {
			log.WithError(err).Errorf("Failed to sync service %s/%s", svcObj.service.Namespace, svcObj.service.Name)
			continue
		}
	}

	for _, block := range c.ipamBlocks {
		b := block.Value.(*model.AllocationBlock)
		for key := range b.SequenceNumberForAllocation {
			ordinal, err := strconv.Atoi(key)
			if err != nil {
				log.WithError(err).Errorf("Failed to parse Ordinal for block %s", key)
			}
			ip := b.OrdinalToIP(ordinal)

			if _, ok := c.allocationTracker.servicesByIp[ip.String()]; !ok {
				log.Infof("Found allocated IP, but not in use. Will release IP: %s", ip.String())
				releaseOptions := ipam.ReleaseOptions{
					Address: ip.String(),
				}
				_, err := c.calicoClient.IPAM().ReleaseIPs(context.Background(), releaseOptions)
				if err != nil {
					log.WithError(err).Errorf("Failed to release IP %s", ip.String())
					continue
				}
			}
		}
	}
}

// syncService does the following:
// - Releases any IP addresses in the IPAM DB associated with the Service that are not in the Service status.
// - Allocates any addresses necessary to satisfy the Service LB request
// - Updates the controllers internal state tracking of which IP addresses are allocated.
// - Updates the IP addresses in the Service Status to match the IPAM DB.
func (c *loadBalancerController) syncService(svcObj serviceObject) error {
	var err error
	var svc *v1.Service
	serviceUpdated := false
	reassignIP := false
	svcStatus := make(map[string]v1.LoadBalancerIngress)

	switch svcObj.updateType {
	case serviceUpdateTypeDELETE:
		if c.allocationTracker.ipsByService[svcObj.namespacedName] != nil {
			err = c.releaseIPByHandle(svcObj)
			if err != nil {
				log.WithError(err).Errorf("Failed to release IP for %s/%s", svcObj.namespacedName.Namespace, svcObj.namespacedName.Name)
				return err
			}
			c.allocationTracker.deleteService(svcObj.namespacedName)
		}
		return nil
	case serviceUpdateTypeADD, serviceUpdateTypeUPDATE:
		if svcObj.service != nil {
			svc = svcObj.service
		} else {
			svc, err = c.serviceLister.Services(svcObj.namespacedName.Namespace).Get(svcObj.namespacedName.Name)
			if err != nil {
				log.WithError(err).Errorf("Failed to get service %s/%s", svcObj.namespacedName.Namespace, svcObj.namespacedName.Name)
				return err
			}
		}

		// Get IPs in use from service
		for _, ingress := range svc.Status.LoadBalancer.Ingress {
			svcStatus[ingress.IP] = ingress
		}

		// Clear any IPs that we have marked as assigned, but are not in service status
		for ip := range c.allocationTracker.ipsByService[svcObj.namespacedName] {
			if _, ok := svcStatus[ip]; !ok {
				err = c.releaseIP(ip)
				if err != nil {
					continue
				}
				c.allocationTracker.releaseAddress(svc, ip)
			}
		}

		//Service has no IP in status, if the service is managed by calico we will try to assign IPs bellow
		if len(svcStatus) == 0 {
			reassignIP = true
		}

		if svc.Spec.Type != v1.ServiceTypeLoadBalancer {
			// Service type has changed, release the ip assigned by calico
			if c.allocationTracker.ipsByService[svcObj.namespacedName] != nil {
				err = c.releaseIPByHandle(svcObj)
				if err != nil {
					return err
				}
				c.allocationTracker.deleteService(svcObj.namespacedName)
				return nil
			} else {
				// Service is not a type of LoadBalancer, we can skip the update
				return nil
			}
		}

		loadBalancerIPs, ipv4pools, ipv6pools, err := c.parseAnnotations(svc.Annotations)
		if err != nil {
			log.WithError(err).Errorf("Failed to parse annotations for service %s/%s", svc.Namespace, svc.Name)
			return err
		}

		// Calico assigned IP previously, no longer managed by us, release IPs assigned by calico
		if loadBalancerIPs == nil &&
			ipv4pools == nil &&
			ipv6pools == nil &&
			!IsCalicoManagedLoadBalancer(svc, c.cfg.AssignIPs) &&
			c.allocationTracker.ipsByService[svcObj.namespacedName] != nil {
			for ip := range c.allocationTracker.ipsByService[svcObj.namespacedName] {
				err = c.releaseIP(ip)
				if err != nil {
					log.WithError(err).Errorf("Failed to release IP for %s/%s", svc.Namespace, svc.Name)
					continue
				}
				delete(svcStatus, ip)
				c.allocationTracker.releaseAddress(svc, ip)
				serviceUpdated = true
			}
		}

		// Check that service has assigned IP equal to the ones on annotations
		if loadBalancerIPs != nil {
			lbIPs := make(map[string]bool)
			for _, ip := range loadBalancerIPs {
				lbIPs[ip.String()] = true
			}
			for ip := range svcStatus {
				if _, ok := lbIPs[ip]; !ok {
					err = c.releaseIP(ip)
					if err != nil {
						log.WithError(err).Errorf("Failed to release IP for %s/%s", svc.Namespace, svc.Name)
						return err
					}
					delete(svcStatus, ip)
					c.allocationTracker.releaseAddress(svc, ip)
					reassignIP = true
					serviceUpdated = true
				}
			}
		} else if ipv4pools != nil || ipv6pools != nil {
			// If pool annotations are specified, we need to check that the IPs assigned are from the specified pools
			for ip := range svcStatus {
				if !isIpInIppool(ip, ipv4pools) && !isIpInIppool(ip, ipv6pools) {
					err = c.releaseIP(ip)
					if err != nil {
						log.WithError(err).Errorf("Failed to release IP for %s/%s", svc.Namespace, svc.Name)
						return err
					}
					delete(svcStatus, ip)
					c.allocationTracker.releaseAddress(svc, ip)
					reassignIP = true
					serviceUpdated = true
				}
			}
		} else {
			// No annotations are specified, check that the IPs assigned aren't from Manual pool from earlier assignment
			for ip := range svcStatus {
				pool, err := c.localIppoolFromIp(ip)
				if err != nil {
					return err
				}
				if pool != nil {
					if pool.Spec.AssignmentMode == api.Manual {
						err = c.releaseIP(ip)
						if err != nil {
							log.WithError(err).Errorf("Failed to release IP for %s/%s", svc.Namespace, svc.Name)
							return err
						}
						delete(svcStatus, ip)
						c.allocationTracker.releaseAddress(svc, ip)
						reassignIP = true
						serviceUpdated = true
					}
				}
			}
		}
	}

	// Service is not in sync, we try to assign new IPs
	if reassignIP && IsCalicoManagedLoadBalancer(svc, c.cfg.AssignIPs) {
		svcIngress := []v1.LoadBalancerIngress{}
		for _, ingress := range svcStatus {
			svcIngress = append(svcIngress, ingress)
		}
		svc.Status.LoadBalancer.Ingress = svcIngress
		assignedIPs, err := c.assignIP(svc)
		if err != nil {
			log.WithError(err).Errorf("Failed to assign IP for %s/%s", svc.Namespace, svc.Name)
			return err
		}
		for _, ip := range assignedIPs {
			svcStatus[ip] = v1.LoadBalancerIngress{
				IP: ip,
			}
			c.allocationTracker.assignAddress(svc, ip)
		}
		serviceUpdated = true
	}

	// If there were no changes to the service during sync, we skip the Status update
	if serviceUpdated {
		svcIngress := []v1.LoadBalancerIngress{}
		for _, ingress := range svcStatus {
			svcIngress = append(svcIngress, ingress)
		}
		svc.Status.LoadBalancer.Ingress = svcIngress

		_, err = c.clientSet.CoreV1().Services(svc.Namespace).UpdateStatus(context.Background(), svc, metav1.UpdateOptions{})
		if err != nil {
			log.WithError(err).Errorf("Failed to update service status %s/%s", svc.Namespace, svc.Name)
			return err
		}
	}
	return nil
}

// assignIP tries to assign IP address for Service.
func (c *loadBalancerController) assignIP(svc *v1.Service) ([]string, error) {
	if len(c.ipPools) == 0 {
		return nil, nil
	}

	handle, err := createHandle(svc)
	if err != nil {
		return nil, err
	}

	loadBalancerIps, ipv4Pools, ipv6Pools, err := c.parseAnnotations(svc.Annotations)
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

	// User requested specific IP, attempt to allocate
	if loadBalancerIps != nil {
		ingress := svc.Status.LoadBalancer.Ingress

		for _, addrs := range loadBalancerIps {
			skipAddrs := false
			for _, lbingress := range ingress {
				// We must be trying to assign missing address due to an error,
				// skip this assignment as it's already assigned and move onto the next one
				if lbingress.IP == addrs.String() {
					skipAddrs = true
				}
			}

			if skipAddrs {
				continue
			}

			ipamArgs := ipam.AssignIPArgs{
				IP:          addrs,
				Hostname:    api.VirtualLoadBalancer,
				HandleID:    &handle,
				Attrs:       metadataAttrs,
				IntendedUse: api.VirtualLoadBalancer,
			}

			err = c.calicoClient.IPAM().AssignIP(context.Background(), ipamArgs)
			if err != nil {
				log.WithField("ip", addrs).WithError(err).Warn("failed to assign ip to node")
				return nil, err
			}
			assignedIPs = append(assignedIPs, addrs.String())
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
			return nil, errors.New("No new IPs to assign, Service already has ipv4 and ipv6 address")
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
			assignedIPs = append(assignedIPs, assignment.IP.String())
		}
	}

	if v6assignments != nil {
		for _, assignment := range v6assignments.IPs {
			assignedIPs = append(assignedIPs, assignment.IP.String())
		}
	}

	return assignedIPs, nil
}

// releaseIPByHandle tries to release all IPs allocated with the Service unique handle
func (c *loadBalancerController) releaseIPByHandle(svcObj serviceObject) error {
	log.Info("Service type LoadBalancer deleted, releasing assigned IP address")

	err := c.calicoClient.IPAM().ReleaseByHandle(context.Background(), svcObj.handle)
	if err != nil {
		log.Errorf("error on removing assigned IP for handle %s", svcObj.handle)
		return err
	}
	return nil
}

func (c *loadBalancerController) releaseIP(ip string) error {
	releaseOptions := ipam.ReleaseOptions{
		Address: ip,
	}
	_, err := c.calicoClient.IPAM().ReleaseIPs(context.Background(), releaseOptions)
	if err != nil {
		log.Errorf("error on removing assigned IP %s", ip)
		return err
	}
	return nil
}

func (c *loadBalancerController) getServiceObjectList() (map[string]serviceObject, error) {
	services, err := c.serviceLister.Services("").List(labels.Everything())
	if err != nil {
		log.WithError(err).Error("Error getting service list")
		return nil, err
	}

	loadBalancerServices := make(map[string]serviceObject)
	for _, svc := range services {
		if IsCalicoManagedLoadBalancer(svc, c.cfg.AssignIPs) {
			handle, err := createHandle(svc)
			if err != nil {
				return nil, err
			}
			loadBalancerServices[handle] = serviceObject{
				handle:     handle,
				updateType: serviceUpdateTypeUPDATE,
				namespacedName: types.NamespacedName{
					Namespace: svc.Namespace,
					Name:      svc.Name,
				},
				service: svc,
			}
		}
	}
	return loadBalancerServices, nil
}

// resolvePools valid IPpool range when specific pool is requested by the user
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
		return true
	}

	if svc.Annotations[annotationIPv4Pools] != "" ||
		svc.Annotations[annotationIPv6Pools] != "" ||
		svc.Annotations[annotationLoadBalancerIP] != "" {
		return true
	}
	return false
}

// validateAnnotation checks if the ips specified in the calico annotation are valid.
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
					return nil, nil, nil, fmt.Errorf("Could not parse %s as a valid IP address", ipAddr)
				}
				if curr.To4() != nil {
					ipv4++
				} else if curr.To16() != nil {
					ipv6++
				}
				loadBalancerIPs = append(loadBalancerIPs, *curr)
			}

			if ipv6 > 1 || ipv4 > 1 {
				return nil, nil, nil, fmt.Errorf("At max only one ipv4 and one ipv6 address can be specified. Recieved %d ipv4 and %d ipv6 addresses", ipv4, ipv6)
			}
		}
	}
	return loadBalancerIPs, ipv4Pools, ipv6Pools, nil
}

// createHandle Returns a handle to use for IP allocation for the service
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
	if len(handle) > k8svalidation.DNS1123LabelMaxLength {
		handle = handle[:k8svalidation.DNS1123LabelMaxLength]
	}

	return handle, nil
}

func isIpInIppool(ipAddr string, cidrs []cnet.IPNet) bool {
	if cidrs == nil {
		return false
	}
	ip := net.ParseIP(ipAddr)
	for _, cidr := range cidrs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func (c *loadBalancerController) localIppoolFromIp(ipAddr string) (*api.IPPool, error) {
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

func kick(c chan<- interface{}) {
	select {
	case c <- nil:
		// pass
	default:
		// pass
	}
}
