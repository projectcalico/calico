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
	"strings"
	"time"

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
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	uruntime "k8s.io/apimachinery/pkg/util/runtime"
	k8svalidation "k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes"
	v1lister "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
)

const (
	annotationIpv4Pools      = "projectcalico.org/ipv4pools"
	annotationIpv6Pools      = "projectcalico.org/ipv6pools"
	annotationLoadBalancerIp = "projectcalico.org/loadBalancerIPs"
	timer                    = 5 * time.Minute
)

type serviceObject struct {
	handle     string
	updateType serviceUpdateType
	service    *v1.Service
}

type serviceUpdateType string

const (
	serviceUpdateTypeADD    serviceUpdateType = "ADD"
	serviceUpdateTypeUPDATE serviceUpdateType = "UPDATE"
	serviceUpdateTypeDELETE serviceUpdateType = "DELETE"
)

// loadBalancerController implements the Controller interface for managing Kubernetes services
// and endpoints, syncing them to the Calico datastore as NetworkSet.
type loadBalancerController struct {
	calicoClient     client.Interface
	dataFeed         *node.DataFeed
	cfg              config.LoadBalancerControllerConfig
	clientSet        *kubernetes.Clientset
	syncerUpdates    chan interface{}
	syncStatus       bapi.SyncStatus
	syncChan         chan interface{}
	ipamBlocks       map[string]model.KVPair
	ipPools          map[string]api.IPPool
	serviceInformer  cache.SharedIndexInformer
	serviceLister    v1lister.ServiceLister
	servicesToUpdate map[string]serviceObject
}

// NewLoadBalancerController returns a controller which manages Service LoadBalancer objects.
func NewLoadBalancerController(clientset *kubernetes.Clientset, calicoClient client.Interface, cfg config.LoadBalancerControllerConfig, serviceInformer cache.SharedIndexInformer, dataFeed *node.DataFeed) controller.Controller {
	lbc := &loadBalancerController{
		calicoClient:     calicoClient,
		cfg:              cfg,
		clientSet:        clientset,
		dataFeed:         dataFeed,
		syncerUpdates:    make(chan interface{}),
		syncChan:         make(chan interface{}, 1),
		ipamBlocks:       make(map[string]model.KVPair),
		ipPools:          make(map[string]api.IPPool),
		serviceInformer:  serviceInformer,
		serviceLister:    v1lister.NewServiceLister(serviceInformer.GetIndexer()),
		servicesToUpdate: make(map[string]serviceObject),
	}

	lbc.RegisterWith(lbc.dataFeed)
	lbc.dataFeed.Start()

	_, err := lbc.serviceInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		DeleteFunc: func(obj interface{}) {
			if svc, ok := obj.(*v1.Service); ok {
				if IsCalicoManagedLoadBalancer(svc, cfg.AssignIPs) {
					lbc.syncerUpdates <- serviceObject{
						updateType: serviceUpdateTypeDELETE,
					}
				}
			}
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			svcNew := newObj.(*v1.Service)
			svcOld := oldObj.(*v1.Service)
			handle, err := createHandle(svcNew)
			if err != nil {
				log.WithError(err).Error("Error creating load balancer handle")
				return
			}
			if svcNew.Spec.Type != v1.ServiceTypeLoadBalancer &&
				svcOld.Spec.Type == v1.ServiceTypeLoadBalancer {
				lbc.syncerUpdates <- serviceObject{
					updateType: serviceUpdateTypeDELETE,
				}
			} else if svcOld.Annotations[annotationIpv4Pools] != svcNew.Annotations[annotationIpv4Pools] ||
				svcOld.Annotations[annotationIpv6Pools] != svcNew.Annotations[annotationIpv6Pools] ||
				svcOld.Annotations[annotationLoadBalancerIp] != svcNew.Annotations[annotationLoadBalancerIp] {
				// Calico annotations have changed, get new address based on new conditions.
				lbc.syncerUpdates <- serviceObject{
					handle:     handle,
					updateType: serviceUpdateTypeUPDATE,
					service:    svcNew,
				}
			} else if svcNew.Status.LoadBalancer.Ingress == nil && IsCalicoManagedLoadBalancer(svcNew, cfg.AssignIPs) {
				lbc.syncerUpdates <- serviceObject{
					handle:     handle,
					updateType: serviceUpdateTypeADD,
				}
			}
		},
		AddFunc: func(obj interface{}) {
			svc := obj.(*v1.Service)
			if IsCalicoManagedLoadBalancer(svc, cfg.AssignIPs) {
				lbc.syncerUpdates <- serviceObject{
					updateType: serviceUpdateTypeADD,
				}
			}
		},
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
	case serviceObject:
		c.handleServiceUpdate(update)
		kick(c.syncChan)
		return
	}
}

func (c *loadBalancerController) handleBlockUpdate(kvp model.KVPair) {
	if kvp.Value != nil {
		host := kvp.Value.(*model.AllocationBlock).Affinity
		if host != nil && *host == fmt.Sprintf("virtual:%s", api.VirtualLoadBalancer) {
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

func (c *loadBalancerController) handleServiceUpdate(svcObj serviceObject) {
	switch svcObj.updateType {
	case serviceUpdateTypeUPDATE:
		c.servicesToUpdate[svcObj.handle] = svcObj
	}
}

// syncIpam has two main uses. It functions as a garbage collection for leaked IP addresses from Service LoadBalancer
// The other use case is to update IPs for any Service LoadBalancer that do not have IPs assigned, this could be caused by the user
// creating Service LoadBalancer before any valid pools were created
func (c *loadBalancerController) syncIPAM() {

	services, err := c.getServiceLoadBalancerList()
	if err != nil {
		log.WithError(err).Error("Skipping IPAM sync")
	}

	// Garbage collection
	// Check all ipamBlocks with loadBalancer affinity, and release unused allocated IPs
	// Skip if there is service scheduled for update. ip will be released during the update and we will run GC right after the un-allocation
	if len(c.servicesToUpdate) == 0 {
		log.Info("Running Service LoadBalancer IP garbage collection")
		for _, block := range c.ipamBlocks {
			attributes := block.Value.(*model.AllocationBlock).Attributes
			for _, attr := range attributes {
				if svc, exists := services[*attr.AttrPrimary]; exists {
					// Service with handle exists, we need to check that all assigned IPs with the handle are still in use by the svc
					log.Debugf("Service found for handle: %s. Check if all IPs allocated by the handle are in use.", *attr.AttrPrimary)
					ips, err := c.calicoClient.IPAM().IPsByHandle(context.Background(), *attr.AttrPrimary)
					if err != nil {
						log.Errorf("Error getting IPs for handle: %s", *attr.AttrPrimary)
					}
					for _, ingressIP := range svc.Status.LoadBalancer.Ingress {
						inUse := false
						for _, handleIP := range ips {
							if handleIP.String() == ingressIP.IP {
								log.Debugf("IP %s in use, skipping", handleIP.String())
								inUse = true
							}
							if !inUse {
								log.Debugf("IP %s not in use, releasing", handleIP.String())
								releaseOptions := ipam.ReleaseOptions{
									Address: ingressIP.IP,
								}
								_, err = c.calicoClient.IPAM().ReleaseIPs(context.Background(), releaseOptions)
								if err != nil {
									log.Errorf("Error releasing IP(%s) for svc: %s", ingressIP.IP, svc.Name)
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
	}

	// Check that all services have assigned IPs as requested, skip if there are no ippools
	if len(c.ipPools) != 0 {
		for _, svc := range services {
			if svc.Status.LoadBalancer.Ingress == nil ||
				(len(svc.Status.LoadBalancer.Ingress) == 1 &&
					(*svc.Spec.IPFamilyPolicy == v1.IPFamilyPolicyRequireDualStack) || *svc.Spec.IPFamilyPolicy == v1.IPFamilyPolicyPreferDualStack) {
				err = c.assignIP(&svc)
				if err != nil {
					log.WithError(err).Errorf("Error assigning IP to svc: %s", svc.Name)
				}
			}
		}
	}

	if len(c.servicesToUpdate) != 0 {
		for key, svcObj := range c.servicesToUpdate {
			switch svcObj.updateType {
			case serviceUpdateTypeUPDATE:
				err = c.releaseIP(svcObj.handle)
				if err != nil {
					log.WithError(err).Error("Error releasing Service IP")
					continue
				}
				svc, err := c.clientSet.CoreV1().Services(svcObj.service.Namespace).Get(context.Background(), svcObj.service.Name, metav1.GetOptions{})
				if err != nil {
					log.WithError(err).Errorf("Error getting Service %s", svcObj.service.Name)
					continue
				}
				svc.Status.LoadBalancer.Ingress = []v1.LoadBalancerIngress{}
				_, err = c.clientSet.CoreV1().Services(svc.Namespace).UpdateStatus(context.Background(), svc, metav1.UpdateOptions{})
				if err != nil {
					// We have assigned IP to the service, but were not able to update the status. The IP will be picked up by GC during the next sync, and we will try to assign a new IP
					log.WithError(err).Error("Error updating Service IP")
					continue
				}
				delete(c.servicesToUpdate, key)
			}
		}
	}
}

// assignIP tries to assign IP address for Service.
func (c *loadBalancerController) assignIP(svc *v1.Service) error {
	if len(c.ipPools) == 0 {
		return nil
	}
	handle, err := createHandle(svc)
	if err != nil {
		return err
	}

	loadBalancerIps, ipv4Pools, ipv6Pools, err := c.parseAnnotations(svc.Annotations)
	if err != nil {
		return err
	}

	metadataAttrs := map[string]string{
		ipam.AttributeService:   svc.Name,
		ipam.AttributeNamespace: svc.Namespace,
		ipam.AttributeType:      string(svc.Spec.Type),
		ipam.AttributeTimestamp: time.Now().UTC().String(),
	}

	// User requested specific IP, attempt to allocate
	if len(loadBalancerIps) != 0 {

		ingress := svc.Status.LoadBalancer.Ingress

		for _, addrs := range loadBalancerIps {
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

			err = c.calicoClient.IPAM().AssignIP(context.Background(), ipamArgs)
			if err != nil {
				log.WithField("ip", addrs).WithError(err).Warn("failed to assign ip to node")
				return err
			}

			ingress = append(ingress, v1.LoadBalancerIngress{IP: addrs.String()})
		}

		svc.Status.LoadBalancer.Ingress = ingress
		_, err = c.clientSet.CoreV1().Services(svc.Namespace).UpdateStatus(context.Background(), svc, metav1.UpdateOptions{})
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

	if len(ipv4Pools) != 0 {
		args.IPv4Pools = ipv4Pools
	}

	if len(ipv6Pools) != 0 {
		args.IPv6Pools = ipv6Pools
	}

	v4Assignments, v6assignments, err := c.calicoClient.IPAM().AutoAssign(context.Background(), args)
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

	_, err = c.clientSet.CoreV1().Services(svc.Namespace).UpdateStatus(context.Background(), svc, metav1.UpdateOptions{})
	if err != nil {
		log.Errorf("LoadBalancer Error updating service %s/%s: %v", svc.Namespace, svc.Name, err)
		return err
	}
	return nil
}

// releaseIP tries to release all IPs allocated with the Service unique handle
func (c *loadBalancerController) releaseIP(handle string) error {
	log.Info("Service type LoadBalancer deleted, releasing assigned IP address")

	err := c.calicoClient.IPAM().ReleaseByHandle(context.Background(), handle)
	if err != nil {
		log.Errorf("error on removing assigned IP for handle %s", handle)
		return err
	}

	return nil
}

func (c *loadBalancerController) getServiceLoadBalancerList() (map[string]v1.Service, error) {
	services, err := c.serviceLister.Services("").List(labels.Everything())
	if err != nil {
		log.WithError(err).Error("Error getting svc list")
		return nil, err
	}

	loadBalancerServices := make(map[string]v1.Service)
	for _, svc := range services {
		if IsCalicoManagedLoadBalancer(svc, c.cfg.AssignIPs) {
			handle, err := createHandle(svc)
			if err != nil {
				return nil, err
			}
			loadBalancerServices[handle] = *svc
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

	if svc.Annotations[annotationIpv4Pools] != "" ||
		svc.Annotations[annotationIpv6Pools] != "" ||
		svc.Annotations[annotationLoadBalancerIp] != "" {
		return true
	}
	return false
}

// validateAnnotation checks if the ips specified in the calico annotation are valid.
// Each service can have at most one ipv4 and one ipv6 address
func (c *loadBalancerController) parseAnnotations(annotations map[string]string) ([]cnet.IP, []cnet.IPNet, []cnet.IPNet, error) {
	loadBalancerIPs := []cnet.IP{}
	ipv4Pools := []cnet.IPNet{}
	ipv6Pools := []cnet.IPNet{}

	for key, annotation := range annotations {
		switch key {
		case annotationIpv4Pools:
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
		case annotationIpv6Pools:
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
		case annotationLoadBalancerIp:
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
					return nil, nil, nil, errors.New(fmt.Sprintf("Could not parse %s as a valid IP address", ipAddr))
				}
				if curr.To4() != nil {
					ipv4++
				} else if curr.To16() != nil {
					ipv6++
				}
				loadBalancerIPs = append(loadBalancerIPs, *curr)
			}

			if ipv6 > 1 || ipv4 > 1 {
				return nil, nil, nil, errors.New(fmt.Sprintf("At max only one ipv4 and one ipv6 address can be specified. Recieved %d ipv4 and %d ipv6 addresses", ipv4, ipv6))
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

func kick(c chan<- interface{}) {
	select {
	case c <- nil:
		// pass
	default:
		// pass
	}
}
