package loadbalancer

import (
	"context"
	"fmt"
	"net"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"

	"github.com/projectcalico/calico/kube-controllers/pkg/config"
	"github.com/projectcalico/calico/kube-controllers/pkg/controllers/node"
	"github.com/projectcalico/calico/kube-controllers/pkg/controllers/utils"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

var _ = Describe("LoadBalancer controller UTs", func() {
	var c *loadBalancerController
	var cli client.Interface
	var cs kubernetes.Interface
	var stopChan chan struct{}

	ipFamilyPolicySingleStack := v1.IPFamilyPolicySingleStack
	ipFamilyPolicyDualStack := v1.IPFamilyPolicyRequireDualStack

	svc := v1.Service{
		Spec: v1.ServiceSpec{
			Type:           v1.ServiceTypeLoadBalancer,
			IPFamilyPolicy: &ipFamilyPolicySingleStack,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-service",
			Namespace: "test-namespace",
			UID:       "1234",
		},
	}

	BeforeEach(func() {
		// Create a fake clientset with nothing in it.
		cs = fake.NewSimpleClientset()

		// Create a fake Calico client.
		cli = node.NewFakeCalicoClient()

		// Create a node indexer with the fake clientset
		factory := informers.NewSharedInformerFactory(cs, 0)
		serviceInformer := factory.Core().V1().Services().Informer()

		// Config for the test.
		cfg := config.LoadBalancerControllerConfig{AssignIPs: apiv3.AllServices}

		// stopChan is used in AfterEach to stop the controller in each test.
		stopChan = make(chan struct{})

		factory.Start(stopChan)
		cache.WaitForCacheSync(stopChan, serviceInformer.HasSynced)
		dataFeed := utils.NewDataFeed(cli)

		// Create a new controller. We don't register with a data feed,
		// as the tests themselves will drive the controller.
		c = NewLoadBalancerController(cs, cli, cfg, serviceInformer, dataFeed)
	})

	AfterEach(func() {
		close(stopChan)

		svc = v1.Service{
			Spec: v1.ServiceSpec{
				Type:           v1.ServiceTypeLoadBalancer,
				IPFamilyPolicy: &ipFamilyPolicySingleStack,
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-service",
				Namespace: "test-namespace",
				UID:       "1234",
			},
		}
	})

	It("should correctly create serviceKey from service", func() {
		svcKey, err := serviceKeyFromService(&svc)
		Expect(err).ToNot(HaveOccurred())
		Expect(svcKey.name).To(Equal(svc.Name))
		Expect(svcKey.namespace).To(Equal(svc.Namespace))
		Expect(svcKey.handle).To(Equal("lb-CcByVDWerSL9WUOKfbkyPBft2m9Xxf822Zvhn2YSpts"))
	})

	It("should determine if service needs IP assigned", func() {
		svcKey, err := serviceKeyFromService(&svc)
		Expect(err).ToNot(HaveOccurred())
		needsIPsAssigned := c.needsIPsAssigned(&svc, *svcKey)
		Expect(needsIPsAssigned).To(BeTrue())

		c.allocationTracker.assignAddressToService(*svcKey, "1.1.1.1")
		needsIPsAssigned = c.needsIPsAssigned(&svc, *svcKey)
		Expect(needsIPsAssigned).To(BeFalse())

		svc.Spec.IPFamilyPolicy = &ipFamilyPolicyDualStack
		needsIPsAssigned = c.needsIPsAssigned(&svc, *svcKey)
		Expect(needsIPsAssigned).To(BeTrue())

		c.allocationTracker.assignAddressToService(*svcKey, "1.1.1.2")
		needsIPsAssigned = c.needsIPsAssigned(&svc, *svcKey)
		Expect(needsIPsAssigned).To(BeFalse())
	})

	It("should determine if service needs status update", func() {
		svcKey, err := serviceKeyFromService(&svc)
		Expect(err).ToNot(HaveOccurred())
		c.allocationTracker.assignAddressToService(*svcKey, "1.1.1.1")
		needsStatusUpdate := c.needsStatusUpdate(&svc, *svcKey)
		Expect(needsStatusUpdate).To(BeTrue())

		svc.Status.LoadBalancer.Ingress = []v1.LoadBalancerIngress{{IP: "1.1.1.1"}}
		needsStatusUpdate = c.needsStatusUpdate(&svc, *svcKey)
		Expect(needsStatusUpdate).To(BeFalse())

		svc.Status.LoadBalancer.Ingress = []v1.LoadBalancerIngress{{IP: "1.1.1.2"}}
		needsStatusUpdate = c.needsStatusUpdate(&svc, *svcKey)
		Expect(needsStatusUpdate).To(BeTrue())
	})

	It("should determine if service is managed by Calico", func() {
		managed := IsCalicoManagedLoadBalancer(&svc, apiv3.RequestedServicesOnly)
		Expect(managed).To(BeFalse())

		managed = IsCalicoManagedLoadBalancer(&svc, apiv3.AllServices)
		Expect(managed).To(BeTrue())

		svc.Annotations = map[string]string{
			annotationIPv4Pools: "poolv4",
		}
		managed = IsCalicoManagedLoadBalancer(&svc, apiv3.RequestedServicesOnly)
		Expect(managed).To(BeTrue())

		svc.Annotations = map[string]string{
			annotationIPv6Pools: "poolv6",
		}
		managed = IsCalicoManagedLoadBalancer(&svc, apiv3.RequestedServicesOnly)
		Expect(managed).To(BeTrue())

		svc.Annotations = map[string]string{
			annotationLoadBalancerIP: "1.1.1.1",
		}
		managed = IsCalicoManagedLoadBalancer(&svc, apiv3.RequestedServicesOnly)
		Expect(managed).To(BeTrue())

		svc.Annotations = map[string]string{}

		svc.Spec.Type = v1.ServiceTypeClusterIP
		managed = IsCalicoManagedLoadBalancer(&svc, apiv3.AllServices)
		Expect(managed).To(BeFalse())

		svc.Spec.Type = v1.ServiceTypeNodePort
		managed = IsCalicoManagedLoadBalancer(&svc, apiv3.AllServices)
		Expect(managed).To(BeFalse())
	})

	It("should correctly update allocationTracker on block update", func() {
		svcKey, err := serviceKeyFromService(&svc)
		Expect(err).ToNot(HaveOccurred())

		Expect(c.allocationTracker.ipsByService[*svcKey]).To(BeEmpty())

		cidr := cnet.MustParseCIDR("10.0.0.4/30")
		key := model.BlockKey{CIDR: cidr}
		aff := "virtual:load-balancer"
		idx0 := 0
		idx1 := 1
		block := model.AllocationBlock{
			CIDR:        cidr,
			Affinity:    &aff,
			Allocations: []*int{&idx0, nil, nil, nil},
			Unallocated: []int{1, 2, 3},
			Attributes: []model.AllocationAttribute{
				{
					AttrPrimary: &svcKey.handle,
					AttrSecondary: map[string]string{
						ipam.AttributeService:   svc.Name,
						ipam.AttributeType:      string(svc.Spec.Type),
						ipam.AttributeNamespace: svc.Namespace,
					},
				},
			},
		}
		kvp := model.KVPair{
			Key:   key,
			Value: &block,
		}

		serviceIPAllocations := make(map[string]bool)
		serviceIPAllocations["10.0.0.4"] = true

		c.handleBlockUpdate(kvp)
		Expect(c.allocationTracker.ipsByService[*svcKey]).ToNot(BeEmpty())
		Expect(c.allocationTracker.ipsByService[*svcKey]).To(HaveLen(1))
		Expect(c.allocationTracker.ipsByService[*svcKey]).To(Equal(serviceIPAllocations))
		Expect(c.allocationTracker.servicesByIP).To(HaveLen(1))
		Expect(c.allocationTracker.servicesByIP["10.0.0.4"]).To(Equal(*svcKey))
		Expect(c.allocationTracker.ipsByBlock[key.String()]).To(HaveLen(1))
		Expect(c.allocationTracker.ipsByBlock[key.String()]).To(Equal(serviceIPAllocations))

		block.Allocations = []*int{&idx0, &idx1, nil, nil}
		block.Unallocated = []int{2, 3}
		block.Attributes = []model.AllocationAttribute{
			{
				AttrPrimary: &svcKey.handle,
				AttrSecondary: map[string]string{
					ipam.AttributeService:   svc.Name,
					ipam.AttributeType:      string(svc.Spec.Type),
					ipam.AttributeNamespace: svc.Namespace,
				},
			},
			{
				AttrPrimary: &svcKey.handle,
				AttrSecondary: map[string]string{
					ipam.AttributeService:   svc.Name,
					ipam.AttributeType:      string(svc.Spec.Type),
					ipam.AttributeNamespace: svc.Namespace,
				},
			},
		}

		serviceIPAllocations["10.0.0.5"] = true

		c.handleBlockUpdate(kvp)
		Expect(c.allocationTracker.ipsByService[*svcKey]).ToNot(BeEmpty())
		Expect(c.allocationTracker.ipsByService[*svcKey]).To(HaveLen(2))
		Expect(c.allocationTracker.ipsByService[*svcKey]).To(Equal(serviceIPAllocations))
		Expect(c.allocationTracker.servicesByIP).To(HaveLen(2))
		Expect(c.allocationTracker.servicesByIP["10.0.0.4"]).To(Equal(*svcKey))
		Expect(c.allocationTracker.servicesByIP["10.0.0.5"]).To(Equal(*svcKey))
		Expect(c.allocationTracker.ipsByBlock[key.String()]).To(HaveLen(2))
		Expect(c.allocationTracker.ipsByBlock[key.String()]).To(Equal(serviceIPAllocations))

		kvp = model.KVPair{
			Key: key,
		}
		c.handleBlockUpdate(kvp)
		Expect(c.allocationTracker.ipsByService[*svcKey]).To(BeEmpty())
		Expect(c.allocationTracker.ipsByBlock).To(BeEmpty())
		Expect(c.allocationTracker.servicesByIP).To(BeEmpty())
	})

	It("should parse calico annotations", func() {
		ipv4poolName := "ipv4pool"
		ipv6poolName := "ipv6pool"

		loadBalancerIPs, ipv4Pools, ipv6Pools, err := c.parseAnnotations(svc.Annotations)
		Expect(err).NotTo(HaveOccurred())
		Expect(loadBalancerIPs).To(BeEmpty())
		Expect(ipv4Pools).To(BeEmpty())
		Expect(ipv6Pools).To(BeEmpty())

		// Incorrect format for LoadBalancerIP annotation
		svc.Annotations = map[string]string{
			annotationLoadBalancerIP: "incorrect",
		}
		_, _, _, err = c.parseAnnotations(svc.Annotations)
		Expect(err).To(HaveOccurred())

		// Multiple v4 ips for LoadBalancerIP annotation
		svc.Annotations = map[string]string{
			annotationLoadBalancerIP: "[\"10.0.0.4\", \"10.0.0.5\"]",
		}
		_, _, _, err = c.parseAnnotations(svc.Annotations)
		Expect(err).To(HaveOccurred())

		// Multiple v6 ips for LoadBalancerIP annotation
		svc.Annotations = map[string]string{
			annotationLoadBalancerIP: "[\"ff06::c3\", \"ff06::c4\"]",
		}
		_, _, _, err = c.parseAnnotations(svc.Annotations)
		Expect(err).To(HaveOccurred())

		// Correct annotations one ipv4 address for LoadBalancerIP annotation
		svc.Annotations = map[string]string{
			annotationLoadBalancerIP: "[\"10.0.0.4\"]",
		}
		_, _, _, err = c.parseAnnotations(svc.Annotations)
		Expect(err).ToNot(HaveOccurred())

		// Correct annotations one ipv6 address for LoadBalancerIP annotation
		svc.Annotations = map[string]string{
			annotationLoadBalancerIP: "[\"ff06::c3\"]",
		}
		_, _, _, err = c.parseAnnotations(svc.Annotations)
		Expect(err).ToNot(HaveOccurred())

		// Correct annotations one ipv4 and one ipv6 address for LoadBalancerIP annotation
		svc.Annotations = map[string]string{
			annotationLoadBalancerIP: "[\"10.0.0.4\", \"ff06::c3\"]",
		}
		_, _, _, err = c.parseAnnotations(svc.Annotations)
		Expect(err).ToNot(HaveOccurred())

		// ipv4Pool annotation with no pool stored in loadBalancer controller
		svc.Annotations = map[string]string{
			annotationIPv4Pools: fmt.Sprintf("[\"%s\"]", ipv4poolName),
		}
		_, _, _, err = c.parseAnnotations(svc.Annotations)
		Expect(err).To(HaveOccurred())

		ipv4Pool := apiv3.IPPool{
			TypeMeta: metav1.TypeMeta{},
			ObjectMeta: metav1.ObjectMeta{
				Name: ipv4poolName,
			},
			Spec: apiv3.IPPoolSpec{
				CIDR:        "10.0.0.4/30",
				AllowedUses: []apiv3.IPPoolAllowedUse{apiv3.IPPoolAllowedUseLoadBalancer},
			},
		}

		c.ipPools[ipv4Pool.Name] = ipv4Pool

		// ipv4Pool annotation with pool stored in loadBalancer controller
		svc.Annotations = map[string]string{
			annotationIPv4Pools: fmt.Sprintf("[\"%s\"]", ipv4poolName),
		}
		_, _, _, err = c.parseAnnotations(svc.Annotations)
		Expect(err).ToNot(HaveOccurred())

		// incorrect ipv4Pool annotation format
		svc.Annotations = map[string]string{
			annotationIPv4Pools: "[ippoolv4]",
		}
		_, _, _, err = c.parseAnnotations(svc.Annotations)
		Expect(err).To(HaveOccurred())

		// ipv6Pool annotation with no pool stored in loadBalancer controller
		svc.Annotations = map[string]string{
			annotationIPv6Pools: fmt.Sprintf("[\"%s\"]", ipv6poolName),
		}
		_, _, _, err = c.parseAnnotations(svc.Annotations)
		Expect(err).To(HaveOccurred())

		ipv6Pool := apiv3.IPPool{
			TypeMeta: metav1.TypeMeta{},
			ObjectMeta: metav1.ObjectMeta{
				Name: ipv6poolName,
			},
			Spec: apiv3.IPPoolSpec{
				CIDR:        "ff06::c3/30",
				AllowedUses: []apiv3.IPPoolAllowedUse{apiv3.IPPoolAllowedUseLoadBalancer},
			},
		}

		c.ipPools[ipv6poolName] = ipv6Pool

		// ipv6Pool annotation with pool stored in loadBalancer controller
		svc.Annotations = map[string]string{
			annotationIPv6Pools: fmt.Sprintf("[\"%s\"]", ipv6poolName),
		}
		_, _, _, err = c.parseAnnotations(svc.Annotations)
		Expect(err).ToNot(HaveOccurred())

		// ipv6Pool and ipv4Pool annotation with pools in loadBalancer controller
		svc.Annotations = map[string]string{
			annotationIPv6Pools: fmt.Sprintf("[\"%s\"]", ipv6poolName),
			annotationIPv4Pools: fmt.Sprintf("[\"%s\"]", ipv4poolName),
		}
		_, _, _, err = c.parseAnnotations(svc.Annotations)
		Expect(err).ToNot(HaveOccurred())

		// all allowed annotations
		svc.Annotations = map[string]string{
			annotationIPv6Pools:      fmt.Sprintf("[\"%s\"]", ipv6poolName),
			annotationIPv4Pools:      fmt.Sprintf("[\"%s\"]", ipv4poolName),
			annotationLoadBalancerIP: "[\"10.0.0.4\"]",
		}
		loadBalancerIPs, ipv4Pools, ipv6Pools, err = c.parseAnnotations(svc.Annotations)
		Expect(err).ToNot(HaveOccurred())

		Expect(loadBalancerIPs).To(Equal([]cnet.IP{*cnet.ParseIP("10.0.0.4")}))

		_, v4cidr, _ := net.ParseCIDR(ipv4Pool.Spec.CIDR)
		Expect(ipv4Pools).To(Equal([]cnet.IPNet{{IPNet: *v4cidr}}))

		_, v6cidr, _ := net.ParseCIDR(ipv6Pool.Spec.CIDR)
		Expect(ipv6Pools).To(Equal([]cnet.IPNet{{IPNet: *v6cidr}}))
	})

	It("should remove Calico ips from service status", func() {
		svc, err := c.clientSet.CoreV1().Services(svc.Namespace).Create(context.Background(), &svc, metav1.CreateOptions{})
		Expect(err).ToNot(HaveOccurred())
		svc.Status.LoadBalancer.Ingress = []v1.LoadBalancerIngress{
			{
				IP: "1.1.1.1",
			},
			{
				IP: "2.2.2.2",
			},
		}

		calicoIPs := map[string]bool{
			"1.1.1.1": true,
		}
		err = c.removeCalicoIPFromStatus(svc, calicoIPs)
		Expect(err).NotTo(HaveOccurred())
		Expect(svc.Status.LoadBalancer.Ingress).To(HaveLen(1))
		Expect(svc.Status.LoadBalancer.Ingress[0].IP).To(Equal("2.2.2.2"))
	})

	It("should update service status with IPs from allocationTracker", func() {
		svcKey, err := serviceKeyFromService(&svc)
		Expect(err).ToNot(HaveOccurred())
		svc, err := c.clientSet.CoreV1().Services(svc.Namespace).Create(context.Background(), &svc, metav1.CreateOptions{})
		Expect(err).ToNot(HaveOccurred())

		c.allocationTracker.ipsByService[*svcKey] = map[string]bool{"1.1.1.1": true}
		err = c.updateServiceStatus(svc, *svcKey)
		Expect(err).ToNot(HaveOccurred())
		Expect(svc.Status.LoadBalancer.Ingress).To(HaveLen(1))
		Expect(svc.Status.LoadBalancer.Ingress[0].IP).To(Equal("1.1.1.1"))

		c.allocationTracker.ipsByService[*svcKey] = map[string]bool{"2.2.2.2": true}
		delete(c.allocationTracker.ipsByService[*svcKey], "1.1.1.1")

		err = c.updateServiceStatus(svc, *svcKey)
		Expect(err).ToNot(HaveOccurred())
		Expect(svc.Status.LoadBalancer.Ingress).To(HaveLen(1))
		Expect(svc.Status.LoadBalancer.Ingress[0].IP).To(Equal("2.2.2.2"))

		delete(c.allocationTracker.ipsByService[*svcKey], "2.2.2.2")
		err = c.updateServiceStatus(svc, *svcKey)
		Expect(err).ToNot(HaveOccurred())
		Expect(svc.Status.LoadBalancer.Ingress).To(HaveLen(0))
	})
})
