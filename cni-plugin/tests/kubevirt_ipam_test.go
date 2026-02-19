// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package main_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"sort"

	"github.com/google/uuid"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/projectcalico/calico/cni-plugin/internal/pkg/testutils"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
	"github.com/projectcalico/calico/libcalico-go/lib/names"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

// GetCNIArgsForPod constructs a CNI_ARGS string matching the format kubelet uses in production.
// Kubelet always prepends IgnoreUnknown=1 so that CNI/IPAM plugins using cnitypes.LoadArgs
// with cnitypes.CommonArgs will ignore fields they don't define (e.g., K8S_POD_NAME).
// Without IgnoreUnknown=1, LoadArgs would fail on any field not present in the plugin's args struct.
func GetCNIArgsForPod(podName, namespace, containerID string) string {
	return fmt.Sprintf("IgnoreUnknown=1;K8S_POD_NAME=%s;K8S_POD_NAMESPACE=%s;K8S_POD_INFRA_CONTAINER_ID=%s",
		podName, namespace, containerID)
}

// verifyOwnerAttributes checks the IPAM owner attributes for all IPs allocated to a VMI handle.
func verifyOwnerAttributes(
	calicoClient client.Interface,
	networkName string,
	namespace string,
	vmName string,
	expectedActivePodName string,
	expectedVMIUID string,
	expectedVMUID string,
	expectedAlternatePodName string,
	expectedVMIMUID string,
) {
	ctx := context.Background()
	handleID := ipam.CreateVMIHandleID(networkName, namespace, vmName)

	ips, err := calicoClient.IPAM().IPsByHandle(ctx, handleID)
	Expect(err).NotTo(HaveOccurred(), "Failed to get IPs by handle %s", handleID)
	Expect(ips).NotTo(BeEmpty(), "No IPs found for handle %s", handleID)

	for _, ip := range ips {
		allocAttr, err := calicoClient.IPAM().GetAssignmentAttributes(ctx, cnet.IP{IP: ip.IP})
		Expect(err).NotTo(HaveOccurred(), "Failed to get assignment attributes for IP %s", ip)
		Expect(allocAttr).NotTo(BeNil(), "No allocation attributes for IP %s", ip)

		fmt.Printf("[TEST] Verifying attributes for IP %s (handle: %s)\n", ip, handleID)

		// Verify ActiveOwnerAttrs
		if expectedActivePodName != "" {
			Expect(allocAttr.ActiveOwnerAttrs).NotTo(BeNil(), "ActiveOwnerAttrs should not be nil")
			Expect(allocAttr.ActiveOwnerAttrs[ipam.AttributePod]).To(Equal(expectedActivePodName),
				"ActiveOwnerAttrs pod name mismatch")
			Expect(allocAttr.ActiveOwnerAttrs[ipam.AttributeNamespace]).To(Equal(namespace),
				"ActiveOwnerAttrs namespace mismatch")
			Expect(allocAttr.ActiveOwnerAttrs[ipam.AttributeVMIName]).To(Equal(vmName),
				"ActiveOwnerAttrs VMI name mismatch")
			Expect(allocAttr.ActiveOwnerAttrs[ipam.AttributeVMIUID]).To(Equal(expectedVMIUID),
				"ActiveOwnerAttrs VMI UID mismatch")
			if expectedVMUID != "" {
				Expect(allocAttr.ActiveOwnerAttrs[ipam.AttributeVMUID]).To(Equal(expectedVMUID),
					"ActiveOwnerAttrs VM UID mismatch")
			}
		} else {
			// Active owner should be cleared (nil or empty)
			if allocAttr.ActiveOwnerAttrs != nil {
				Expect(allocAttr.ActiveOwnerAttrs).To(BeEmpty(),
					"ActiveOwnerAttrs should be cleared for IP %s", ip)
			}
		}

		// Verify AlternateOwnerAttrs
		if expectedAlternatePodName != "" {
			Expect(allocAttr.AlternateOwnerAttrs).NotTo(BeNil(), "AlternateOwnerAttrs should not be nil for migration target")
			Expect(allocAttr.AlternateOwnerAttrs[ipam.AttributePod]).To(Equal(expectedAlternatePodName),
				"AlternateOwnerAttrs pod name mismatch")
			Expect(allocAttr.AlternateOwnerAttrs[ipam.AttributeNamespace]).To(Equal(namespace),
				"AlternateOwnerAttrs namespace mismatch")
			Expect(allocAttr.AlternateOwnerAttrs[ipam.AttributeVMIName]).To(Equal(vmName),
				"AlternateOwnerAttrs VMI name mismatch")
			Expect(allocAttr.AlternateOwnerAttrs[ipam.AttributeVMIUID]).To(Equal(expectedVMIUID),
				"AlternateOwnerAttrs VMI UID mismatch")
			if expectedVMIMUID != "" {
				Expect(allocAttr.AlternateOwnerAttrs[ipam.AttributeVMIMUID]).To(Equal(expectedVMIMUID),
					"AlternateOwnerAttrs VMIM UID mismatch")
			}
			if expectedVMUID != "" {
				Expect(allocAttr.AlternateOwnerAttrs[ipam.AttributeVMUID]).To(Equal(expectedVMUID),
					"AlternateOwnerAttrs VM UID mismatch")
			}
		} else {
			// No migration target expected - AlternateOwnerAttrs should be nil or empty
			if allocAttr.AlternateOwnerAttrs != nil {
				Expect(allocAttr.AlternateOwnerAttrs).To(BeEmpty(),
					"AlternateOwnerAttrs should be empty when no migration target is expected")
			}
		}

		fmt.Printf("[TEST] Owner attributes verified for IP %s\n", ip)
	}
}

// getIPsForVMIHandle returns the sorted list of IP strings allocated to a VMI handle.
// Useful for comparing IPs across operations to verify persistence.
func getIPsForVMIHandle(calicoClient client.Interface, networkName, namespace, vmName string) []string {
	ctx := context.Background()
	handleID := ipam.CreateVMIHandleID(networkName, namespace, vmName)

	ips, err := calicoClient.IPAM().IPsByHandle(ctx, handleID)
	Expect(err).NotTo(HaveOccurred(), "Failed to get IPs by handle %s", handleID)

	result := make([]string, len(ips))
	for i, ip := range ips {
		result[i] = ip.String()
	}
	sort.Strings(result)
	return result
}

// verifyOwnerAttributesCleared verifies that both ActiveOwnerAttrs and AlternateOwnerAttrs
// are nil or empty for all IPs allocated to a VMI handle. IPs must still be allocated.
func verifyOwnerAttributesCleared(calicoClient client.Interface, networkName, namespace, vmName string) {
	ctx := context.Background()
	handleID := ipam.CreateVMIHandleID(networkName, namespace, vmName)

	ips, err := calicoClient.IPAM().IPsByHandle(ctx, handleID)
	Expect(err).NotTo(HaveOccurred(), "Failed to get IPs by handle %s", handleID)
	Expect(ips).NotTo(BeEmpty(), "IPs should still be allocated to handle %s", handleID)

	for _, ip := range ips {
		allocAttr, err := calicoClient.IPAM().GetAssignmentAttributes(ctx, cnet.IP{IP: ip.IP})
		Expect(err).NotTo(HaveOccurred())

		if allocAttr.ActiveOwnerAttrs != nil {
			Expect(allocAttr.ActiveOwnerAttrs).To(BeEmpty(),
				"ActiveOwnerAttrs should be cleared for IP %s", ip)
		}
		if allocAttr.AlternateOwnerAttrs != nil {
			Expect(allocAttr.AlternateOwnerAttrs).To(BeEmpty(),
				"AlternateOwnerAttrs should be cleared for IP %s", ip)
		}
	}
	fmt.Printf("[TEST] Verified owner attributes cleared for handle %s (%d IPs)\n", handleID, len(ips))
}

// verifyHandleReleased verifies that the VMI handle has been released (no IPs allocated).
func verifyHandleReleased(calicoClient client.Interface, networkName, namespace, vmName string) {
	ctx := context.Background()
	handleID := ipam.CreateVMIHandleID(networkName, namespace, vmName)

	ips, err := calicoClient.IPAM().IPsByHandle(ctx, handleID)
	// After ReleaseByHandle, either IPsByHandle returns an error (handle not found)
	// or returns an empty list. Both indicate the handle has been released.
	if err == nil {
		Expect(ips).To(BeEmpty(), "Handle %s should have no IPs after release", handleID)
	}
	fmt.Printf("[TEST] Verified handle %s is released (err=%v, ipCount=%d)\n", handleID, err, len(ips))
}

// verifyHandleNotReleased verifies that the VMI handle still has IPs allocated matching expectedIPs.
func verifyHandleNotReleased(calicoClient client.Interface, networkName, namespace, vmName string, expectedIPs []string) {
	currentIPs := getIPsForVMIHandle(calicoClient, networkName, namespace, vmName)
	Expect(currentIPs).To(Equal(expectedIPs), "IPs should still be allocated to handle")
	fmt.Printf("[TEST] Verified handle still has IPs: %v\n", currentIPs)
}

// getDualStackNetconf returns a netconf JSON string that requests both IPv4 and IPv6 addresses.
func getDualStackNetconf(cniVersion string) string {
	return fmt.Sprintf(`{
		"cniVersion": "%s",
		"name": "net1",
		"type": "calico",
		"etcd_endpoints": "http://%s:2379",
		"kubernetes": {
			"kubeconfig": "/home/user/certs/kubeconfig",
			"k8s_api_root": "https://127.0.0.1:6443"
		},
		"datastore_type": "kubernetes",
		"log_level": "debug",
		"ipam": {
			"type": "calico-ipam",
			"assign_ipv4": "true",
			"assign_ipv6": "true"
		}
	}`, cniVersion, os.Getenv("ETCD_IP"))
}

// updateIPAMKubeVirtIPPersistence updates the KubeVirtVMAddressPersistence setting in IPAMConfig
func updateIPAMKubeVirtIPPersistence(calicoClient client.Interface, persistence *apiv3.VMAddressPersistence) {
	ctx := context.Background()
	ipamConfig, err := calicoClient.IPAMConfiguration().Get(ctx, "default", options.GetOptions{})

	if err != nil {
		// Check if error is specifically because the resource doesn't exist
		if _, ok := err.(errors.ErrorResourceDoesNotExist); !ok {
			// It's a different error, fail the test
			Expect(err).NotTo(HaveOccurred())
		}

		// IPAMConfig doesn't exist, create it
		fmt.Printf("[TEST] Creating IPAMConfig with KubeVirtVMAddressPersistence = %v\n", persistence)
		newConfig := &apiv3.IPAMConfiguration{
			ObjectMeta: metav1.ObjectMeta{
				Name: "default",
			},
			Spec: apiv3.IPAMConfigurationSpec{
				StrictAffinity:               false,
				AutoAllocateBlocks:           true,
				MaxBlocksPerHost:             0,
				KubeVirtVMAddressPersistence: persistence,
			},
		}
		_, err = calicoClient.IPAMConfiguration().Create(ctx, newConfig, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())
		fmt.Printf("[TEST] IPAMConfig created successfully\n")
	} else {
		// IPAMConfig exists, update it
		fmt.Printf("[TEST] Updating existing IPAMConfig with KubeVirtVMAddressPersistence = %v\n", persistence)
		ipamConfig.Spec.KubeVirtVMAddressPersistence = persistence
		_, err = calicoClient.IPAMConfiguration().Update(ctx, ipamConfig, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())
		fmt.Printf("[TEST] IPAMConfig updated successfully\n")
	}
}

// KubeVirt VM-based handle ID tests
// These tests verify that virt-launcher pods use VM-based handle IDs for IP persistence.
// The Makefile installs minimal KubeVirt CRDs (without operators) before running tests.
// Tests will skip gracefully if CRD installation fails.
var _ = Describe("KubeVirt VM-based handle ID", func() {
	// Skip these tests if not running against Kubernetes datastore
	// since we need to create CRD resources
	if os.Getenv("DATASTORE_TYPE") != "kubernetes" {
		return
	}

	cniVersion := os.Getenv("CNI_SPEC_VERSION")
	calicoClient, err := client.NewFromEnv()
	Expect(err).NotTo(HaveOccurred())

	var k8sClient *kubernetes.Clientset
	var testNs string
	var vmName string
	var podName string
	var cid string
	var virtResourceManager *KubeVirtResourceManager
	var sourcePodName string
	var sourceCID string
	var sourceCNIArgs string
	var netconf string
	var originalIPs []string

	// initialiseTestInfra sets up the test infrastructure including datastore, IP pools, k8s client, node, and namespace
	initialiseTestInfra := func() {
		testutils.WipeDatastore()
		testutils.MustCreateNewIPPool(calicoClient, "192.168.0.0/16", false, false, true)
		testutils.MustCreateNewIPPool(calicoClient, "fd80:24e2:f998:72d6::/64", false, false, true)

		// Create a unique container ID for each test
		cid = uuid.NewString()

		// Get Kubernetes client first (needed for AddNode)
		config, err := clientcmd.BuildConfigFromFlags("", "/home/user/certs/kubeconfig")
		Expect(err).NotTo(HaveOccurred())
		k8sClient, err = kubernetes.NewForConfig(config)
		Expect(err).NotTo(HaveOccurred())

		// Create the node for these tests. The IPAM code requires a corresponding Calico node to exist.
		var name string
		name, err = names.Hostname()
		Expect(err).NotTo(HaveOccurred())
		err = testutils.AddNode(calicoClient, k8sClient, name)
		Expect(err).NotTo(HaveOccurred())

		// Create a test namespace
		testNs = "test-kubevirt-" + uuid.NewString()[:8]
		ns := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: testNs,
			},
		}
		_, err = k8sClient.CoreV1().Namespaces().Create(context.Background(), ns, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		vmName = "test-vm"
		podName = "virt-launcher-" + vmName + "-abcde"

		// Initialize KubeVirt resource manager
		virtResourceManager, err = NewKubeVirtResourceManager(k8sClient, testNs, vmName)
		Expect(err).NotTo(HaveOccurred())
	}

	// setupSourceVirtLauncherPod creates the VMI (and optionally VM), source virt-launcher pod,
	// allocates dual-stack IPs, and verifies owner attributes.
	// If standalone is true, creates a standalone VMI without a VM owner.
	// If standalone is false, creates a VM and a VMI owned by that VM.
	setupSourceVirtLauncherPod := func(standalone bool) {
		if standalone {
			fmt.Println("[TEST] Setting up standalone VMI (no VM owner)")
			virtResourceManager.CreateStandaloneVMI()
		} else {
			fmt.Println("[TEST] Setting up VM-owned VMI")
			virtResourceManager.CreateVM()
			virtResourceManager.CreateVMI(false, "")
		}

		sourcePodName = "virt-launcher-" + vmName + "-source"
		sourceCID = uuid.NewString()
		virtResourceManager.CreateVirtLauncherPod(sourcePodName, "")

		netconf = getDualStackNetconf(cniVersion)
		sourceCNIArgs = GetCNIArgsForPod(sourcePodName, testNs, sourceCID)

		result, errOut, exitCode := testutils.RunIPAMPlugin(netconf, "ADD", sourceCNIArgs, sourceCID, cniVersion)
		Expect(exitCode).To(Equal(0), fmt.Sprintf("Source IPAM ADD failed: %v", errOut))
		Expect(result.IPs).To(HaveLen(2), "Expected dual-stack: one IPv4 and one IPv6")
		verifyRoutesPopulatedInResult(result, true)

		originalIPs = getIPsForVMIHandle(calicoClient, "net1", testNs, vmName)
		Expect(originalIPs).To(HaveLen(2))
		// Verify one IPv4 and one IPv6
		hasIPv4 := net.ParseIP(originalIPs[0]).To4() != nil || net.ParseIP(originalIPs[1]).To4() != nil
		hasIPv6 := net.ParseIP(originalIPs[0]).To4() == nil || net.ParseIP(originalIPs[1]).To4() == nil
		Expect(hasIPv4).To(BeTrue(), "Expected one IPv4 address in original IPs")
		Expect(hasIPv6).To(BeTrue(), "Expected one IPv6 address in original IPs")
		fmt.Printf("[TEST] Original IPs: %v\n", originalIPs)

		// Verify source pod is active owner, no alternate
		verifyOwnerAttributes(calicoClient, "net1", testNs, vmName,
			sourcePodName, virtResourceManager.Resources.VMIUID, virtResourceManager.Resources.VMUID,
			"", "")
	}

	// setupMigrationTarget creates VMIM and target pod for migration testing.
	// Assumes VM, VMI, and source pod with IPs are already created via setupSourceVirtLauncherPod(false).
	setupMigrationTarget := func() string {
		fmt.Printf("\n[TEST] ===== Setting up migration target =====\n")

		// Create VMIM
		migrationUID := virtResourceManager.CreateVMIM("test-migration")

		// Create target pod with migration label
		podName = "virt-launcher-" + vmName + "-target"
		virtResourceManager.CreateVirtLauncherPod(podName, migrationUID)

		fmt.Println("[TEST] Migration target setup completed - target pod created")
		return migrationUID
	}

	BeforeEach(func() {
		initialiseTestInfra()
	})

	AfterEach(func() {
		// Clean up test namespace
		if k8sClient != nil && testNs != "" {
			err := k8sClient.CoreV1().Namespaces().Delete(context.Background(), testNs, metav1.DeleteOptions{})
			if err != nil {
				fmt.Printf("Warning: failed to delete test namespace %s: %v\n", testNs, err)
			}
		}

		// Delete the node
		name, err := names.Hostname()
		Expect(err).NotTo(HaveOccurred())
		err = testutils.DeleteNode(calicoClient, k8sClient, name)
		Expect(err).NotTo(HaveOccurred())
	})

	Context("IP Persistence and Release", func() {
		Context("on pod recreation", func() {
			It("should retain IPs when virt-launcher pod is deleted and recreated with same VMI", func() {
				fmt.Println("\n[TEST] ===== Running test: IP persistence on pod recreation =====")
				setupSourceVirtLauncherPod(false)

				// Step 1: IPAM DEL for source pod - clears owner attrs but IPs stay allocated
				_, _, exitCode := testutils.RunIPAMPlugin(netconf, "DEL", sourceCNIArgs, sourceCID, cniVersion)
				Expect(exitCode).To(Equal(0))

				// Verify IPs still allocated but owner attributes cleared
				currentIPs := getIPsForVMIHandle(calicoClient, "net1", testNs, vmName)
				Expect(currentIPs).To(Equal(originalIPs), "IPs should persist after pod deletion")
				verifyOwnerAttributesCleared(calicoClient, "net1", testNs, vmName)

				// Step 2: Delete source pod from k8s, create pod2 with same VMI
				err := k8sClient.CoreV1().Pods(testNs).Delete(context.Background(), sourcePodName, metav1.DeleteOptions{})
				Expect(err).NotTo(HaveOccurred())

				pod2Name := "virt-launcher-" + vmName + "-pod2"
				cid2 := uuid.NewString()
				virtResourceManager.CreateVirtLauncherPod(pod2Name, "")

				// Step 3: IPAM ADD for pod2 - should get same IPs
				cniArgs2 := GetCNIArgsForPod(pod2Name, testNs, cid2)
				result2, errOut, exitCode := testutils.RunIPAMPlugin(netconf, "ADD", cniArgs2, cid2, cniVersion)
				Expect(exitCode).To(Equal(0), fmt.Sprintf("IPAM ADD for pod2 failed: %v", errOut))
				Expect(result2.IPs).To(HaveLen(2), "Expected dual-stack: one IPv4 and one IPv6")
				verifyRoutesPopulatedInResult(result2, true)

				// Verify same IPs were reused
				newIPs := getIPsForVMIHandle(calicoClient, "net1", testNs, vmName)
				Expect(newIPs).To(Equal(originalIPs), "IPs should be the same after pod recreation")
				fmt.Printf("[TEST] Recreated pod IPs: %v (same as original)\n", newIPs)

				// Verify pod2 is now active owner
				verifyOwnerAttributes(calicoClient, "net1", testNs, vmName,
					pod2Name, virtResourceManager.Resources.VMIUID, virtResourceManager.Resources.VMUID,
					"", "")

				// Clean up
				_, _, exitCode = testutils.RunIPAMPlugin(netconf, "DEL", cniArgs2, cid2, cniVersion)
				Expect(exitCode).To(Equal(0))
			})
		})

		Context("on live migration", func() {
			It("should retain IPs during live migration and clean up owners on pod deletion", func() {
				fmt.Println("\n[TEST] ===== Running test: IP persistence on live migration =====")
				setupSourceVirtLauncherPod(false)

				// Step 1: Add migration target pod, verify IPs are persistent,
				// verify owner attributes (source=active, target=alternate), and verify empty routes
				setupMigrationTarget()
				targetPodName := podName
				targetCID := uuid.NewString()
				targetCNIArgs := GetCNIArgsForPod(targetPodName, testNs, targetCID)
				result, errOut, exitCode := testutils.RunIPAMPlugin(netconf, "ADD", targetCNIArgs, targetCID, cniVersion)
				Expect(exitCode).To(Equal(0), fmt.Sprintf("Target IPAM ADD failed: %v", errOut))
				Expect(result.IPs).To(HaveLen(2), "Migration target should receive both existing IPs")

				currentIPs := getIPsForVMIHandle(calicoClient, "net1", testNs, vmName)
				Expect(currentIPs).To(Equal(originalIPs), "IPs should persist during migration")

				verifyOwnerAttributes(calicoClient, "net1", testNs, vmName,
					sourcePodName, virtResourceManager.Resources.VMIUID, virtResourceManager.Resources.VMUID,
					targetPodName, virtResourceManager.Resources.VMIMUID)

				verifyRoutesPopulatedInResult(result, false)

				// Step 2: Delete source pod, verify IPs persist,
				// verify active owner cleared and alternate (target) remains
				_, _, exitCode = testutils.RunIPAMPlugin(netconf, "DEL", sourceCNIArgs, sourceCID, cniVersion)
				Expect(exitCode).To(Equal(0))

				currentIPs = getIPsForVMIHandle(calicoClient, "net1", testNs, vmName)
				Expect(currentIPs).To(Equal(originalIPs), "IPs should persist after source pod deletion")

				verifyOwnerAttributes(calicoClient, "net1", testNs, vmName,
					"", // active owner cleared
					virtResourceManager.Resources.VMIUID, virtResourceManager.Resources.VMUID,
					targetPodName, virtResourceManager.Resources.VMIMUID)

				// Step 3: Delete target pod, verify IPs persist,
				// verify both owners cleared
				_, _, exitCode = testutils.RunIPAMPlugin(netconf, "DEL", targetCNIArgs, targetCID, cniVersion)
				Expect(exitCode).To(Equal(0))

				currentIPs = getIPsForVMIHandle(calicoClient, "net1", testNs, vmName)
				Expect(currentIPs).To(Equal(originalIPs), "IPs should persist after both pod deletions")
				verifyOwnerAttributesCleared(calicoClient, "net1", testNs, vmName)
			})
		})

		Context("on VMI recreation", func() {
			It("should retain IPs when VMI is deleted and recreated", func() {
				fmt.Println("\n[TEST] ===== Running test: IP persistence on VMI recreation =====")
				setupSourceVirtLauncherPod(false)
				oldVMIUID := virtResourceManager.Resources.VMIUID

				// Step 1: Delete VMI (simulating VMI recycling by VM controller)
				// Note: source pod is NOT deleted - it becomes orphaned
				fmt.Println("[TEST] Deleting VMI to simulate VMI recreation...")
				virtResourceManager.DeleteVMI()

				// Step 2: Create new VMI (same name, new UID - as VM controller would do)
				virtResourceManager.CreateVMI(false, "")
				newVMIUID := virtResourceManager.Resources.VMIUID
				Expect(newVMIUID).NotTo(Equal(oldVMIUID), "New VMI should have a different UID")
				fmt.Printf("[TEST] New VMI created with UID: %s (old: %s)\n", newVMIUID, oldVMIUID)

				// IPs should still be allocated to the handle (handle is based on namespace+name, not UID)
				currentIPs := getIPsForVMIHandle(calicoClient, "net1", testNs, vmName)
				Expect(currentIPs).To(Equal(originalIPs), "IPs should persist across VMI recreation")

				// Step 3: Create new source pod for the new VMI
				sourcePod2Name := "virt-launcher-" + vmName + "-src2"
				sourceCID2 := uuid.NewString()
				virtResourceManager.CreateVirtLauncherPod(sourcePod2Name, "")

				// Step 4: IPAM ADD for new source pod - should get same IPs
				cniArgs2 := GetCNIArgsForPod(sourcePod2Name, testNs, sourceCID2)
				result, errOut, exitCode := testutils.RunIPAMPlugin(netconf, "ADD", cniArgs2, sourceCID2, cniVersion)
				Expect(exitCode).To(Equal(0), fmt.Sprintf("Source pod2 IPAM ADD failed: %v", errOut))
				Expect(result.IPs).To(HaveLen(2))
				verifyRoutesPopulatedInResult(result, true)

				// Verify same IPs
				newIPs := getIPsForVMIHandle(calicoClient, "net1", testNs, vmName)
				Expect(newIPs).To(Equal(originalIPs), "IPs should be the same after VMI recreation")
				fmt.Printf("[TEST] New source pod IPs: %v (same as original)\n", newIPs)

				// Verify new source pod is active owner with new VMI UID
				verifyOwnerAttributes(calicoClient, "net1", testNs, vmName,
					sourcePod2Name, newVMIUID, virtResourceManager.Resources.VMUID,
					"", "")

				// Clean up
				_, _, exitCode = testutils.RunIPAMPlugin(netconf, "DEL", cniArgs2, sourceCID2, cniVersion)
				Expect(exitCode).To(Equal(0))
			})
		})

		Context("IP release", func() {
			It("should not release handle when source pod is deleted without VM deletion", func() {
				fmt.Println("\n[TEST] ===== Running test: IP release - no release on pod deletion without VM deletion =====")
				setupSourceVirtLauncherPod(false)

				// IPAM DEL for source pod - clears owner attrs but VM is not being deleted
				_, _, exitCode := testutils.RunIPAMPlugin(netconf, "DEL", sourceCNIArgs, sourceCID, cniVersion)
				Expect(exitCode).To(Equal(0))

				// Handle and IPs should still exist (VM not deleting → no release)
				verifyHandleNotReleased(calicoClient, "net1", testNs, vmName, originalIPs)
				verifyOwnerAttributesCleared(calicoClient, "net1", testNs, vmName)
			})

			It("should not release handle when VMI has deletion timestamp", func() {
				fmt.Println("\n[TEST] ===== Running test: IP release - no release on VMI deletion =====")
				setupSourceVirtLauncherPod(false)

				// Set deletion timestamp on VMI (not VM)
				virtResourceManager.SetVMIDeletionTimestamp()

				// IPAM DEL for source pod
				_, _, exitCode := testutils.RunIPAMPlugin(netconf, "DEL", sourceCNIArgs, sourceCID, cniVersion)
				Expect(exitCode).To(Equal(0))

				// Handle and IPs should still exist (only VM deletion triggers release, not VMI)
				verifyHandleNotReleased(calicoClient, "net1", testNs, vmName, originalIPs)
				verifyOwnerAttributesCleared(calicoClient, "net1", testNs, vmName)
			})

			It("should release handle when VM has deletion timestamp and pod is deleted", func() {
				fmt.Println("\n[TEST] ===== Running test: IP release - release on VM deletion =====")
				setupSourceVirtLauncherPod(false)

				// Set deletion timestamp on VM
				virtResourceManager.SetVMDeletionTimestamp()

				// IPAM DEL for source pod - VM is deleting and all owners cleared → release
				_, _, exitCode := testutils.RunIPAMPlugin(netconf, "DEL", sourceCNIArgs, sourceCID, cniVersion)
				Expect(exitCode).To(Equal(0))

				// Handle and IPs should be released
				verifyHandleReleased(calicoClient, "net1", testNs, vmName)
			})

			It("should release handle when both owners are deleted with VM deleting (source first)", func() {
				fmt.Println("\n[TEST] ===== Running test: IP release - both owners deleted, source first =====")
				setupSourceVirtLauncherPod(false)

				// Step 1: Add migration target pod
				setupMigrationTarget()
				targetPodName := podName
				targetCID := uuid.NewString()
				targetCNIArgs := GetCNIArgsForPod(targetPodName, testNs, targetCID)
				result, errOut, exitCode := testutils.RunIPAMPlugin(netconf, "ADD", targetCNIArgs, targetCID, cniVersion)
				Expect(exitCode).To(Equal(0), fmt.Sprintf("Target IPAM ADD failed: %v", errOut))
				Expect(result.IPs).To(HaveLen(2))

				// Step 2: Verify two owners (source=active, target=alternate)
				verifyOwnerAttributes(calicoClient, "net1", testNs, vmName,
					sourcePodName, virtResourceManager.Resources.VMIUID, virtResourceManager.Resources.VMUID,
					targetPodName, virtResourceManager.Resources.VMIMUID)

				// Step 3: Set VM deletion timestamp
				virtResourceManager.SetVMDeletionTimestamp()

				// Step 4: Delete source pod - clears active owner, but alternate (target) remains → not released
				_, _, exitCode = testutils.RunIPAMPlugin(netconf, "DEL", sourceCNIArgs, sourceCID, cniVersion)
				Expect(exitCode).To(Equal(0))
				verifyHandleNotReleased(calicoClient, "net1", testNs, vmName, originalIPs)

				// Step 5: Delete target pod - clears alternate owner, all owners empty, VM deleting → released
				_, _, exitCode = testutils.RunIPAMPlugin(netconf, "DEL", targetCNIArgs, targetCID, cniVersion)
				Expect(exitCode).To(Equal(0))
				verifyHandleReleased(calicoClient, "net1", testNs, vmName)
			})

			It("should release handle when both owners are deleted with VM deleting (target first)", func() {
				fmt.Println("\n[TEST] ===== Running test: IP release - both owners deleted, target first =====")
				setupSourceVirtLauncherPod(false)

				// Step 1: Add migration target pod
				setupMigrationTarget()
				targetPodName := podName
				targetCID := uuid.NewString()
				targetCNIArgs := GetCNIArgsForPod(targetPodName, testNs, targetCID)
				result, errOut, exitCode := testutils.RunIPAMPlugin(netconf, "ADD", targetCNIArgs, targetCID, cniVersion)
				Expect(exitCode).To(Equal(0), fmt.Sprintf("Target IPAM ADD failed: %v", errOut))
				Expect(result.IPs).To(HaveLen(2))

				// Step 2: Verify two owners (source=active, target=alternate)
				verifyOwnerAttributes(calicoClient, "net1", testNs, vmName,
					sourcePodName, virtResourceManager.Resources.VMIUID, virtResourceManager.Resources.VMUID,
					targetPodName, virtResourceManager.Resources.VMIMUID)

				// Step 3: Set VM deletion timestamp
				virtResourceManager.SetVMDeletionTimestamp()

				// Step 4: Delete target pod - clears alternate owner, but active (source) remains → not released
				_, _, exitCode = testutils.RunIPAMPlugin(netconf, "DEL", targetCNIArgs, targetCID, cniVersion)
				Expect(exitCode).To(Equal(0))
				verifyHandleNotReleased(calicoClient, "net1", testNs, vmName, originalIPs)

				// Step 5: Delete source pod - clears active owner, all owners empty, VM deleting → released
				_, _, exitCode = testutils.RunIPAMPlugin(netconf, "DEL", sourceCNIArgs, sourceCID, cniVersion)
				Expect(exitCode).To(Equal(0))
				verifyHandleReleased(calicoClient, "net1", testNs, vmName)
			})

			It("should release handle when standalone VMI has deletion timestamp and pod is deleted", func() {
				fmt.Println("\n[TEST] ===== Running test: IP release - standalone VMI with deletion timestamp =====")
				setupSourceVirtLauncherPod(true)

				// Set VMI deletion timestamp (no VM to delete, VMI itself is being deleted)
				virtResourceManager.SetVMIDeletionTimestamp()

				// IPAM DEL - standalone VMI is deleting and all owners will be cleared → release
				_, _, exitCode := testutils.RunIPAMPlugin(netconf, "DEL", sourceCNIArgs, sourceCID, cniVersion)
				Expect(exitCode).To(Equal(0))

				// Verify handle is released
				verifyHandleReleased(calicoClient, "net1", testNs, vmName)
			})
		})
	})

	Context("KubeVirt object verification", func() {
		It("should fail IPAM ADD when pod references a VMI that does not exist", func() {
			fmt.Println("\n[TEST] ===== Running test: should fail IPAM ADD when pod references a non-existent VMI =====")

			// Create a virt-launcher pod with ownerReference pointing to a VMI that does not exist.
			// We do NOT call CreateVM/CreateVMI, so the VMI object is absent from the cluster.
			controllerTrue := true
			fakeVMIUID := "non-existent-vmi-uid-" + uuid.NewString()
			fakePodName := "virt-launcher-" + vmName + "-orphan"

			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      fakePodName,
					Namespace: testNs,
					UID:       k8stypes.UID("pod-" + uuid.NewString()),
					Labels: map[string]string{
						"kubevirt.io/domain": vmName,
					},
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion: "kubevirt.io/v1",
							Kind:       "VirtualMachineInstance",
							Name:       vmName,
							UID:        k8stypes.UID(fakeVMIUID),
							Controller: &controllerTrue,
						},
					},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "compute",
							Image: "registry.k8s.io/pause:3.1",
						},
					},
				},
			}

			_, err := k8sClient.CoreV1().Pods(testNs).Create(context.Background(), pod, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			// Wait for the pod to be retrievable
			Eventually(func() error {
				_, err := k8sClient.CoreV1().Pods(testNs).Get(context.Background(), fakePodName, metav1.GetOptions{})
				return err
			}, "5s", "100ms").Should(BeNil())

			netconf := getDualStackNetconf(cniVersion)
			fakeCID := uuid.NewString()
			cniArgs := GetCNIArgsForPod(fakePodName, testNs, fakeCID)

			// IPAM ADD should fail because the referenced VMI does not exist
			_, errOut, exitCode := testutils.RunIPAMPlugin(netconf, "ADD", cniArgs, fakeCID, cniVersion)
			Expect(exitCode).NotTo(Equal(0), "IPAM ADD should fail when the referenced VMI does not exist")
			Expect(errOut.Msg).To(ContainSubstring("failed to get VMI info"),
				"Error should indicate VMI lookup failure")

			fmt.Printf("[TEST] IPAM ADD correctly failed: exit=%d, err=%s\n", exitCode, errOut.Msg)
		})
	})

	Context("KubeVirt VM persistence disabled", func() {
		AfterEach(func() {
			// Clean up IPAMConfig setting
			updateIPAMKubeVirtIPPersistence(calicoClient, nil)
		})

		It("should fail if migration target but KubeVirtVMAddressPersistence is disabled", func() {
			fmt.Println("\n[TEST] ===== Running test: should fail if migration target but KubeVirtVMAddressPersistence is disabled =====")
			setupSourceVirtLauncherPod(false)

			// Set IPAMConfig to disable VM address persistence.
			updateIPAMKubeVirtIPPersistence(calicoClient, vmAddressPersistencePtr(apiv3.VMAddressPersistenceDisabled))

			// Set up migration target (VMIM + target pod)
			setupMigrationTarget()

			netconf := getDualStackNetconf(cniVersion)
			cniArgs := GetCNIArgsForPod(podName, testNs, cid)

			// Run IPAM ADD - should fail because migration targets are rejected
			// when persistence is disabled (VMI detection still happens to catch this).
			_, errOut, exitCode := testutils.RunIPAMPlugin(netconf, "ADD", cniArgs, cid, cniVersion)
			Expect(exitCode).NotTo(Equal(0), "IPAM ADD should fail when persistence is disabled")
			Expect(errOut.Msg).To(ContainSubstring("not allowed when KubeVirtVMAddressPersistence is disabled"))
		})

		It("should treat virt-launcher source pod as a normal pod when persistence is disabled", func() {
			fmt.Println("\n[TEST] ===== Running test: should treat virt-launcher source pod as a normal pod when persistence is disabled =====")

			// Disable persistence BEFORE creating the source pod
			updateIPAMKubeVirtIPPersistence(calicoClient, vmAddressPersistencePtr(apiv3.VMAddressPersistenceDisabled))

			// Create VM and VMI resources
			virtResourceManager.CreateVM()
			virtResourceManager.CreateVMI(false, "")

			netconf := getDualStackNetconf(cniVersion)
			ctx := context.Background()
			vmiHandleID := ipam.CreateVMIHandleID("net1", testNs, vmName)

			// 1. Create first pod, save its IPs, verify no VMI-based handle or owner attributes
			firstPod := "virt-launcher-" + vmName + "-disabled-1"
			firstCID := uuid.NewString()
			virtResourceManager.CreateVirtLauncherPod(firstPod, "")

			firstCNIArgs := GetCNIArgsForPod(firstPod, testNs, firstCID)
			result1, _, exitCode := testutils.RunIPAMPlugin(netconf, "ADD", firstCNIArgs, firstCID, cniVersion)
			Expect(exitCode).To(Equal(0), "IPAM ADD should succeed for first pod")
			Expect(result1.IPs).NotTo(BeEmpty(), "First pod should have allocated IPs")

			firstPodIPs := make([]string, len(result1.IPs))
			for i, ip := range result1.IPs {
				firstPodIPs[i] = ip.Address.IP.String()
			}
			fmt.Printf("[TEST] First pod IPs: %v\n", firstPodIPs)

			// No VMI-based handle should exist
			ips, err := calicoClient.IPAM().IPsByHandle(ctx, vmiHandleID)
			if err == nil {
				Expect(ips).To(BeEmpty(), "VMI-based handle should not have any IPs when persistence is disabled")
			}
			fmt.Printf("[TEST] Confirmed no IPs on VMI handle %s (err=%v)\n", vmiHandleID, err)

			// 2. Create second pod with same VMI owner, verify it gets a different IP
			secondPod := "virt-launcher-" + vmName + "-disabled-2"
			secondCID := uuid.NewString()
			virtResourceManager.CreateVirtLauncherPod(secondPod, "")

			secondCNIArgs := GetCNIArgsForPod(secondPod, testNs, secondCID)
			result2, _, exitCode := testutils.RunIPAMPlugin(netconf, "ADD", secondCNIArgs, secondCID, cniVersion)
			Expect(exitCode).To(Equal(0), "IPAM ADD should succeed for second pod")
			Expect(result2.IPs).NotTo(BeEmpty(), "Second pod should have allocated IPs")

			secondPodIPs := make([]string, len(result2.IPs))
			for i, ip := range result2.IPs {
				secondPodIPs[i] = ip.Address.IP.String()
			}
			fmt.Printf("[TEST] Second pod IPs: %v\n", secondPodIPs)

			// Second pod should have different IPs from first (no VMI-based reuse)
			for _, secondIP := range secondPodIPs {
				Expect(firstPodIPs).NotTo(ContainElement(secondIP),
					fmt.Sprintf("Second pod IP %s should differ from first pod IPs %v", secondIP, firstPodIPs))
			}

			// 3. Delete first pod, verify its IPs are released
			_, _, exitCode = testutils.RunIPAMPlugin(netconf, "DEL", firstCNIArgs, firstCID, cniVersion)
			Expect(exitCode).To(Equal(0), "IPAM DEL should succeed for first pod")

			firstHandleID := fmt.Sprintf("net1.%s", firstCID)
			ips, err = calicoClient.IPAM().IPsByHandle(ctx, firstHandleID)
			if err == nil {
				Expect(ips).To(BeEmpty(), "First pod's handle should have no IPs after DEL")
			}
			fmt.Printf("[TEST] Confirmed first pod IPs released (handle=%s, err=%v)\n", firstHandleID, err)

			// 4. Delete second pod, verify its IPs are released
			_, _, exitCode = testutils.RunIPAMPlugin(netconf, "DEL", secondCNIArgs, secondCID, cniVersion)
			Expect(exitCode).To(Equal(0), "IPAM DEL should succeed for second pod")

			secondHandleID := fmt.Sprintf("net1.%s", secondCID)
			ips, err = calicoClient.IPAM().IPsByHandle(ctx, secondHandleID)
			if err == nil {
				Expect(ips).To(BeEmpty(), "Second pod's handle should have no IPs after DEL")
			}
			fmt.Printf("[TEST] Confirmed second pod IPs released (handle=%s, err=%v)\n", secondHandleID, err)
		})
	})
})

// Helper function to create VMAddressPersistence pointer
func vmAddressPersistencePtr(v apiv3.VMAddressPersistence) *apiv3.VMAddressPersistence {
	return &v
}

// KubeVirtTestResources stores information about created KubeVirt resources
type KubeVirtTestResources struct {
	VMUID         string
	VMIUID        string
	VMIMUID       string
	SourcePodName string
	TargetPodName string
}

// KubeVirtResourceManager encapsulates resources and methods for KubeVirt testing
type KubeVirtResourceManager struct {
	dynamicClient dynamic.Interface
	k8sClient     kubernetes.Interface
	testNs        string
	vmName        string
	Resources     KubeVirtTestResources
}

// NewKubeVirtResourceManager creates a new KubeVirt resource manager
func NewKubeVirtResourceManager(k8sClient kubernetes.Interface, testNs, vmName string) (*KubeVirtResourceManager, error) {
	config, err := clientcmd.BuildConfigFromFlags("", "/home/user/certs/kubeconfig")
	if err != nil {
		return nil, err
	}

	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	return &KubeVirtResourceManager{
		dynamicClient: dynamicClient,
		k8sClient:     k8sClient,
		testNs:        testNs,
		vmName:        vmName,
		Resources:     KubeVirtTestResources{},
	}, nil
}

// CreateVM creates a VirtualMachine resource
func (h *KubeVirtResourceManager) CreateVM() {
	gvr := schema.GroupVersionResource{
		Group:    "kubevirt.io",
		Version:  "v1",
		Resource: "virtualmachines",
	}

	vm := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "kubevirt.io/v1",
			"kind":       "VirtualMachine",
			"metadata": map[string]interface{}{
				"name":      h.vmName,
				"namespace": h.testNs,
			},
			"spec": map[string]interface{}{
				"running": true,
			},
		},
	}

	createdVM, err := h.dynamicClient.Resource(gvr).Namespace(h.testNs).Create(context.Background(), vm, metav1.CreateOptions{})
	if err != nil {
		Skip(fmt.Sprintf("Skipping KubeVirt tests - CRDs not installed: %v", err))
	}

	h.Resources.VMUID = string(createdVM.GetUID())
	fmt.Printf("[TEST] VM created successfully: %s/%s (actual UID from K8s: %s)\n", h.testNs, h.vmName, h.Resources.VMUID)
}

// CreateVMI creates a VirtualMachineInstance resource
func (h *KubeVirtResourceManager) CreateVMI(withMigration bool, migrationUID string) {
	controllerTrue := true
	blockOwnerDeletion := true

	vmiObj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "kubevirt.io/v1",
			"kind":       "VirtualMachineInstance",
			"metadata": map[string]interface{}{
				"name":      h.vmName,
				"namespace": h.testNs,
				"ownerReferences": []interface{}{
					map[string]interface{}{
						"apiVersion":         "kubevirt.io/v1",
						"kind":               "VirtualMachine",
						"name":               h.vmName,
						"uid":                h.Resources.VMUID,
						"controller":         controllerTrue,
						"blockOwnerDeletion": blockOwnerDeletion,
					},
				},
			},
			"spec": map[string]interface{}{},
			"status": map[string]interface{}{
				"activePods": map[string]interface{}{
					"pod-" + uuid.NewString(): "node1",
				},
			},
		},
	}

	// Add migration state if requested
	if withMigration {
		status := vmiObj.Object["status"].(map[string]interface{})
		status["migrationState"] = map[string]interface{}{
			"migrationUID": migrationUID,
			"sourcePod":    "virt-launcher-source",
			"targetPod":    "virt-launcher-target",
		}
	}

	gvr := schema.GroupVersionResource{
		Group:    "kubevirt.io",
		Version:  "v1",
		Resource: "virtualmachineinstances",
	}

	createdVMI, err := h.dynamicClient.Resource(gvr).Namespace(h.testNs).Create(context.Background(), vmiObj, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred())

	h.Resources.VMIUID = string(createdVMI.GetUID())
	fmt.Printf("[TEST] VMI created successfully: %s/%s (actual UID from K8s: %s, withMigration: %v)\n", h.testNs, h.vmName, h.Resources.VMIUID, withMigration)

	// Wait for VMI to be retrievable
	fmt.Printf("[TEST] Waiting for VMI to be retrievable...\n")
	Eventually(func() error {
		_, err := h.dynamicClient.Resource(gvr).Namespace(h.testNs).Get(context.Background(), h.vmName, metav1.GetOptions{})
		return err
	}, "5s", "100ms").Should(BeNil())
	fmt.Printf("[TEST] VMI is now retrievable: %s/%s with UID: %s\n", h.testNs, h.vmName, h.Resources.VMIUID)
}

// CreateStandaloneVMI creates a VirtualMachineInstance resource without a VM owner.
// This simulates a standalone VMI that was created directly (not via a VirtualMachine object).
func (h *KubeVirtResourceManager) CreateStandaloneVMI() {
	vmiObj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "kubevirt.io/v1",
			"kind":       "VirtualMachineInstance",
			"metadata": map[string]interface{}{
				"name":      h.vmName,
				"namespace": h.testNs,
			},
			"spec": map[string]interface{}{},
			"status": map[string]interface{}{
				"activePods": map[string]interface{}{
					"pod-" + uuid.NewString(): "node1",
				},
			},
		},
	}

	gvr := schema.GroupVersionResource{
		Group:    "kubevirt.io",
		Version:  "v1",
		Resource: "virtualmachineinstances",
	}

	createdVMI, err := h.dynamicClient.Resource(gvr).Namespace(h.testNs).Create(context.Background(), vmiObj, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred())

	h.Resources.VMIUID = string(createdVMI.GetUID())
	fmt.Printf("[TEST] Standalone VMI created successfully: %s/%s (actual UID from K8s: %s, no VM owner)\n", h.testNs, h.vmName, h.Resources.VMIUID)

	// Wait for VMI to be retrievable
	fmt.Printf("[TEST] Waiting for standalone VMI to be retrievable...\n")
	Eventually(func() error {
		_, err := h.dynamicClient.Resource(gvr).Namespace(h.testNs).Get(context.Background(), h.vmName, metav1.GetOptions{})
		return err
	}, "5s", "100ms").Should(BeNil())
	fmt.Printf("[TEST] Standalone VMI is now retrievable: %s/%s with UID: %s\n", h.testNs, h.vmName, h.Resources.VMIUID)
}

// CreateVirtLauncherPod creates a virt-launcher pod
func (h *KubeVirtResourceManager) CreateVirtLauncherPod(podName string, migrationUID string) {
	controllerTrue := true

	podLabels := map[string]string{
		"kubevirt.io/domain": h.vmName,
	}

	// Add migration label if migrationUID is provided
	if migrationUID != "" {
		podLabels["kubevirt.io/migrationJobUID"] = migrationUID
	}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
			Namespace: h.testNs,
			UID:       k8stypes.UID("pod-" + uuid.NewString()),
			Labels:    podLabels,
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: "kubevirt.io/v1",
					Kind:       "VirtualMachineInstance",
					Name:       h.vmName,
					UID:        k8stypes.UID(h.Resources.VMIUID),
					Controller: &controllerTrue,
				},
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:  "compute",
					Image: "registry.k8s.io/pause:3.1",
				},
			},
		},
	}

	_, err := h.k8sClient.CoreV1().Pods(h.testNs).Create(context.Background(), pod, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred())
	fmt.Printf("[TEST] Virt-launcher pod created successfully: %s/%s (migrationUID: %s, VMI UID: %s)\n", h.testNs, podName, migrationUID, h.Resources.VMIUID)

	// Wait for pod to be retrievable
	Eventually(func() error {
		_, err := h.k8sClient.CoreV1().Pods(h.testNs).Get(context.Background(), podName, metav1.GetOptions{})
		return err
	}, "5s", "100ms").Should(BeNil())
	fmt.Printf("[TEST] Virt-launcher pod is now retrievable: %s/%s\n", h.testNs, podName)

	// Track pod name in resources
	if migrationUID != "" {
		h.Resources.TargetPodName = podName
	} else {
		h.Resources.SourcePodName = podName
	}
}

// DeleteVMI deletes the VirtualMachineInstance resource and waits for it to be gone
func (h *KubeVirtResourceManager) DeleteVMI() {
	gvr := schema.GroupVersionResource{
		Group:    "kubevirt.io",
		Version:  "v1",
		Resource: "virtualmachineinstances",
	}

	err := h.dynamicClient.Resource(gvr).Namespace(h.testNs).Delete(context.Background(), h.vmName, metav1.DeleteOptions{})
	Expect(err).NotTo(HaveOccurred())

	// Wait for VMI to be deleted
	Eventually(func() bool {
		_, err := h.dynamicClient.Resource(gvr).Namespace(h.testNs).Get(context.Background(), h.vmName, metav1.GetOptions{})
		return err != nil
	}, "10s", "200ms").Should(BeTrue(), "VMI should be deleted")

	fmt.Printf("[TEST] VMI deleted: %s/%s (old UID: %s)\n", h.testNs, h.vmName, h.Resources.VMIUID)
	h.Resources.VMIUID = ""
}

// CreateVMIM creates a VirtualMachineInstanceMigration resource
func (h *KubeVirtResourceManager) CreateVMIM(name string) string {
	vmim := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "kubevirt.io/v1",
			"kind":       "VirtualMachineInstanceMigration",
			"metadata": map[string]interface{}{
				"name":      name,
				"namespace": h.testNs,
			},
			"spec": map[string]interface{}{
				"vmiName": h.vmName,
			},
		},
	}

	gvr := schema.GroupVersionResource{
		Group:    "kubevirt.io",
		Version:  "v1",
		Resource: "virtualmachineinstancemigrations",
	}

	createdVMIM, err := h.dynamicClient.Resource(gvr).Namespace(h.testNs).Create(context.Background(), vmim, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred())

	h.Resources.VMIMUID = string(createdVMIM.GetUID())
	fmt.Printf("[TEST] VMIM created successfully: %s/%s (actual UID from K8s: %s)\n", h.testNs, name, h.Resources.VMIMUID)

	// Wait for VMIM to be retrievable
	fmt.Printf("[TEST] Waiting for VMIM to be retrievable...\n")
	Eventually(func() error {
		_, err := h.dynamicClient.Resource(gvr).Namespace(h.testNs).Get(context.Background(), name, metav1.GetOptions{})
		return err
	}, "5s", "100ms").Should(BeNil())
	fmt.Printf("[TEST] VMIM is now retrievable: %s/%s with UID: %s\n", h.testNs, name, h.Resources.VMIMUID)

	return h.Resources.VMIMUID
}

// SetVMDeletionTimestamp sets a deletion timestamp on the VM object by adding a finalizer
// then initiating deletion. The finalizer prevents actual removal while DeletionTimestamp is set.
func (h *KubeVirtResourceManager) SetVMDeletionTimestamp() {
	gvr := schema.GroupVersionResource{
		Group:    "kubevirt.io",
		Version:  "v1",
		Resource: "virtualmachines",
	}

	// Add a finalizer to prevent actual deletion
	patch := []byte(`[{"op": "add", "path": "/metadata/finalizers", "value": ["test.calico.org/prevent-deletion"]}]`)
	_, err := h.dynamicClient.Resource(gvr).Namespace(h.testNs).Patch(
		context.Background(), h.vmName, k8stypes.JSONPatchType, patch, metav1.PatchOptions{})
	Expect(err).NotTo(HaveOccurred(), "Failed to add finalizer to VM")

	// Delete the VM - sets DeletionTimestamp but finalizer prevents actual removal
	err = h.dynamicClient.Resource(gvr).Namespace(h.testNs).Delete(
		context.Background(), h.vmName, metav1.DeleteOptions{})
	Expect(err).NotTo(HaveOccurred(), "Failed to initiate VM deletion")

	// Verify VM still exists with DeletionTimestamp set
	vm, err := h.dynamicClient.Resource(gvr).Namespace(h.testNs).Get(
		context.Background(), h.vmName, metav1.GetOptions{})
	Expect(err).NotTo(HaveOccurred(), "VM should still exist (protected by finalizer)")
	Expect(vm.GetDeletionTimestamp()).NotTo(BeNil(), "VM should have DeletionTimestamp set")

	fmt.Printf("[TEST] VM %s/%s now has DeletionTimestamp set\n", h.testNs, h.vmName)
}

// SetVMIDeletionTimestamp sets a deletion timestamp on the VMI object by adding a finalizer
// then initiating deletion. The finalizer prevents actual removal while DeletionTimestamp is set.
func (h *KubeVirtResourceManager) SetVMIDeletionTimestamp() {
	gvr := schema.GroupVersionResource{
		Group:    "kubevirt.io",
		Version:  "v1",
		Resource: "virtualmachineinstances",
	}

	// Add a finalizer to prevent actual deletion
	patch := []byte(`[{"op": "add", "path": "/metadata/finalizers", "value": ["test.calico.org/prevent-deletion"]}]`)
	_, err := h.dynamicClient.Resource(gvr).Namespace(h.testNs).Patch(
		context.Background(), h.vmName, k8stypes.JSONPatchType, patch, metav1.PatchOptions{})
	Expect(err).NotTo(HaveOccurred(), "Failed to add finalizer to VMI")

	// Delete the VMI - sets DeletionTimestamp but finalizer prevents actual removal
	err = h.dynamicClient.Resource(gvr).Namespace(h.testNs).Delete(
		context.Background(), h.vmName, metav1.DeleteOptions{})
	Expect(err).NotTo(HaveOccurred(), "Failed to initiate VMI deletion")

	// Verify VMI still exists with DeletionTimestamp set
	vmi, err := h.dynamicClient.Resource(gvr).Namespace(h.testNs).Get(
		context.Background(), h.vmName, metav1.GetOptions{})
	Expect(err).NotTo(HaveOccurred(), "VMI should still exist (protected by finalizer)")
	Expect(vmi.GetDeletionTimestamp()).NotTo(BeNil(), "VMI should have DeletionTimestamp set")

	fmt.Printf("[TEST] VMI %s/%s now has DeletionTimestamp set\n", h.testNs, h.vmName)
}
