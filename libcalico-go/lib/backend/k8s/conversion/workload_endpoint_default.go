// Copyright (c) 2016-2025 Tigera, Inc. All rights reserved.

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

package conversion

import (
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"
	log "github.com/sirupsen/logrus"
	kapiv1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	libapiv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/json"
	"github.com/projectcalico/calico/libcalico-go/lib/names"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

var (
	// Bandwidth in bits per second
	minBandwidth = resource.MustParse("1k")
	maxBandwidth = resource.MustParse("1P")
	// Burst sizes in bits
	minBurst     = resource.MustParse("1k")
	defaultBurst = resource.MustParse("4Gi")                                    // 512 Mi bytes
	maxBurst     = resource.MustParse(strconv.FormatUint(math.MaxUint32*8, 10)) // 34359738360, approx. 4Gi bytes
	// Peakrate in bits per second
	// Peakrate should always be greater than bandwidth, so we make the min and max slightly higher than those
	minPeakrate = resource.MustParse("1.01k")
	maxPeakrate = resource.MustParse("1.01P")
	// Minburst in bytes (not bits because it is typically the MTU)
	minMinburst = resource.MustParse("1k")
	maxMinburst = resource.MustParse("100M")
	// Packet rate in packets per second
	// Packet rate and packet burst are limited to XT_LIMIT_SCALE (10k)
	// See https://github.com/torvalds/linux/blob/16b70698aa3ae7888826d0c84567c72241cf6713/include/uapi/linux/netfilter/xt_limit.h#L8
	minPacketRate = resource.MustParse("1")
	maxPacketRate = resource.MustParse("10k")
	// Packet burst sizes in number of packets
	minPacketBurst     = resource.MustParse("1")
	defaultPacketBurst = resource.MustParse("5")
	maxPacketBurst     = resource.MustParse("10k")
	// Maximum number of connections (absolute number of connections, no unit)
	minNumConnections = resource.MustParse("1")
	// The connection limit is an uint32 (maximum value 4294967295).
	// See https://github.com/torvalds/linux/blob/16b70698aa3ae7888826d0c84567c72241cf6713/include/uapi/linux/netfilter/xt_connlimit.h#L25
	maxNumConnections = resource.MustParse(strconv.FormatUint(math.MaxUint32, 10))
)

type defaultWorkloadEndpointConverter struct{}

// VethNameForWorkload returns a deterministic veth name
// for the given Kubernetes workload (WEP) name and namespace.
func (wc defaultWorkloadEndpointConverter) VethNameForWorkload(namespace, podname string) string {
	// A SHA1 is always 20 bytes long, and so is sufficient for generating the
	// veth name and mac addr.
	h := sha1.New()
	h.Write([]byte(fmt.Sprintf("%s.%s", namespace, podname)))
	prefix := os.Getenv("FELIX_INTERFACEPREFIX")
	if prefix == "" {
		// Prefix is not set. Default to "cali"
		prefix = "cali"
	} else {
		// Prefix is set - use the first value in the list.
		splits := strings.Split(prefix, ",")
		prefix = splits[0]
	}
	log.WithField("prefix", prefix).Debugf("Using prefix to create a WorkloadEndpoint veth name")
	return fmt.Sprintf("%s%s", prefix, hex.EncodeToString(h.Sum(nil))[:11])
}

func (wc defaultWorkloadEndpointConverter) PodToWorkloadEndpoints(pod *kapiv1.Pod) ([]*model.KVPair, error) {
	wep, err := wc.podToDefaultWorkloadEndpoint(pod)
	if err != nil {
		return nil, err
	}

	return []*model.KVPair{wep}, nil
}

// PodToWorkloadEndpoint converts a Pod to a WorkloadEndpoint.  It assumes the calling code
// has verified that the provided Pod is valid to convert to a WorkloadEndpoint.
// PodToWorkloadEndpoint requires a Pods Name and Node Name to be populated. It will
// fail to convert from a Pod to WorkloadEndpoint otherwise.
func (wc defaultWorkloadEndpointConverter) podToDefaultWorkloadEndpoint(pod *kapiv1.Pod) (*model.KVPair, error) {
	log.WithField("pod", pod).Debug("Converting pod to WorkloadEndpoint")
	// Get all the profiles that apply
	var profiles []string

	// Pull out the Namespace based profile off the pod name and Namespace.
	profiles = append(profiles, NamespaceProfileNamePrefix+pod.Namespace)

	// Pull out the Serviceaccount based profile off the pod SA and namespace
	if pod.Spec.ServiceAccountName != "" {
		profiles = append(profiles, serviceAccountNameToProfileName(pod.Spec.ServiceAccountName, pod.Namespace))
	}

	wepids := names.WorkloadEndpointIdentifiers{
		Node:         pod.Spec.NodeName,
		Orchestrator: apiv3.OrchestratorKubernetes,
		Endpoint:     "eth0",
		Pod:          pod.Name,
	}
	wepName, err := wepids.CalculateWorkloadEndpointName(false)
	if err != nil {
		return nil, err
	}

	podIPNets, err := getPodIPs(pod)
	if err != nil {
		// IP address was present but malformed in some way, handle as an explicit failure.
		return nil, err
	}

	if IsFinished(pod) {
		// Pod is finished but not yet deleted.  In this state the IP will have been freed and returned to the pool
		// so we need to make sure we don't let the caller believe it still belongs to this endpoint.
		// Pods with no IPs will get filtered out before they get to Felix in the watcher syncer cache layer.
		// We can't pretend the workload endpoint is deleted _here_ because that would confuse users of the
		// native v3 Watch() API.
		log.Debug("Pod is in a 'finished' state so no longer owns its IP(s).")
		podIPNets = nil
	}

	ipNets := []string{}
	for _, ipNet := range podIPNets {
		ipNets = append(ipNets, ipNet.String())
	}

	// Generate the interface name based on workload.  This must match
	// the host-side veth configured by the CNI plugin.
	interfaceName := wc.VethNameForWorkload(pod.Namespace, pod.Name)

	// Build the labels map.  Start with the pod labels, and append two additional labels for
	// namespace and orchestrator matches.
	labels := make(map[string]string)
	for k, v := range pod.Labels {
		labels[k] = v
	}
	labels[apiv3.LabelNamespace] = pod.Namespace
	labels[apiv3.LabelOrchestrator] = apiv3.OrchestratorKubernetes

	if pod.Spec.ServiceAccountName != "" && len(pod.Spec.ServiceAccountName) < 63 {
		// For backwards compatibility, include the label if less than 63 characters.
		labels[apiv3.LabelServiceAccount] = pod.Spec.ServiceAccountName
	}

	// Pull out floating IP annotation
	var floatingIPs []libapiv3.IPNAT
	if annotation, ok := pod.Annotations["cni.projectcalico.org/floatingIPs"]; ok && len(podIPNets) > 0 {
		// Parse Annotation data
		var ips []string
		err := json.Unmarshal([]byte(annotation), &ips)
		if err != nil {
			return nil, fmt.Errorf("failed to parse '%s' as JSON: %s", annotation, err)
		}

		// Get IPv4 and IPv6 targets for NAT
		var podnetV4, podnetV6 *cnet.IPNet
		for _, ipNet := range podIPNets {
			if ipNet.IP.To4() != nil {
				podnetV4 = ipNet
				netmask, _ := podnetV4.Mask.Size()
				if netmask != 32 {
					return nil, fmt.Errorf("PodIP %v is not a valid IPv4: Mask size is %d, not 32", ipNet, netmask)
				}
			} else {
				podnetV6 = ipNet
				netmask, _ := podnetV6.Mask.Size()
				if netmask != 128 {
					return nil, fmt.Errorf("PodIP %v is not a valid IPv6: Mask size is %d, not 128", ipNet, netmask)
				}
			}
		}

		for _, ip := range ips {
			if strings.Contains(ip, ":") {
				if podnetV6 != nil {
					floatingIPs = append(floatingIPs, libapiv3.IPNAT{
						InternalIP: podnetV6.IP.String(),
						ExternalIP: ip,
					})
				}
			} else {
				if podnetV4 != nil {
					floatingIPs = append(floatingIPs, libapiv3.IPNAT{
						InternalIP: podnetV4.IP.String(),
						ExternalIP: ip,
					})
				}
			}
		}
	}

	// Handle source IP spoofing annotation
	sourcePrefixes, err := HandleSourceIPSpoofingAnnotation(pod.Annotations)
	if err != nil {
		return nil, err
	}

	// Map any named ports through.
	var endpointPorts []libapiv3.WorkloadEndpointPort
	endpointPorts = appendEndpointPorts(endpointPorts, pod, pod.Spec.Containers)
	endpointPorts = appendEndpointPorts(endpointPorts, pod, pod.Spec.InitContainers)

	// Get the container ID if present.  This is used in the CNI plugin to distinguish different pods that have
	// the same name.  For example, restarted stateful set pods.
	containerID := pod.Annotations[AnnotationContainerID]

	qosControls, err := handleQoSControlsAnnotations(pod.Annotations)
	if err != nil {
		// If QoSControls can't be parsed, log the error but keep processing the workload
		log.WithField("pod", pod).WithError(err).Warn("Error parsing QoSControl annotations")
	}

	// Create the workload endpoint.
	wep := libapiv3.NewWorkloadEndpoint()
	wep.ObjectMeta = metav1.ObjectMeta{
		Name:              wepName,
		Namespace:         pod.Namespace,
		CreationTimestamp: pod.CreationTimestamp,
		UID:               pod.UID,
		Labels:            labels,
		GenerateName:      pod.GenerateName,
	}
	wep.Spec = libapiv3.WorkloadEndpointSpec{
		Orchestrator:               "k8s",
		Node:                       pod.Spec.NodeName,
		Pod:                        pod.Name,
		ContainerID:                containerID,
		Endpoint:                   "eth0",
		InterfaceName:              interfaceName,
		Profiles:                   profiles,
		IPNetworks:                 ipNets,
		Ports:                      endpointPorts,
		IPNATs:                     floatingIPs,
		ServiceAccountName:         pod.Spec.ServiceAccountName,
		AllowSpoofedSourcePrefixes: sourcePrefixes,
		QoSControls:                qosControls,
	}

	if v, ok := pod.Annotations["k8s.v1.cni.cncf.io/network-status"]; ok {
		if wep.Annotations == nil {
			wep.Annotations = make(map[string]string)
		}
		wep.Annotations["k8s.v1.cni.cncf.io/network-status"] = v
	}

	// Embed the workload endpoint into a KVPair.
	kvp := model.KVPair{
		Key: model.ResourceKey{
			Name:      wepName,
			Namespace: pod.Namespace,
			Kind:      libapiv3.KindWorkloadEndpoint,
		},
		Value:    wep,
		Revision: pod.ResourceVersion,
	}
	return &kvp, nil
}

func appendEndpointPorts(ports []libapiv3.WorkloadEndpointPort, pod *kapiv1.Pod, containers []kapiv1.Container) []libapiv3.WorkloadEndpointPort {
	for _, container := range containers {
		for _, containerPort := range container.Ports {
			if containerPort.ContainerPort != 0 && (containerPort.HostPort != 0 || containerPort.Name != "") {
				var modelProto numorstring.Protocol
				switch containerPort.Protocol {
				case kapiv1.ProtocolUDP:
					modelProto = numorstring.ProtocolFromString("udp")
				case kapiv1.ProtocolSCTP:
					modelProto = numorstring.ProtocolFromString("sctp")
				case kapiv1.ProtocolTCP, kapiv1.Protocol("") /* K8s default is TCP. */ :
					modelProto = numorstring.ProtocolFromString("tcp")
				default:
					log.WithFields(log.Fields{
						"protocol": containerPort.Protocol,
						"pod":      pod,
						"port":     containerPort,
					}).Debug("Ignoring named port with unknown protocol")
					continue
				}

				ports = append(ports, libapiv3.WorkloadEndpointPort{
					Name:     containerPort.Name,
					Protocol: modelProto,
					Port:     uint16(containerPort.ContainerPort),
					HostPort: uint16(containerPort.HostPort),
					HostIP:   containerPort.HostIP,
				})
			}
		}
	}
	return ports
}

// HandleSourceIPSpoofingAnnotation parses the allowedSourcePrefixes annotation if present,
// and returns the allowed prefixes as a slice of strings.
func HandleSourceIPSpoofingAnnotation(annot map[string]string) ([]string, error) {
	var sourcePrefixes []string
	if annotation, ok := annot["cni.projectcalico.org/allowedSourcePrefixes"]; ok && annotation != "" {
		// Parse Annotation data
		var requestedSourcePrefixes []string
		err := json.Unmarshal([]byte(annotation), &requestedSourcePrefixes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse '%s' as JSON: %s", annotation, err)
		}

		// Filter out any invalid entries and normalize the CIDRs.
		for _, prefix := range requestedSourcePrefixes {
			if _, n, err := cnet.ParseCIDR(prefix); err != nil {
				return nil, fmt.Errorf("failed to parse '%s' as a CIDR: %s", prefix, err)
			} else {
				sourcePrefixes = append(sourcePrefixes, n.String())
			}
		}
	}
	return sourcePrefixes, nil
}

func handleQoSControlsAnnotations(annotations map[string]string) (*libapiv3.QoSControls, error) {
	qosControls := &libapiv3.QoSControls{}
	var errs []error

	// k8s bandwidth annotations
	if str, found := annotations[AnnotationK8sQoSIngressBandwidth]; found {
		ingressBandwidth, err := parseAndValidateQty(str, minBandwidth, maxBandwidth)
		if err != nil {
			errs = append(errs, fmt.Errorf("error parsing ingress bandwidth annotation: %w", err))
		}
		qosControls.IngressBandwidth = ingressBandwidth
	}
	if str, found := annotations[AnnotationK8sQoSEgressBandwidth]; found {
		egressBandwidth, err := parseAndValidateQty(str, minBandwidth, maxBandwidth)
		if err != nil {
			errs = append(errs, fmt.Errorf("error parsing egress bandwidth annotation: %w", err))
		}
		qosControls.EgressBandwidth = egressBandwidth
	}

	// calico bandwidth annotations (override k8s annotations if present)
	if str, found := annotations[AnnotationQoSIngressBandwidth]; found {
		ingressBandwidth, err := parseAndValidateQty(str, minBandwidth, maxBandwidth)
		if err != nil {
			errs = append(errs, fmt.Errorf("error parsing ingress bandwidth annotation: %w", err))
		}
		qosControls.IngressBandwidth = ingressBandwidth
	}
	if str, found := annotations[AnnotationQoSEgressBandwidth]; found {
		egressBandwidth, err := parseAndValidateQty(str, minBandwidth, maxBandwidth)
		if err != nil {
			errs = append(errs, fmt.Errorf("error parsing egress bandwidth annotation: %w", err))
		}
		qosControls.EgressBandwidth = egressBandwidth
	}

	// calico burst annotations
	if str, found := annotations[AnnotationQoSIngressBurst]; found {
		ingressBurst, err := parseAndValidateQty(str, minBurst, maxBurst)
		if err != nil {
			errs = append(errs, fmt.Errorf("error parsing ingress burst annotation: %w", err))
		}
		qosControls.IngressBurst = ingressBurst
	}
	if str, found := annotations[AnnotationQoSEgressBurst]; found {
		egressBurst, err := parseAndValidateQty(str, minBurst, maxBurst)
		if err != nil {
			errs = append(errs, fmt.Errorf("error parsing egress burst annotation: %w", err))
		}
		qosControls.EgressBurst = egressBurst
	}

	// calico peakrate annotations
	if str, found := annotations[AnnotationQoSIngressPeakrate]; found {
		ingressPeakrate, err := parseAndValidateQty(str, minPeakrate, maxPeakrate)
		if err != nil {
			errs = append(errs, fmt.Errorf("error parsing ingress peakrate annotation: %w", err))
		}
		qosControls.IngressPeakrate = ingressPeakrate
	}
	if str, found := annotations[AnnotationQoSEgressPeakrate]; found {
		egressPeakrate, err := parseAndValidateQty(str, minPeakrate, maxPeakrate)
		if err != nil {
			errs = append(errs, fmt.Errorf("error parsing egress peakrate annotation: %w", err))
		}
		qosControls.EgressPeakrate = egressPeakrate
	}

	// calico minburst/mtu annotations
	if str, found := annotations[AnnotationQoSIngressMinburst]; found {
		ingressMinburst, err := parseAndValidateQty(str, minMinburst, maxMinburst)
		if err != nil {
			errs = append(errs, fmt.Errorf("error parsing ingress minburst annotation: %w", err))
		}
		qosControls.IngressMinburst = ingressMinburst
	}
	if str, found := annotations[AnnotationQoSEgressMinburst]; found {
		egressMinburst, err := parseAndValidateQty(str, minMinburst, maxMinburst)
		if err != nil {
			errs = append(errs, fmt.Errorf("error parsing egress minburst annotation: %w", err))
		}
		qosControls.EgressMinburst = egressMinburst
	}

	// calico packet rate annotations
	if str, found := annotations[AnnotationQoSIngressPacketRate]; found {
		ingressPacketRate, err := parseAndValidateQty(str, minPacketRate, maxPacketRate)
		if err != nil {
			errs = append(errs, fmt.Errorf("error parsing ingress packet rate annotation: %w", err))
		}
		qosControls.IngressPacketRate = ingressPacketRate
	}
	if str, found := annotations[AnnotationQoSEgressPacketRate]; found {
		egressPacketRate, err := parseAndValidateQty(str, minPacketRate, maxPacketRate)
		if err != nil {
			errs = append(errs, fmt.Errorf("error parsing egress packet rate annotation: %w", err))
		}
		qosControls.EgressPacketRate = egressPacketRate
	}

	// calico packet burst annotations
	if str, found := annotations[AnnotationQoSIngressPacketBurst]; found {
		ingressPacketBurst, err := parseAndValidateQty(str, minPacketBurst, maxPacketBurst)
		if err != nil {
			errs = append(errs, fmt.Errorf("error parsing ingress packet rate annotation: %w", err))
		}
		qosControls.IngressPacketBurst = ingressPacketBurst
	}
	if str, found := annotations[AnnotationQoSEgressPacketBurst]; found {
		egressPacketBurst, err := parseAndValidateQty(str, minPacketBurst, maxPacketBurst)
		if err != nil {
			errs = append(errs, fmt.Errorf("error parsing egress packet rate annotation: %w", err))
		}
		qosControls.EgressPacketBurst = egressPacketBurst
	}

	// calico number of connections annotations
	if str, found := annotations[AnnotationQoSIngressMaxConnections]; found {
		ingressMaxConnections, err := parseAndValidateQty(str, minNumConnections, maxNumConnections)
		if err != nil {
			errs = append(errs, fmt.Errorf("error parsing ingress max connections annotation: %w", err))
		}
		qosControls.IngressMaxConnections = ingressMaxConnections
	}
	if str, found := annotations[AnnotationQoSEgressMaxConnections]; found {
		egressMaxConnections, err := parseAndValidateQty(str, minNumConnections, maxNumConnections)
		if err != nil {
			errs = append(errs, fmt.Errorf("error parsing egress max connections annotation: %w", err))
		}
		qosControls.EgressMaxConnections = egressMaxConnections
	}

	// if burst is configured, bandwidth must be configured
	if qosControls.IngressBurst != 0 && qosControls.IngressBandwidth == 0 {
		errs = append(errs, fmt.Errorf("ingress bandwidth must be specified when ingress burst is specified"))
		qosControls.IngressBurst = 0
	}
	if qosControls.EgressBurst != 0 && qosControls.EgressBandwidth == 0 {
		errs = append(errs, fmt.Errorf("egress bandwidth must be specified when egress burst is specified"))
		qosControls.EgressBurst = 0
	}

	// if peakrate is configured, bandwidth must be configured and peakrate must be greater than bandwidth
	if qosControls.IngressPeakrate != 0 && (qosControls.IngressBandwidth == 0 || qosControls.IngressBandwidth >= qosControls.IngressPeakrate) {
		errs = append(errs, fmt.Errorf("ingress peakrate must be greater than ingress bandwidth when specified"))
		qosControls.IngressPeakrate = 0
	}
	if qosControls.EgressPeakrate != 0 && (qosControls.EgressBandwidth == 0 || qosControls.EgressBandwidth >= qosControls.EgressPeakrate) {
		errs = append(errs, fmt.Errorf("egress peakrate must be greater than egress bandwidth when specified"))
		qosControls.EgressPeakrate = 0
	}

	// if minburst is configured, peakrate must be configured
	if qosControls.IngressMinburst != 0 && qosControls.IngressPeakrate == 0 {
		errs = append(errs, fmt.Errorf("ingress peakrate must be specified when ingress minburst is specified"))
		qosControls.IngressMinburst = 0
	}
	if qosControls.EgressMinburst != 0 && qosControls.EgressPeakrate == 0 {
		errs = append(errs, fmt.Errorf("egress peakrate must be specified when egress minburst is specified"))
		qosControls.EgressMinburst = 0
	}

	// if packet burst is configured, packet rate must be configured
	if qosControls.IngressPacketBurst != 0 && qosControls.IngressPacketRate == 0 {
		errs = append(errs, fmt.Errorf("ingress packet rate must be specified when ingress packet burst is specified"))
		qosControls.IngressPacketBurst = 0
	}
	if qosControls.EgressPacketBurst != 0 && qosControls.EgressPacketRate == 0 {
		errs = append(errs, fmt.Errorf("egress packet rate must be specified when egress packet burst is specified"))
		qosControls.EgressPacketBurst = 0
	}

	// default burst values if bandwidth is configured
	if qosControls.IngressBandwidth != 0 && qosControls.IngressBurst == 0 {
		qosControls.IngressBurst = defaultBurst.Value()
	}
	if qosControls.EgressBandwidth != 0 && qosControls.EgressBurst == 0 {
		qosControls.EgressBurst = defaultBurst.Value()
	}

	// default minburst values are configured in felix/dataplane/linux/qos/qos.go because they depend on the interface MTU

	// default packet burst values if packet rate is configured
	if qosControls.IngressPacketRate != 0 && qosControls.IngressPacketBurst == 0 {
		qosControls.IngressPacketBurst = defaultPacketBurst.Value()
	}
	if qosControls.EgressPacketRate != 0 && qosControls.EgressPacketBurst == 0 {
		qosControls.EgressPacketBurst = defaultPacketBurst.Value()
	}

	// Calico DSCP value for egress traffic annotation.
	if str, found := annotations[AnnotationQoSEgressDSCP]; found {
		dscp := numorstring.DSCPFromString(str)
		err := dscp.Validate()
		if err != nil {
			errs = append(errs, fmt.Errorf("error parsing DSCP annotation: %w", err))
		} else {
			qosControls.DSCP = &dscp
		}
	}

	// return nil if no control is configured
	if (*qosControls == libapiv3.QoSControls{}) {
		qosControls = nil
	}

	return qosControls, errors.Join(errs...)
}

func parseAndValidateQty(str string, minQty, maxQty resource.Quantity) (int64, error) {
	qty, err := resource.ParseQuantity(str)
	if err != nil {
		return 0, err
	}

	if qty.Value() < minQty.Value() {
		return minQty.Value(), fmt.Errorf("resource specified is too small (less than %v), setting it to %v", minQty, minQty)
	}
	if qty.Value() > maxQty.Value() {
		return maxQty.Value(), fmt.Errorf("resource specified is too large (more than %v), setting it to %v", maxQty, maxQty)
	}

	return qty.Value(), nil
}
