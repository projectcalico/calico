// Copyright (c) 2017-2025 Tigera, Inc. All rights reserved.

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
	"encoding/json"

	log "github.com/sirupsen/logrus"
)

const (
	NamespaceLabelPrefix            = "pcns."
	NamespaceProfileNamePrefix      = "kns."
	ServiceAccountLabelPrefix       = "pcsa."
	ServiceAccountProfileNamePrefix = "ksa."

	// AnnotationPodIP is an annotation we apply to pods when assigning them an IP.  It
	// duplicates the value of the Pod.Status.PodIP field, which is set by kubelet but,
	// since we write it ourselves, we can make sure that it is written synchronously
	// and quickly.
	//
	// We set this annotation to the empty string when the WEP is deleted by the CNI plugin.
	// That signals that the IP no longer belongs to this pod.
	AnnotationPodIP = "cni.projectcalico.org/podIP"

	// AnnotationPodIPs is similar for the plural PodIPs field.
	AnnotationPodIPs = "cni.projectcalico.org/podIPs"

	// AnnotationPodIPs is the annotation set by the Amazon VPC CNI plugin.
	AnnotationAWSPodIPs = "vpc.amazonaws.com/pod-ips"

	// AnnotationContainerID stores the container ID of the pod.  This allows us to disambiguate different pods
	// that have the same name and namespace.  For example, stateful set pod that is restarted.  May be missing
	// on older Pods.
	AnnotationContainerID = "cni.projectcalico.org/containerID"

	// AnnotationPodNetns stores the path of the pod's network namespace.
	AnnotationPodNetns = "cni.projectcalico.org/podNetns"

	// AnnotationNetworkStatus is the annotation key for the primary pod interface
	// (eth0 or empty) that records the interface's status.  The value is a JSON
	// object (see NetworkStatus).
	//
	// Example:  cni.projectcalico.org/network-status: {"netns":"/run/netns/cni-1234"}
	AnnotationNetworkStatus = "cni.projectcalico.org/network-status"

	// AnnotationNetworkStatusPrefix is the prefix of the per-interface
	// network-status annotation for non-primary pod interfaces.  The full key
	// is AnnotationNetworkStatusPrefix + <iface> + AnnotationNetworkStatusSuffix.
	//
	// Example:  cni.projectcalico.org/net1.network-status: {"netns":"/run/netns/cni-1234"}
	AnnotationNetworkStatusPrefix = "cni.projectcalico.org/"
	AnnotationNetworkStatusSuffix = ".network-status"

	// DefaultPodInterface is the in-pod interface name used by the primary
	// (Calico) CNI; per-interface helpers treat this name specially so the
	// annotation has no suffix.
	DefaultPodInterface = "eth0"

	// NameLabel is a label that can be used to match a serviceaccount or namespace
	// name exactly.
	NameLabel = "projectcalico.org/name"

	// AdminPolicyRuleNameLabel is a label that show a rule's name before conversion to Calico data model.
	// As an example, it holds an admin network policy rule name before conversion to GNPs.
	K8sCNPRuleNameLabel = "name"

	// QoSControls related annotations
	AnnotationK8sQoSIngressBandwidth   = "kubernetes.io/ingress-bandwidth"
	AnnotationK8sQoSEgressBandwidth    = "kubernetes.io/egress-bandwidth"
	AnnotationQoSIngressBandwidth      = "qos.projectcalico.org/ingressBandwidth"
	AnnotationQoSEgressBandwidth       = "qos.projectcalico.org/egressBandwidth"
	AnnotationQoSIngressBurst          = "qos.projectcalico.org/ingressBurst"
	AnnotationQoSEgressBurst           = "qos.projectcalico.org/egressBurst"
	AnnotationQoSIngressPeakrate       = "qos.projectcalico.org/ingressPeakrate"
	AnnotationQoSEgressPeakrate        = "qos.projectcalico.org/egressPeakrate"
	AnnotationQoSIngressMinburst       = "qos.projectcalico.org/ingressMinburst"
	AnnotationQoSEgressMinburst        = "qos.projectcalico.org/egressMinburst"
	AnnotationQoSIngressPacketRate     = "qos.projectcalico.org/ingressPacketRate"
	AnnotationQoSEgressPacketRate      = "qos.projectcalico.org/egressPacketRate"
	AnnotationQoSIngressPacketBurst    = "qos.projectcalico.org/ingressPacketBurst"
	AnnotationQoSEgressPacketBurst     = "qos.projectcalico.org/egressPacketBurst"
	AnnotationQoSIngressMaxConnections = "qos.projectcalico.org/ingressMaxConnections"
	AnnotationQoSEgressMaxConnections  = "qos.projectcalico.org/egressMaxConnections"
	AnnotationQoSEgressDSCP            = "qos.projectcalico.org/dscp"
)

// AnnotationNetworkStatusForIface returns the per-interface network-status
// annotation key for the given in-pod interface name.  The primary interface
// (empty or eth0) uses AnnotationNetworkStatus directly; non-primary
// interfaces use a per-iface suffix form
// (cni.projectcalico.org/<iface>.network-status).
func AnnotationNetworkStatusForIface(iface string) string {
	if iface == "" || iface == DefaultPodInterface {
		return AnnotationNetworkStatus
	}
	return AnnotationNetworkStatusPrefix + iface + AnnotationNetworkStatusSuffix
}

// NetworkStatus is the decoded value of the per-interface network-status
// annotation that the Calico CNI plugin writes to pods.
type NetworkStatus struct {
	// Netns is the path of the pod's network namespace, as seen by the CNI
	// plugin in the host mount namespace.
	Netns string `json:"netns,omitempty"`
}

// MarshalInterfaceStatus encodes a NetworkStatus into the JSON form written to
// the per-interface annotation.  Returns "" when there is nothing to record so
// callers can skip writing an empty annotation.
func MarshalInterfaceStatus(s NetworkStatus) (string, error) {
	if s.Netns == "" {
		return "", nil
	}
	b, err := json.Marshal(&s)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// InterfaceStatusFromAnnotation returns the parsed NetworkStatus recorded for
// the given in-pod interface, or a zero value if the annotation is missing or
// malformed.
func InterfaceStatusFromAnnotation(annotations map[string]string, iface string) NetworkStatus {
	v, ok := annotations[AnnotationNetworkStatusForIface(iface)]
	if !ok || v == "" {
		return NetworkStatus{}
	}
	var ns NetworkStatus
	if err := json.Unmarshal([]byte(v), &ns); err != nil {
		log.WithError(err).WithFields(log.Fields{
			"iface":      iface,
			"annotation": v,
		}).Warn("Failed to parse network-status annotation")
		return NetworkStatus{}
	}
	return ns
}
