// Copyright (c) 2021 Tigera, Inc. All rights reserved.
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
package autodetection

import (
	"fmt"
	"net"
	"regexp"
	"strings"

	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"

	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/node/pkg/lifecycle/utils"
)

const (
	AUTODETECTION_METHOD_FIRST          = "first-found"
	AUTODETECTION_METHOD_CAN_REACH      = "can-reach="
	AUTODETECTION_METHOD_INTERFACE      = "interface="
	AUTODETECTION_METHOD_SKIP_INTERFACE = "skip-interface="
	AUTODETECTION_METHOD_CIDR           = "cidr="
	K8S_INTERNAL_IP                     = "kubernetes-internal-ip"
)

// autoDetectCIDR auto-detects the IP and Network using the requested
// detection method.
func AutoDetectCIDR(method string, version int, k8sNode *v1.Node, getInterfaces func([]string, []string, int) ([]Interface, error)) *cnet.IPNet {
	if method == "" || method == AUTODETECTION_METHOD_FIRST {
		// Autodetect the IP by enumerating all interfaces (excluding
		// known internal interfaces).
		return autoDetectCIDRFirstFound(version)
	} else if strings.HasPrefix(method, AUTODETECTION_METHOD_INTERFACE) {
		// Autodetect the IP from the specified interface.
		ifStr := strings.TrimPrefix(method, AUTODETECTION_METHOD_INTERFACE)
		// Regexes are passed in as a string separated by ","
		ifRegexes := regexp.MustCompile(`\s*,\s*`).Split(ifStr, -1)
		return autoDetectCIDRByInterface(ifRegexes, version)
	} else if strings.HasPrefix(method, AUTODETECTION_METHOD_CIDR) {
		// Autodetect the IP by filtering interface by its address.
		cidrStr := strings.TrimPrefix(method, AUTODETECTION_METHOD_CIDR)
		// CIDRs are passed in as a string separated by ","
		matches := []cnet.IPNet{}
		for _, r := range regexp.MustCompile(`\s*,\s*`).Split(cidrStr, -1) {
			_, cidr, err := cnet.ParseCIDR(r)
			if err != nil {
				log.Errorf("Invalid CIDR %q for IP autodetection method: %s", r, method)
				return nil
			}
			matches = append(matches, *cidr)
		}
		return autoDetectCIDRByCIDR(matches, version)
	} else if strings.HasPrefix(method, AUTODETECTION_METHOD_CAN_REACH) {
		// Autodetect the IP by connecting a UDP socket to a supplied address.
		destStr := strings.TrimPrefix(method, AUTODETECTION_METHOD_CAN_REACH)
		return autoDetectCIDRByReach(destStr, version)
	} else if strings.HasPrefix(method, AUTODETECTION_METHOD_SKIP_INTERFACE) {
		// Autodetect the Ip by enumerating all interfaces (excluding
		// known internal interfaces and any interfaces whose name
		// matches the given regexes).
		ifStr := strings.TrimPrefix(method, AUTODETECTION_METHOD_SKIP_INTERFACE)
		// Regexes are passed in as a string separated by ","
		ifRegexes := regexp.MustCompile(`\s*,\s*`).Split(ifStr, -1)
		return autoDetectCIDRBySkipInterface(ifRegexes, version)
	} else if strings.HasPrefix(method, K8S_INTERNAL_IP) {
		// K8s InternalIP configured for node is used
		if k8sNode == nil {
			log.Error("Cannot use method 'kubernetes-internal-ip' when not running on a Kubernetes cluster")
			return nil
		}
		return autoDetectUsingK8sInternalIP(version, k8sNode, getInterfaces)
	}

	// The autodetection method is not recognised and is required.  Exit.
	log.Errorf("Invalid IP autodetection method: %s", method)
	utils.Terminate()
	return nil
}

// autoDetectCIDRFirstFound auto-detects the first valid Network it finds across
// all interfaces (excluding common known internal interface names).
func autoDetectCIDRFirstFound(version int) *cnet.IPNet {
	incl := []string{}

	iface, cidr, err := FilteredEnumeration(incl, DEFAULT_INTERFACES_TO_EXCLUDE, nil, version)
	if err != nil {
		log.Warnf("Unable to auto-detect an IPv%d address: %s", version, err)
		return nil
	}

	log.Infof("Using autodetected IPv%d address on interface %s: %s", version, iface.Name, cidr.String())

	return cidr
}

// autoDetectCIDRByInterface auto-detects the first valid Network on the interfaces
// matching the supplied interface regex.
func autoDetectCIDRByInterface(ifaceRegexes []string, version int) *cnet.IPNet {
	iface, cidr, err := FilteredEnumeration(ifaceRegexes, nil, nil, version)
	if err != nil {
		log.Warnf("Unable to auto-detect an IPv%d address using interface regexes %v: %s", version, ifaceRegexes, err)
		return nil
	}

	log.Infof("Using autodetected IPv%d address %s on matching interface %s", version, cidr.String(), iface.Name)

	return cidr
}

// autoDetectCIDRByCIDR auto-detects the first valid Network on the interfaces
// matching the supplied cidr.
func autoDetectCIDRByCIDR(matches []cnet.IPNet, version int) *cnet.IPNet {
	iface, cidr, err := FilteredEnumeration(nil, nil, matches, version)
	if err != nil {
		log.Warnf("Unable to auto-detect an IPv%d address using interface cidr %s: %s", version, matches, err)
		return nil
	}

	log.Infof("Using autodetected IPv%d address %s on interface %s matching cidrs %+v", version, cidr.String(), iface.Name, matches)

	return cidr
}

// autoDetectCIDRByReach auto-detects the IP and Network by setting up a UDP
// connection to a "reach" address.
func autoDetectCIDRByReach(dest string, version int) *cnet.IPNet {
	if cidr, err := ReachDestination(dest, version); err != nil {
		log.Warnf("Unable to auto-detect IPv%d address by connecting to %s: %s", version, dest, err)
		return nil
	} else {
		log.Infof("Using autodetected IPv%d address %s, detected by connecting to %s", version, cidr.String(), dest)
		return cidr
	}
}

// autoDetectCIDRBySkipInterface auto-detects the first valid Network on the interfaces
// matching the supplied interface regexes.
func autoDetectCIDRBySkipInterface(ifaceRegexes []string, version int) *cnet.IPNet {
	incl := []string{}
	excl := DEFAULT_INTERFACES_TO_EXCLUDE
	excl = append(excl, ifaceRegexes...)

	iface, cidr, err := FilteredEnumeration(incl, excl, nil, version)
	if err != nil {
		log.Warnf("Unable to auto-detect an IPv%d address while excluding %v: %s", version, ifaceRegexes, err)
		return nil
	}

	log.Infof("Using autodetected IPv%d address on interface %s: %s while skipping matching interfaces", version, iface.Name, cidr.String())
	return cidr
}

// autoDetectUsingK8sInternalIP reads K8s Node InternalIP.
func autoDetectUsingK8sInternalIP(version int, k8sNode *v1.Node, getInterfaces func([]string, []string, int) ([]Interface, error)) *cnet.IPNet {
	var address string
	var err error

	nodeAddresses := k8sNode.Status.Addresses
	for _, addr := range nodeAddresses {
		if addr.Type == v1.NodeInternalIP {
			if (version == 4 && utils.IsIPv4String(addr.Address)) || (version == 6 && utils.IsIPv6String(addr.Address)) {
				address, err = GetLocalCIDR(addr.Address, version, getInterfaces)
				if err != nil {
					return nil
				}
				break
			}
		}
	}

	ip, ipNet, err := cnet.ParseCIDR(address)
	if err != nil {
		log.Errorf("Unable to parse CIDR %v : %v", address, err)
		return nil
	}
	// ParseCIDR masks off the IP addr of the IPNet it returns eg. ParseCIDR("192.168.1.2/24" will return
	//"192.168.1.2, 192.168.1.0/24". Callers of this function (autoDetectUsingK8sInternalIP) expect the full IP address
	// to be preserved in the CIDR ie. we should return 192.168.1.2/24
	ipNet.IP = ip.IP
	return ipNet
}

// getLocalCIDR attempts to merge CIDR information from the host with the given IP address.
// If a CIDR is provided, then it is simply returned.
// If an IP is provided, it attempts to find the matching interface on the host to detect the appropriate prefix length.
// If no match is found, the IP will be returned unmodified.
func GetLocalCIDR(ip string, version int, getInterfaces func([]string, []string, int) ([]Interface, error)) (string, error) {
	if strings.Contains(ip, "/") {
		// Already a CIDR
		return ip, nil
	}

	var destCIDR net.IP
	if version == 4 {
		destCIDR = net.ParseIP(ip).To4()
	} else {
		destCIDR = net.ParseIP(ip).To16()
	}

	if destCIDR == nil {
		return ip, fmt.Errorf("%s is invalid.", ip)
	}

	// Get a full list of interface and IPs and find the CIDR matching the
	// found IP.
	interfaces, err := getInterfaces(nil, nil, version)
	if err != nil {
		return ip, err
	}

	log.Debugf("Auto-detecting IPv%d CIDR of %s", version, ip)
	for _, iface := range interfaces {
		log.WithField("Name", iface.Name).Debug("Checking interface")
		for _, cidr := range iface.Cidrs {
			log.WithField("CIDR", cidr.String()).Debug("Found")
			if cidr.IP.Equal(destCIDR) {
				log.WithField("CIDR", cidr.String()).Info("Including CIDR information from host interface.")
				return cidr.String(), nil
			}
		}
	}

	// Even if no CIDR is found, it doesn't think it needs to throw an exception
	log.Warnf("Unable to find matching host interface for IP %s", ip)
	return ip, nil
}
