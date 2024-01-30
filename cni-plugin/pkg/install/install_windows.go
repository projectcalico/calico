//go:build windows

// Copyright (c) 2020 Tigera, Inc. All rights reserved.
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

package install

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/winutils"
)

func defaultNetConf() string {
	netconf := `{
  "name": "Calico",
  "cniVersion": "0.3.1",
  "plugins": [
    {
      "type": "calico",
      "name": "Calico",
      "windows_use_single_network": true,
      "mode": "__MODE__",
      "vxlan_mac_prefix":  "__MAC_PREFIX__",
      "vxlan_vni": __VNI__,
      "mtu": __CNI_MTU__,
      "policy": {
        "type": "k8s"
      },
      "log_level": "__LOG_LEVEL__",
      "log_file_path": "__LOG_FILE_PATH__",
      "windows_loopback_DSR": "__DSR_SUPPORT__",
      "capabilities": {"dns": true},
      "DNS":  {
        "Nameservers":  [__KUBERNETES_DNS_SERVERS__],
        "Search":  [
          "svc.cluster.local"
        ]
      },
      "nodename": "__KUBERNETES_NODE_NAME__",
      "nodename_file": "__NODENAME_FILE__",
      "nodename_file_optional": true,
      "datastore_type": "__DATASTORE_TYPE__",

      "etcd_endpoints": "__ETCD_ENDPOINTS__",
      "etcd_key_file": "__ETCD_KEY_FILE__",
      "etcd_cert_file": "__ETCD_CERT_FILE__",
      "etcd_ca_cert_file": "__ETCD_CA_CERT_FILE__",

      "kubernetes": {
        "kubeconfig": "__KUBECONFIG_FILEPATH__"
      },
      "ipam": {
        "type": "__IPAM_TYPE__",
        "subnet": "usePodCidr"
      },

      "policies":  [
        {
          "Name":  "EndpointPolicy",
          "Value":  {
            "Type":  "OutBoundNAT",
            "ExceptionList":  [__KUBERNETES_SERVICE_CIDRS__]
          }
        },
__KUBERNETES_ROUTE_POLICIES__
      ]
    }
  ]
}`
	return netconf
}

// Perform replacement of windows variables
func replacePlatformSpecificVars(c config, netconf string) string {
	cniNetDir := c.CNINetDir
	if !(strings.HasPrefix(cniNetDir, "c:") || strings.HasPrefix(cniNetDir, "C:")) {
		cniNetDir = filepath.Join("c:", cniNetDir)
	}
	kubeconfigPath := filepath.Join(cniNetDir, "/calico-kubeconfig")
	kubeconfigPath = filepath.ToSlash(kubeconfigPath)
	netconf = strings.Replace(netconf, "__KUBECONFIG_FILEPATH__", kubeconfigPath, -1)

	netconf = strings.Replace(netconf, "__LOG_FILE_PATH__", getEnv("LOG_FILE_PATH", "c:/var/log/calico/cni/cni.log"), -1)

	// Support multiple KUBERNETES_SERVICE_CIDRS
	serviceCIDRIPs := getEnv("KUBERNETES_SERVICE_CIDRS", "10.96.0.10")
	serviceCIDRIPList := []string{}
	for _, ip := range strings.Split(serviceCIDRIPs, ",") {
		serviceCIDRIPList = append(serviceCIDRIPList, fmt.Sprintf("\"%s\"", strings.TrimSpace(ip)))
	}
	quotedServiceCIDRIPs := strings.Join(serviceCIDRIPList, ",")
	netconf = strings.Replace(netconf, "__KUBERNETES_SERVICE_CIDRS__", quotedServiceCIDRIPs, -1)

	routePolicyList := []string{}
	for _, ip := range serviceCIDRIPList {
		routePolicy := fmt.Sprintf(`        {
          "Name":  "EndpointPolicy",
          "Value":  {
            "Type":  "__ROUTE_TYPE__",
            "DestinationPrefix":  %s,
            "NeedEncap":  true
          }
        }`, ip)
		routePolicyList = append(routePolicyList, routePolicy)
	}
	routePolicyListStr := strings.Join(routePolicyList, ",\n")
	netconf = strings.Replace(netconf, "__KUBERNETES_ROUTE_POLICIES__", routePolicyListStr, -1)

	// __ROUTE_TYPE__ substitution must be done after __KUBERNETES_ROUTE_POLICIES__ because the latter contains the former.
	netconf = strings.Replace(netconf, "__ROUTE_TYPE__", getEnv("ROUTE_TYPE", "SDNROUTE"), -1)

	netconf = strings.Replace(netconf, "__VNI__", getEnv("VXLAN_VNI", "4096"), -1)
	netconf = strings.Replace(netconf, "__MAC_PREFIX__", getEnv("MAC_PREFIX", "0E-2A"), -1)

	netconf = strings.Replace(netconf, "__NODENAME_FILE__", getEnv("CALICO_NODENAME_FILE", "c:/var/run/calico/nodename"), -1)

	dnsIPs := getEnv("KUBERNETES_DNS_SERVERS", "10.96.0.10")
	dnsIPList := []string{}
	for _, ip := range strings.Split(dnsIPs, ",") {
		dnsIPList = append(dnsIPList, fmt.Sprintf("\"%s\"", strings.TrimSpace(ip)))
	}
	quotedDNSIPs := strings.Join(dnsIPList, ",")
	netconf = strings.Replace(netconf, "__KUBERNETES_DNS_SERVERS__", quotedDNSIPs, -1)

	backend := getEnv("CALICO_NETWORKING_BACKEND", "vxlan")
	if strings.ToLower(backend) == "bird" || strings.ToLower(backend) == "bgp" {
		backend = "windows-bgp"
	}
	netconf = strings.Replace(netconf, "__MODE__", backend, -1)

	ipamType := getEnv("CNI_IPAM_TYPE", "calico-ipam")
	if backend == "vxlan" && ipamType != "calico-ipam" {
		logrus.Fatalf("Calico VXLAN requires IPAM type calico-ipam, not %s", ipamType)

	}
	netconf = strings.Replace(netconf, "__IPAM_TYPE__", ipamType, -1)

	// Get Windows version information via powershell to determine whether DSR is supported.
	// Retry for 10 attempts in case any step fails.
	var stdout, stderr string
	var err error
	var winVerInt, buildNumInt, halVerInt int
	for attempts := 10; attempts > 0; attempts-- {
		stdout, stderr, err = winutils.Powershell("Get-ComputerInfo | select WindowsVersion, OsBuildNumber, OsHardwareAbstractionLayer")
		logger := logrus.WithFields(logrus.Fields{"stderr": stderr, "stdout": stdout})
		if err != nil {
			logger.WithError(err).Warn("Failed to interact with powershell. May retry...")
			time.Sleep(1 * time.Second)
			continue
		}
		lines := strings.Split(stdout, "\r\n")
		if len(lines) < 4 {
			logger.WithError(err).Warn("Could not parse output from powershell command. May retry...")
			time.Sleep(1 * time.Second)
			continue
		}
		line := lines[3]
		fields := strings.Fields(line)
		if len(fields) < 3 {
			logger.WithError(err).WithField("line", line).Warn("Could not parse fields from powershell command output line. May retry...")
			time.Sleep(1 * time.Second)
			continue
		}
		winVer := fields[0]
		winVerInt, err = strconv.Atoi(winVer)
		if err != nil {
			logger.WithError(err).WithField("winVer", winVer).Warn("Error converting winVer to int. May retry...")
			time.Sleep(1 * time.Second)
			continue
		}
		buildNum := fields[1]
		buildNumInt, err = strconv.Atoi(buildNum)
		if err != nil {
			logger.WithError(err).WithField("buildNum", buildNum).Warn("Error converting buildNum to int. May retry...")
			time.Sleep(1 * time.Second)
			continue
		}
		hal := fields[2]
		halVer := strings.Split(hal, ".")[3]
		halVerInt, err = strconv.Atoi(halVer)
		if err != nil {
			logger.WithError(err).WithField("halVer", halVer).Warn("Error converting halVer to int. May retry...")
			time.Sleep(1 * time.Second)
			continue
		}
		break
	}
	if err != nil {
		logrus.WithError(err).Fatal("Failed to retrieve Windows version information to determine DSR support.")
	}

	supportsDSR := (winVerInt == 1809 && buildNumInt >= 17763 && halVerInt >= 1432) || (winVerInt >= 1903 && buildNumInt >= 18317)
	logrus.WithField("supportsDSR", supportsDSR).Info("Successfully determined whether DSR is supported.")
	// Remove the quotes when replacing with boolean values (the quotes are in so that the template is valid JSON even before replacing)
	if supportsDSR {
		netconf = strings.Replace(netconf, `"__DSR_SUPPORT__"`, "true", -1)
	} else {
		netconf = strings.Replace(netconf, `"__DSR_SUPPORT__"`, "false", -1)
	}

	return netconf
}
