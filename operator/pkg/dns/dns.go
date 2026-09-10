// Copyright (c) 2020-2026 Tigera, Inc. All rights reserved.

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

package dns

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"regexp"
)

const (
	// Default location for the resolv.conf file.
	DefaultResolveConfPath = "/etc/resolv.conf"

	// Default cluster domain value for k8s clusters.
	DefaultClusterDomain = "cluster.local"
)

// GetClusterDomain parses the path to resolv.conf to find the cluster domain.
func GetClusterDomain(resolvConfPath string) (string, error) {
	var clusterDomain string
	file, err := os.Open(resolvConfPath)
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()

	reg := regexp.MustCompile(`^search.*?\ssvc\.([^\s]*)`)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		match := reg.FindStringSubmatch(scanner.Text())
		if len(match) > 0 {
			clusterDomain = match[1]
		}
	}

	if err := scanner.Err(); err != nil {
		return "", err
	}

	if clusterDomain == "" {
		return "", fmt.Errorf("failed to find cluster domain in resolv.conf")
	}

	return clusterDomain, nil
}

// IsDomainName checks if the given name is a domain name and returns true if it is.
func IsDomainName(name string) bool {
	// Attempt to parse it as an IP.
	return net.ParseIP(name) == nil
}

// GetServiceDNSNames returns a list of a service's DNS names.
// We return:
// - <svc_name>
// - <svc_name>.<ns>
// - <svc_name>.<ns>.svc
// - <svc_name>.<ns>.svc.<cluster-domain>
func GetServiceDNSNames(name, namespace, clusterDomain string) []string {
	domains := []string{
		name,
		fmt.Sprintf("%s.%s", name, namespace),
		fmt.Sprintf("%s.%s.svc", name, namespace),
	}

	// If the cluster domain isn't set, this becomes an invalid DNS name since it would end in a dot. So only add it if it's set.
	if clusterDomain != "" {
		domains = append(domains, fmt.Sprintf("%s.%s.svc.%s", name, namespace, clusterDomain))
	}
	return domains
}
