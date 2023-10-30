// Copyright (c) 2023 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package winutils

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	log "github.com/sirupsen/logrus"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	certutil "k8s.io/client-go/util/cert"
)

func Powershell(args ...string) (string, string, error) {
	// Add default powershell to PATH
	path := os.Getenv("PATH")
	err := os.Setenv("PATH", path+";C:/Windows/System32/WindowsPowerShell/v1.0/")
	if err != nil {
		return "", "", err
	}

	ps, err := exec.LookPath("powershell.exe")
	if err != nil {
		return "", "", err
	}

	args = append([]string{"-NoProfile", "-NonInteractive"}, args...)
	cmd := exec.Command(ps, args...)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	if err != nil {
		return "", "", err
	}

	return stdout.String(), stderr.String(), err
}

// InHostProcessContainer returns true if inside a Windows HostProcess container, by
// checking if OS is Windows and the $env:CONTAINER_SANDBOX_MOUNT_POINT env variable
// is set.
func InHostProcessContainer() bool {
	if runtime.GOOS == "windows" && os.Getenv("CONTAINER_SANDBOX_MOUNT_POINT") != "" {
		return true
	}
	return false
}

// GetHostPath returns the mount paths for a container
// In the case of Windows HostProcess containers this prepends the CONTAINER_SANDBOX_MOUNT_POINT env variable
// for other operating systems or if the sandbox env variable is not set it returns the standard mount points
// see https://kubernetes.io/docs/tasks/configure-pod-container/create-hostprocess-pod/#volume-mounts
// FIXME: this will no longer be needed when containerd v1.6 is EOL'd
func GetHostPath(path string) string {
	if InHostProcessContainer() {
		sandbox := os.Getenv("CONTAINER_SANDBOX_MOUNT_POINT")
		// Remove drive letter prefixs as the CONTAINER_SANDBOX_MOUNT_POINT env var will contain it
		path := strings.TrimPrefix(path, "c:")
		path = strings.TrimPrefix(path, "C:")
		// Remove literal unresolved CONTAINER_SANDBOX_MOUNT_POINT env var
		path = strings.TrimPrefix(path, "$env:CONTAINER_SANDBOX_MOUNT_POINT")
		// join them and return with forward slashes so it can be serialized properly in json later if required
		path = filepath.Join(sandbox, path)
		return filepath.ToSlash(path)
	}
	return path
}

// FIXME: get rid of this and call rest.InClusterConfig() directly when containerd v1.6 is EOL'd
// GetInClusterConfig returns a config object which uses the service account
// kubernetes gives to pods. It's intended for clients that expect to be
// running inside a pod running on kubernetes. It will return ErrNotInCluster
// if called from a process not running in a kubernetes environment.
// It is a copy of InClusterConfig() from k8s.io/client-go/rest but using
// winutils.GetHostPath() for the file paths, so that Windows hostprocess
// containers on containerd v1.6 can work with the in-cluster config.
func GetInClusterConfig() (*rest.Config, error) {
	tokenFile := GetHostPath("/var/run/secrets/kubernetes.io/serviceaccount/token")
	rootCAFile := GetHostPath("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if len(host) == 0 || len(port) == 0 {
		return nil, rest.ErrNotInCluster
	}

	token, err := os.ReadFile(tokenFile)
	if err != nil {
		return nil, err
	}

	tlsClientConfig := rest.TLSClientConfig{}

	if _, err := certutil.NewPool(rootCAFile); err != nil {
		log.Errorf("Expected to load root CA config from %s, but got err: %v", rootCAFile, err)
	} else {
		tlsClientConfig.CAFile = rootCAFile
	}

	return &rest.Config{
		Host:            "https://" + net.JoinHostPort(host, port),
		TLSClientConfig: tlsClientConfig,
		BearerToken:     string(token),
		BearerTokenFile: tokenFile,
	}, nil
}

// FIXME: get rid of this and call clientcmd.BuildConfigFromFlags() directly when containerd v1.6 is EOL'd
// BuildConfigFromFlags is a helper function that builds configs from a master
// url or a kubeconfig filepath. These are passed in as command line flags for cluster
// components. Warnings should reflect this usage. If neither masterUrl or kubeconfigPath
// are passed in we fallback to inClusterConfig. If inClusterConfig fails, we fallback
// to the default config.
// It is a copy of BuildConfigFromFlags() from k8s.io/client-go/tools/clientcmd but using
// GetInClusterConfig(), which uses winutils.GetHostPath() for the file paths, so that
// Windows hostprocess containers on containerd v1.6 can work with the in-cluster config.
func BuildConfigFromFlags(masterUrl, kubeconfigPath string) (*rest.Config, error) {
	if kubeconfigPath == "" && masterUrl == "" {
		log.Warning("Neither --kubeconfig nor --master was specified.  Using the inClusterConfig.  This might not work.")
		kubeconfig, err := GetInClusterConfig()
		if err == nil {
			return kubeconfig, nil
		}
		log.Warning("error creating inClusterConfig, falling back to default config: ", err)
	}
	return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		&clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfigPath},
		&clientcmd.ConfigOverrides{ClusterInfo: clientcmdapi.Cluster{Server: masterUrl}}).ClientConfig()
}

// When running in a Windows hostprocess container (HPC), add Calico Prometheus metrics
// port rules to the Windows firewall. Invoke Windows Powershell to possibly remove an
// existing rule and add the new rule. Since Felix is restarted when these configs change,
// changes to PrometheusMetricsPort will always result in an updated firewall rule.
func MaybeConfigureWindowsFirewallRules(windowsManageFirewallRules string, prometheusMetricsEnabled bool, prometheusMetricsPort int) {
	if !InHostProcessContainer() {
		log.Debug("Not running in a Windows hostprocess container (HPC), skipping Windows firewall rule setup")
		return
	}

	// Don't touch firewall rules if WindowsManageFirewallRules is disabled in FelixConfiguration
	if windowsManageFirewallRules != "Enabled" {
		log.Debug("WindowsManageFirewallRules is not enabled, skipping Windows firewall rule setup")
		return
	}

	const winFirewallRuleName = "Calico Prometheus Ports (calico-managed rule)"

	// If prometheus metrics are enabled, add rule, otherwise only clean up any possibly existing rule
	var commands []string

	log.Infof("Cleaning any previously existing '%s' Windows firewall rule.", winFirewallRuleName)

	commands = append(commands, fmt.Sprintf("Remove-NetFirewallRule -DisplayName '%s' -erroraction 'silentlycontinue'", winFirewallRuleName))

	if prometheusMetricsEnabled {
		log.Infof("Prometheus metrics are enabled, adding '%s' Windows firewall rule.", winFirewallRuleName)

		// addFirewallRuleCmd := fmt.Sprintf("New-NetFirewallRule -DisplayName '%s' -Direction inbound -Profile Any -Action Allow -LocalPort %d -Protocol TCP -Program '%s'", winFirewallRuleName, prometheusMetricsPort, os.Args[0])
		commands = append(commands, fmt.Sprintf("New-NetFirewallRule -DisplayName '%s' -Direction inbound -Profile Any -Action Allow -LocalPort %d -Protocol TCP", winFirewallRuleName, prometheusMetricsPort))
	}

	stdout, stderr, err := Powershell(strings.Join(commands, ";"))
	if err != nil {
		log.Warnf("Error interacting with powershell to configure Windows Firewall metrics ports rule\nstdout:%s\nerror: %s\nstderr: %s", stdout, err, stderr)
	} else {
		log.Debugf("Configured '%s' Windows firewall rule.\nstdout: %s\nstderr: %s", winFirewallRuleName, stdout, stderr)
	}
}
