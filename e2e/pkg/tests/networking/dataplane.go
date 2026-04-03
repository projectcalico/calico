// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

package networking

import (
	"context"
	"time"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/sirupsen/logrus"
	operatorv1 "github.com/tigera/operator/api/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"
)

// calicoDataplane represents the Calico dataplane mode.
type calicoDataplane string

const (
	dataplaneIptables calicoDataplane = "Iptables"
	dataplaneBPF      calicoDataplane = "BPF"
	dataplaneVPP      calicoDataplane = "VPP"
	dataplaneNftables calicoDataplane = "Nftables"
)

// kubeProxyMode represents the kube-proxy operational mode.
type kubeProxyMode string

const (
	proxyIptables kubeProxyMode = "iptables"
	proxyIPVS     kubeProxyMode = "ipvs"
	proxyNftables kubeProxyMode = "nftables"
)

// clusterDataplane holds the detected dataplane and proxy configuration.
type clusterDataplane struct {
	Calico    calicoDataplane
	KubeProxy kubeProxyMode
}

// IsBPF returns true if the Calico dataplane is BPF.
func (d clusterDataplane) IsBPF() bool { return d.Calico == dataplaneBPF }

// IsVPP returns true if the Calico dataplane is VPP.
func (d clusterDataplane) IsVPP() bool { return d.Calico == dataplaneVPP }

// IsIPVS returns true if kube-proxy is running in IPVS mode.
func (d clusterDataplane) IsIPVS() bool { return d.KubeProxy == proxyIPVS }

// detectDataplane auto-detects the Calico dataplane and kube-proxy mode from
// cluster state. It tries the Installation CR first, then falls back to
// FelixConfiguration for manifest-based installs.
func detectDataplane(cli ctrlclient.Client, clientset kubernetes.Interface) clusterDataplane {
	dp := clusterDataplane{
		Calico:    dataplaneIptables,
		KubeProxy: proxyIptables,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Try Installation CR first (operator-managed clusters).
	installation := &operatorv1.Installation{}
	err := cli.Get(ctx, ctrlclient.ObjectKey{Name: "default"}, installation)
	if err == nil && installation.Spec.CalicoNetwork != nil && installation.Spec.CalicoNetwork.LinuxDataplane != nil {
		switch *installation.Spec.CalicoNetwork.LinuxDataplane {
		case operatorv1.LinuxDataplaneBPF:
			dp.Calico = dataplaneBPF
		case operatorv1.LinuxDataplaneVPP:
			dp.Calico = dataplaneVPP
		case operatorv1.LinuxDataplaneNftables:
			dp.Calico = dataplaneNftables
		default:
			dp.Calico = dataplaneIptables
		}
		logrus.Infof("Detected Calico dataplane from Installation CR: %s", dp.Calico)
	} else {
		// Fall back to FelixConfiguration for manifest-based installs.
		felixCfg := &v3.FelixConfiguration{}
		if err := cli.Get(ctx, ctrlclient.ObjectKey{Name: "default"}, felixCfg); err == nil {
			if felixCfg.Spec.BPFEnabled != nil && *felixCfg.Spec.BPFEnabled {
				dp.Calico = dataplaneBPF
			} else if felixCfg.Spec.UseInternalDataplaneDriver != nil && !*felixCfg.Spec.UseInternalDataplaneDriver {
				dp.Calico = dataplaneVPP
			}
			logrus.Infof("Detected Calico dataplane from FelixConfiguration: %s", dp.Calico)
		} else {
			logrus.WithError(err).Info("Could not read FelixConfiguration, defaulting to iptables")
		}
	}

	// Detect kube-proxy mode from the kube-proxy ConfigMap.
	dp.KubeProxy = detectKubeProxyMode(clientset)

	logrus.Infof("Cluster dataplane: calico=%s, kube-proxy=%s", dp.Calico, dp.KubeProxy)
	return dp
}

// kubeProxyConfig is a minimal struct for parsing the kube-proxy config.
type kubeProxyConfig struct {
	Mode string `yaml:"mode" json:"mode"`
}

// detectKubeProxyMode reads the kube-proxy ConfigMap to determine the proxy mode.
func detectKubeProxyMode(clientset kubernetes.Interface) kubeProxyMode {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cm, err := clientset.CoreV1().ConfigMaps("kube-system").Get(ctx, "kube-proxy", metav1.GetOptions{})
	if err != nil {
		logrus.WithError(err).Info("Could not read kube-proxy ConfigMap, defaulting to iptables proxy mode")
		return proxyIptables
	}

	configData, ok := cm.Data["config.conf"]
	if !ok {
		configData = cm.Data["kubeconfig.conf"]
	}

	if configData == "" {
		logrus.Info("kube-proxy ConfigMap has no parseable config, defaulting to iptables proxy mode")
		return proxyIptables
	}

	var cfg kubeProxyConfig
	if err := yaml.Unmarshal([]byte(configData), &cfg); err != nil {
		logrus.WithError(err).Info("Could not parse kube-proxy config, defaulting to iptables proxy mode")
		return proxyIptables
	}

	switch cfg.Mode {
	case "ipvs":
		logrus.Info("Detected kube-proxy mode: IPVS")
		return proxyIPVS
	case "nftables":
		logrus.Info("Detected kube-proxy mode: nftables")
		return proxyNftables
	default:
		logrus.Infof("Detected kube-proxy mode: iptables (raw value: %q)", cfg.Mode)
		return proxyIptables
	}
}
