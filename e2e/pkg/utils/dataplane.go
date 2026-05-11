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

package utils

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

// CalicoDataplane is the Calico dataplane mode running on the cluster.
type CalicoDataplane string

const (
	DataplaneIptables CalicoDataplane = "Iptables"
	DataplaneBPF      CalicoDataplane = "BPF"
	DataplaneVPP      CalicoDataplane = "VPP"
	DataplaneNftables CalicoDataplane = "Nftables"
)

// KubeProxyMode is the kube-proxy operational mode running on the cluster.
type KubeProxyMode string

const (
	KubeProxyIptables KubeProxyMode = "iptables"
	KubeProxyIPVS     KubeProxyMode = "ipvs"
	KubeProxyNftables KubeProxyMode = "nftables"
)

// ClusterDataplane holds the detected dataplane and kube-proxy configuration.
type ClusterDataplane struct {
	Calico    CalicoDataplane
	KubeProxy KubeProxyMode
}

// IsBPF returns true if the Calico dataplane is BPF.
func (d ClusterDataplane) IsBPF() bool { return d.Calico == DataplaneBPF }

// IsVPP returns true if the Calico dataplane is VPP.
func (d ClusterDataplane) IsVPP() bool { return d.Calico == DataplaneVPP }

// IsNftables returns true if the Calico dataplane is nftables.
func (d ClusterDataplane) IsNftables() bool { return d.Calico == DataplaneNftables }

// IsIPVS returns true if kube-proxy is running in IPVS mode.
func (d ClusterDataplane) IsIPVS() bool { return d.KubeProxy == KubeProxyIPVS }

// DetectDataplane auto-detects the Calico dataplane and kube-proxy mode from
// cluster state. It tries the Installation CR first, then falls back to
// FelixConfiguration for manifest-based installs.
func DetectDataplane(cli ctrlclient.Client, clientset kubernetes.Interface) ClusterDataplane {
	return ClusterDataplane{
		Calico:    DetectCalicoDataplane(cli),
		KubeProxy: DetectKubeProxyMode(clientset),
	}
}

// DetectCalicoDataplane returns just the Calico dataplane mode, skipping the
// kube-proxy lookup. Useful for callers that only need to branch on the
// Calico-side dataplane (e.g. BPF vs. iptables).
func DetectCalicoDataplane(cli ctrlclient.Client) CalicoDataplane {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Prefer the Installation CR (operator-managed clusters).
	installation := &operatorv1.Installation{}
	if err := cli.Get(ctx, ctrlclient.ObjectKey{Name: "default"}, installation); err == nil &&
		installation.Spec.CalicoNetwork != nil &&
		installation.Spec.CalicoNetwork.LinuxDataplane != nil {
		var dp CalicoDataplane
		switch *installation.Spec.CalicoNetwork.LinuxDataplane {
		case operatorv1.LinuxDataplaneBPF:
			dp = DataplaneBPF
		case operatorv1.LinuxDataplaneVPP:
			dp = DataplaneVPP
		case operatorv1.LinuxDataplaneNftables:
			dp = DataplaneNftables
		default:
			dp = DataplaneIptables
		}
		logrus.Infof("Detected Calico dataplane from Installation CR: %s", dp)
		return dp
	}

	// Fall back to FelixConfiguration for manifest-based installs.
	felixCfg := &v3.FelixConfiguration{}
	if err := cli.Get(ctx, ctrlclient.ObjectKey{Name: "default"}, felixCfg); err == nil {
		var dp CalicoDataplane = DataplaneIptables
		if felixCfg.Spec.BPFEnabled != nil && *felixCfg.Spec.BPFEnabled {
			dp = DataplaneBPF
		} else if felixCfg.Spec.NFTablesMode != nil && *felixCfg.Spec.NFTablesMode == v3.NFTablesModeEnabled {
			dp = DataplaneNftables
		} else if felixCfg.Spec.UseInternalDataplaneDriver != nil && !*felixCfg.Spec.UseInternalDataplaneDriver {
			dp = DataplaneVPP
		}
		logrus.Infof("Detected Calico dataplane from FelixConfiguration: %s", dp)
		return dp
	} else {
		logrus.WithError(err).Info("Could not read FelixConfiguration, defaulting to iptables")
	}
	return DataplaneIptables
}

// kubeProxyConfig is a minimal struct for parsing the kube-proxy config.
type kubeProxyConfig struct {
	Mode string `yaml:"mode" json:"mode"`
}

// DetectKubeProxyMode reads the kube-proxy ConfigMap to determine the proxy mode.
func DetectKubeProxyMode(clientset kubernetes.Interface) KubeProxyMode {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cm, err := clientset.CoreV1().ConfigMaps("kube-system").Get(ctx, "kube-proxy", metav1.GetOptions{})
	if err != nil {
		logrus.WithError(err).Info("Could not read kube-proxy ConfigMap, defaulting to iptables proxy mode")
		return KubeProxyIptables
	}

	configData, ok := cm.Data["config.conf"]
	if !ok {
		configData = cm.Data["kubeconfig.conf"]
	}

	if configData == "" {
		logrus.Info("kube-proxy ConfigMap has no parseable config, defaulting to iptables proxy mode")
		return KubeProxyIptables
	}

	var cfg kubeProxyConfig
	if err := yaml.Unmarshal([]byte(configData), &cfg); err != nil {
		logrus.WithError(err).Info("Could not parse kube-proxy config, defaulting to iptables proxy mode")
		return KubeProxyIptables
	}

	switch cfg.Mode {
	case "ipvs":
		logrus.Info("Detected kube-proxy mode: IPVS")
		return KubeProxyIPVS
	case "nftables":
		logrus.Info("Detected kube-proxy mode: nftables")
		return KubeProxyNftables
	default:
		logrus.Infof("Detected kube-proxy mode: iptables (raw value: %q)", cfg.Mode)
		return KubeProxyIptables
	}
}
