package cni

import (
	"context"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	authenticationv1 "k8s.io/api/authentication/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const defaultCNITokenValiditySeconds = 3600

var kubeconfigPath string = "/host/etc/cni/net.d/calico-kubeconfig"

var tokenSupported = false
var tokenOnce = &sync.Once{}

func Run() {
	// Log to stdout.  this prevents our logs from being interpreted as errors by, for example,
	// fluentd's default configuration.
	logrus.SetOutput(os.Stdout)

	ticker := time.NewTicker(defaultCNITokenValiditySeconds / 3)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			logrus.Info("Update of CNI kubeconfig triggered based on elapsed time.")
			cfg, err := rest.InClusterConfig()
			if err != nil {
				logrus.WithError(err).Error("Error generating kube config.")
				continue
			}
			err = rest.LoadTLSFiles(cfg)
			if err != nil {
				logrus.WithError(err).Error("Error loading TLS files.")
				continue
			}
			writeKubeconfig(cfg)
		}
	}
}

// writeKubeconfig writes an updated kubeconfig file to disk that the CNI plugin can use to access the Kubernetes API.
func writeKubeconfig(cfg *rest.Config) {
	template := `# Kubeconfig file for Calico CNI plugin. Installed by calico/node.
apiVersion: v1
kind: Config
clusters:
- name: local
  cluster:
    server: %s
    certificate-authority-data: "%s"
users:
- name: calico
  user:
    token: %s
contexts:
- name: calico-context
  context:
    cluster: local
    user: calico
current-context: calico-context`

	// Replace the placeholders.
	data := fmt.Sprintf(template, cfg.Host, base64.StdEncoding.EncodeToString(cfg.CAData), createCNIToken(cfg))

	// Write the filled out config to disk.
	if err := ioutil.WriteFile(kubeconfigPath, []byte(data), 0600); err != nil {
		logrus.WithError(err).Error("Failed to write CNI plugin kubeconfig file")
		return
	}
	logrus.WithField("path", kubeconfigPath).Info("Wrote updated CNI kubeconfig file.")
}

func createCNIToken(kubecfg *rest.Config) string {
	clientset, err := kubernetes.NewForConfig(kubecfg)
	if err != nil {
		logrus.WithError(err).Error("Failed to create clientset for CNI kubeconfig")
		return "invalid-token"
	}

	tokenRequestSupported := func() bool {
		tokenOnce.Do(func() {
			resources, err := clientset.Discovery().ServerResourcesForGroupVersion("v1")
			if err != nil {
				return
			}
			for _, resource := range resources.APIResources {
				if resource.Name == "serviceaccounts/token" {
					tokenSupported = true
					return
				}
			}
		})
		return tokenSupported
	}

	validity := int64(defaultCNITokenValiditySeconds)
	tr := &authenticationv1.TokenRequest{
		Spec: authenticationv1.TokenRequestSpec{
			Audiences:         []string{"kubernetes"},
			ExpirationSeconds: &validity,
		},
	}

	tokenRequest, err := clientset.CoreV1().ServiceAccounts(metav1.NamespaceSystem).CreateToken(context.TODO(), "calico-node", tr, metav1.CreateOptions{})
	if apierrors.IsNotFound(err) && !tokenRequestSupported() {
		logrus.WithError(err).Error("Unable to create token for CNI kubeconfig as token request api is not supported")
		return "invalid-token"
	}
	if err != nil {
		logrus.WithError(err).Error("Unable to create token for CNI kubeconfig")
		return "invalid-token"
	}

	return tokenRequest.Status.Token
}
