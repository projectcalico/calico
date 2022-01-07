package cni

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/sirupsen/logrus"
	"gopkg.in/fsnotify/fsnotify.v1"
	"k8s.io/client-go/rest"
)

var serviceaccountDirectory string = "/var/run/secrets/kubernetes.io/serviceaccount/"
var kubeconfigPath string = "/host/etc/cni/net.d/calico-kubeconfig"

func Run() {
	// Log to stdout.  this prevents our logs from being interpreted as errors by, for example,
	// fluentd's default configuration.
	logrus.SetOutput(os.Stdout)

	// Create a watcher for file changes.
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		panic(err)
	}
	defer watcher.Close()

	// Watch for changes to the serviceaccount directory. Rety if necessary.
	for {
		if err := watcher.Add(serviceaccountDirectory); err != nil {
			// Error watching the file - retry
			logrus.WithError(err).Error("Failed to watch Kubernetes serviceaccount files.")
			time.Sleep(5 * time.Second)
			continue
		}

		// Successfully watched the file. Break from the retry loop.
		logrus.WithField("directory", serviceaccountDirectory).Info("Watching contents for changes.")
		break
	}

	// Handle events from the watcher.
	for {
		// To prevent tight looping, add a sleep here.
		time.Sleep(1 * time.Second)

		select {
		case event := <-watcher.Events:
			// We've received a notification that the Kubernetes secrets files have changed.
			// Update the kubeconfig file on disk to match.
			logrus.WithField("event", event).Info("Notified of change to serviceaccount files.")
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

		case err := <-watcher.Errors:
			// We've received an error - log it out but don't exit.
			logrus.WithError(err).Error("Error watching serviceaccount files.")
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
	data := fmt.Sprintf(template, cfg.Host, base64.StdEncoding.EncodeToString(cfg.CAData), cfg.BearerToken)

	// Write the filled out config to disk.
	if err := ioutil.WriteFile(kubeconfigPath, []byte(data), 0600); err != nil {
		logrus.WithError(err).Error("Failed to write CNI plugin kubeconfig file")
		return
	}
	logrus.WithField("path", kubeconfigPath).Info("Wrote updated CNI kubeconfig file.")
}
