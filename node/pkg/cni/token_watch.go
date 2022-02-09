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

const (
	serviceaccountDirectory = "/var/run/secrets/kubernetes.io/serviceaccount/"
	tokenFile               = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	rootCAFile              = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	kubeconfigPath          = "/host/etc/cni/net.d/calico-kubeconfig"
)

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

	// Watch for changes to the serviceaccount directory, token file, and crt. Rety if necessary.
	for {
		if err := watcher.Add(serviceaccountDirectory); err != nil {
			// Error watching the file - retry
			logrus.WithError(err).Error("Failed to watch Kubernetes serviceaccount directory.")
			time.Sleep(5 * time.Second)
			continue
		}
		if err := watcher.Add(tokenFile); err != nil {
			// Error watching the file - retry
			logrus.WithError(err).Error("Failed to watch Kubernetes serviceaccount token file.")
			time.Sleep(5 * time.Second)
			continue
		}
		if err := watcher.Add(rootCAFile); err != nil {
			// Error watching the file - retry
			logrus.WithError(err).Error("Failed to watch Kubernetes serviceaccount ca.crt.")
			time.Sleep(5 * time.Second)
			continue
		}

		// Successfully watched the file. Break from the retry loop.
		logrus.WithField("directory", serviceaccountDirectory).Info("Watching contents for changes.")
		break
	}

	configWriter := cniConfigWriter{}

	// Handle events from the watcher.
	for {
		// To prevent tight looping, add a sleep here.
		time.Sleep(1 * time.Second)

		select {
		case <-time.After(5 * time.Minute):
			// Periodic token refresh.
			logrus.Debug("Triggering periodic CNI config refresh")
			err := configWriter.handleEvent()
			if err != nil {
				logrus.WithError(err).Error("Failed to handle fsnotify event")
			}
		case event := <-watcher.Events:
			// We've received a notification that the Kubernetes secrets files have changed.
			// Update the kubeconfig file on disk to match.
			logrus.WithField("event", event).Info("Notified of change to serviceaccount files.")
			err := configWriter.handleEvent()
			if err != nil {
				logrus.WithError(err).Error("Failed to handle fsnotify event")
			}
		case err := <-watcher.Errors:
			// We've received an error - log it out but don't exit.
			logrus.WithError(err).Error("Error watching serviceaccount files.")
		}
	}
}

type cniConfigWriter struct {
	previousConfig string
}

func (w *cniConfigWriter) handleEvent() error {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		logrus.WithError(err).Error("Error generating kube config.")
		return err
	}
	err = rest.LoadTLSFiles(cfg)
	if err != nil {
		logrus.WithError(err).Error("Error loading TLS files.")
		return err
	}
	return w.writeKubeconfig(cfg)
}

// writeKubeconfig writes an updated kubeconfig file to disk that the CNI plugin can use to access the Kubernetes API.
func (w *cniConfigWriter) writeKubeconfig(cfg *rest.Config) error {
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

	// No need to write the kubeconfig if it hasn't changed.
	if data == w.previousConfig {
		logrus.Debug("CNI config on disk is still valid")
		return nil
	}

	// Write the filled out config to disk.
	if err := ioutil.WriteFile(kubeconfigPath, []byte(data), 0600); err != nil {
		logrus.WithError(err).Error("Failed to write CNI plugin kubeconfig file")
		return err
	}
	logrus.WithField("path", kubeconfigPath).Info("Wrote updated CNI kubeconfig file.")
	w.previousConfig = data
	return nil
}
