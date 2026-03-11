package utils

import (
	"fmt"
	"net"
	"time"

	"k8s.io/kubernetes/test/e2e/framework/kubectl"
)

// Kubectl is a wrapper around kubectl commands used in tests. Note that this helper is
// NOT meant to be used for general resource CRUD operations, for that use the client in
// pkg/utils/client.
type Kubectl struct{}

func (k *Kubectl) Logs(ns, label, user string) (string, error) {
	options := []string{"logs"}
	if user != "" {
		options = append(options, fmt.Sprintf("--as=%v", user))
	}
	if label != "" {
		options = append(options, fmt.Sprintf("-l %s", label))
	}

	output, err := kubectl.NewKubectlCommand(ns, options...).Exec()
	return output, err
}

func (k *Kubectl) Wait(kind, ns, name, user, condition string, timeout time.Duration) error {
	options := []string{"wait", kind, name, "--for", condition, "--timeout", timeout.String()}
	if user != "" {
		options = append(options, fmt.Sprintf("--as=%v", user))
	}
	_, err := kubectl.NewKubectlCommand(ns, options...).Exec()
	return err
}

// PortForward starts a kubectl port-forward in the background, allocating a random
// local port to avoid conflicts when tests run in parallel. It returns the local port.
func (k *Kubectl) PortForward(ns, pod, remotePort, user string, timeOut chan time.Time) (int, error) {
	localPort, err := getFreePort()
	if err != nil {
		return 0, fmt.Errorf("failed to allocate local port: %w", err)
	}

	options := []string{"port-forward", pod, fmt.Sprintf("%d:%s", localPort, remotePort)}
	if user != "" {
		options = append(options, fmt.Sprintf("--as=%v", user))
	}

	go func() {
		_, err := kubectl.NewKubectlCommand(ns, options...).WithTimeout(timeOut).Exec()
		if err != nil {
			return
		}
	}()
	return localPort, nil
}

func getFreePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port, nil
}
