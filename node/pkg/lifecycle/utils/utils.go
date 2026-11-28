// Copyright (c) 2021-2026 Tigera, Inc. All rights reserved.
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
	"encoding/json"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	kapiv1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/projectcalico/calico/libcalico-go/lib/names"
	"github.com/projectcalico/calico/libcalico-go/lib/nodestatus"
)

const (
	defaultShutdownTimestampFileLinux   = `/var/lib/calico/shutdownTS`
	defaultShutdownTimestampFileWindows = `c:\CalicoWindows\shutdownTS`
	defaultNodenameFileLinux            = `/var/lib/calico/nodename`
	defaultNodenameFileWindows          = `c:\CalicoWindows\nodename`
)

// For testing purposes we define an exit function that we can override.
var exitFunction = os.Exit

// Terminate prints a terminate message and exists with status 1.
func Terminate() {
	log.Warn("Terminating")
	exitFunction(1)
}

// GetExitFunction return current exit function.
func GetExitFunction() func(int) {
	return exitFunction
}

// SetExitFunction set exitFunction to be called.
func SetExitFunction(exitFunc func(int)) {
	exitFunction = exitFunc
}

// shutdownTimestampFileName returns file name used for saving shutdown timestamp.
func shutdownTimestampFileName() string {
	fn := os.Getenv("CALICO_SHUTDOWN_TIMESTAMP_FILE")
	if fn == "" {
		if runtime.GOOS == "windows" {
			return defaultShutdownTimestampFileWindows
		} else {
			return defaultShutdownTimestampFileLinux
		}
	}
	return fn
}

// RemoveShutdownTimestampFile removes shutdown timestamp file.
func RemoveShutdownTimestampFile() error {
	dataOK := true
	filename := shutdownTimestampFileName()
	data, err := os.ReadFile(filename)
	if err != nil {
		if os.IsNotExist(err) {
			// File doesn't exist
			return nil
		}
		log.WithError(err).Error("Failed to read " + filename)
		dataOK = false
	}
	if err := os.Remove(filename); err != nil {
		log.WithError(err).Error("Failed to remove " + filename)
		return err
	}

	if dataOK {
		log.WithField("timestamp", string(data)).Info("removed shutdown timestamp")
	} else {
		log.Info("removed shutdown timestamp")
	}
	return nil
}

// SaveShutdownTimestamp saves timestamp to shutdown timestamp file.
func SaveShutdownTimestamp() error {
	ts := time.Now().UTC().Format(time.RFC3339)
	filename := shutdownTimestampFileName()
	log.Infof("Writing shutdown timestamp %s to %s", ts, filename)
	if err := os.WriteFile(filename, []byte(ts), 0o644); err != nil {
		log.WithError(err).Error("Unable to write to " + filename)
		return err
	}
	return nil
}

// DetermineNodeName is called to determine the node name to use for this instance
// of calico/node.
func DetermineNodeName() string {
	var nodeName string
	var err error

	// Determine the name of this node.  Precedence is:
	// -  NODENAME
	// -  Value stored in our nodename file.
	// -  HOSTNAME (lowercase)
	// -  os.Hostname (lowercase).
	// We use the names.Hostname which lowercases and trims the name.
	if nodeName = strings.TrimSpace(os.Getenv("NODENAME")); nodeName != "" {
		log.Infof("Using NODENAME environment for node name %s", nodeName)
	} else if nodeName = NodenameFromFile(); nodeName != "" {
		log.Infof("Using stored node name %s from %s", nodeName, nodenameFileName())
	} else if nodeName = strings.ToLower(strings.TrimSpace(os.Getenv("HOSTNAME"))); nodeName != "" {
		log.Infof("Using HOSTNAME environment (lowercase) for node name %s", nodeName)
	} else if nodeName, err = names.Hostname(); err != nil {
		log.WithError(err).Error("Unable to determine hostname")
		Terminate()
	} else {
		log.Warn("Using auto-detected node name. It is recommended that an explicit value is supplied using " +
			"the NODENAME environment variable.")
	}
	log.Infof("Determined node name: %s", nodeName)

	return nodeName
}

func nodenameFileName() string {
	fn := os.Getenv("CALICO_NODENAME_FILE")
	if fn == "" {
		if runtime.GOOS == "windows" {
			return defaultNodenameFileWindows
		} else {
			return defaultNodenameFileLinux
		}
	}
	return fn
}

// NodenameFromFile reads the nodename file if it exists and
// returns the nodename within.
func NodenameFromFile() string {
	filename := nodenameFileName()
	data, err := os.ReadFile(filename)
	if err != nil {
		if os.IsNotExist(err) {
			// File doesn't exist, return empty string.
			log.Debug("File does not exist: " + filename)
			return ""
		}
		log.WithError(err).Error("Failed to read " + filename)
		Terminate()
	}
	return string(data)
}

// writeNodeConfig writes out the this node's configuration to disk for use by other components.
// Specifically, it creates:
// - nodenameFileName() - used to persist the determined node name to disk for future use.
func WriteNodeConfig(nodeName string) {
	filename := nodenameFileName()
	log.Debugf("Writing %s to "+filename, nodeName)
	if err := os.WriteFile(filename, []byte(nodeName), 0o644); err != nil {
		log.WithError(err).Error("Unable to write to " + filename)
		Terminate()
	}
}

// retryInterval paces the retry loops below, which ride out transient API errors while the
// node is still coming up.
const retryInterval = time.Second

// SetNodeNetworkUnavailableCondition sets the Kubernetes NetworkUnavailable node condition to
// value, retrying until timeout.
// https://kubernetes.io/docs/concepts/architecture/nodes/#condition
func SetNodeNetworkUnavailableCondition(
	ctx context.Context,
	clientset kubernetes.Interface,
	nodeName string,
	value bool,
	reason string,
	message string,
	timeout time.Duration,
) error {
	log.Infof("Setting NetworkUnavailable to %t", value)

	status := kapiv1.ConditionFalse
	if value {
		status = kapiv1.ConditionTrue
	}
	condition := kapiv1.NodeCondition{
		Type:               kapiv1.NodeNetworkUnavailable,
		Status:             status,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: metav1.Now(),
		LastHeartbeatTime:  metav1.Now(),
	}

	raw, err := json.Marshal(&[]kapiv1.NodeCondition{condition})
	if err != nil {
		return err
	}
	patch := fmt.Appendf(nil, `{"status":{"conditions":%s}}`, raw)

	return retryUntil(ctx, timeout, "set the NetworkUnavailable condition", func() error {
		_, err := clientset.CoreV1().Nodes().PatchStatus(ctx, nodeName, patch)
		return err
	})
}

// RemoveNetworkReadyTaint clears the network-ready taint, retrying until timeout. It runs
// whether or not the feature is enabled, so disabling it drains the taint rather than
// stranding every node that already carries one.
func RemoveNetworkReadyTaint(
	ctx context.Context,
	clientset kubernetes.Interface,
	nodeName string,
	timeout time.Duration,
) error {
	return retryUntil(ctx, timeout, "remove the network-ready taint", func() error {
		node, err := clientset.CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
		if err != nil {
			return err
		}
		if !nodestatus.HasNetworkReadyTaint(node) {
			return nil
		}

		node.Spec.Taints = nodestatus.WithoutNetworkReadyTaint(node.Spec.Taints)
		if _, err := clientset.CoreV1().Nodes().Update(ctx, node, metav1.UpdateOptions{}); err != nil {
			return err
		}
		log.WithField("node", nodeName).Info("Removed the network-ready taint")
		return nil
	})
}

func retryUntil(ctx context.Context, timeout time.Duration, description string, attempt func() error) error {
	deadline := time.After(timeout)
	var lastErr error
	for {
		if lastErr = attempt(); lastErr == nil {
			return nil
		}
		log.WithError(lastErr).Warnf("Failed to %s; will retry", description)

		select {
		case <-ctx.Done():
			return fmt.Errorf("gave up trying to %s: %w", description, lastErr)
		case <-deadline:
			return fmt.Errorf("timed out trying to %s: %w", description, lastErr)
		case <-time.After(retryInterval):
		}
	}
}

// IsIPv6String returns if ip is IPv6.
func IsIPv6String(ip string) bool {
	netIP := net.ParseIP(ip)
	return IsIPv6(netIP)
}

// IsIPv4String returns if ip is IPv4.
func IsIPv4String(ip string) bool {
	netIP := net.ParseIP(ip)
	return IsIPv4(netIP)
}

// IsIPv4 returns if netIP is IPv4.
func IsIPv4(netIP net.IP) bool {
	return netIP != nil && netIP.To4() != nil
}

// IsIPv6 returns if netIP is IPv6.
func IsIPv6(netIP net.IP) bool {
	return netIP != nil && netIP.To4() == nil
}
