// Copyright (c) 2018-2021 Tigera, Inc. All rights reserved.
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
package utils

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/containernetworking/cni/pkg/skel"
	cniv1 "github.com/containernetworking/cni/pkg/types/100"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/windows/registry"

	"github.com/projectcalico/calico/cni-plugin/internal/pkg/utils/cri"
	"github.com/projectcalico/calico/cni-plugin/pkg/dataplane/windows"
	"github.com/projectcalico/calico/cni-plugin/pkg/types"
	api "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	calicoclient "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
)

const (
	CalicoRegistryKey   = `Software\tigera\calico`
	PodDeletedKeyString = `PodDeleted`
	PodDeletedKey       = CalicoRegistryKey + `\` + PodDeletedKeyString

	// Wait for 10 minutes for pod deletion timestamp timeout.
	// Sandbox operations timeout is 4 minutes.
	defaultPodDeletionTimestampTimeout = 600
)

func updateHostLocalIPAMDataForOS(subnet string, ipamData map[string]interface{}) error {
	return UpdateHostLocalIPAMDataForWindows(subnet, ipamData)
}

func EnsureVXLANTunnelAddr(ctx context.Context, calicoClient calicoclient.Interface, nodeName string, ipNet *net.IPNet, networkName string) error {
	return windows.EnsureVXLANTunnelAddr(ctx, calicoClient, nodeName, ipNet, networkName)
}

func networkApplicationContainer(args *skel.CmdArgs) error {
	return windows.NetworkApplicationContainer(args)
}

// Create calico key if not exists.
func ensureCalicoKey() error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, "software", registry.CREATE_SUB_KEY)
	if err != nil {
		return err
	}
	defer k.Close()

	// CreateKey creates a key named path under open key k.
	// CreateKey returns the new key and a boolean flag that reports whether the key already existed.
	tigeraK, _, err := registry.CreateKey(k, "tigera", registry.CREATE_SUB_KEY)
	if err != nil {
		return err
	}
	defer tigeraK.Close()

	calicoK, _, err := registry.CreateKey(tigeraK, "calico", registry.CREATE_SUB_KEY)
	if err != nil {
		return err
	}
	defer calicoK.Close()

	return nil
}

// Create key for deletion timestamps if not exists.
// Remove obsolete entries.
func maintainWepDeletionTimestamps(timeout int) error {
	if timeout == 0 {
		timeout = defaultPodDeletionTimestampTimeout
	}
	// Open or Create subkey if not exists.
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, PodDeletedKey, registry.QUERY_VALUE|registry.SET_VALUE)
	if err == registry.ErrNotExist {
		// Create calico key if not exists.
		err := ensureCalicoKey()
		if err != nil {
			logrus.Errorf("Failed to ensure Calico registry key. err: %v", err)
			return err
		}
		calicoK, err := registry.OpenKey(registry.LOCAL_MACHINE, CalicoRegistryKey, registry.CREATE_SUB_KEY)
		if err != nil {
			return err
		}
		defer calicoK.Close()

		k, _, err = registry.CreateKey(calicoK, PodDeletedKeyString, registry.QUERY_VALUE|registry.SET_VALUE)
		if err != nil {
			return err
		}
	} else if err != nil {
		return nil
	}
	defer k.Close()

	// Delete obsolete timestamps.
	containerIDs, err := k.ReadValueNames(-1)
	if err != nil {
		return err
	}

	for _, id := range containerIDs {
		val, _, err := k.GetStringValue(id)
		if err != nil {
			return err
		}

		t, err := time.Parse(time.RFC3339, val)
		if err != nil {
			return err
		}

		logrus.WithField("id", id).Debugf("Maintainer get timestamp for pod deletion [%s]", val)
		if time.Since(t) > (time.Second * time.Duration(timeout)) {
			logrus.WithField("id", id).Debugf("Found old pod deletion timestamp [%s] with timeout %d seconds, cleaning it up.", val, timeout)
			err := k.DeleteValue(id)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func CheckWepJustDeleted(containerID string, timeout int) (bool, error) {
	if timeout == 0 {
		timeout = defaultPodDeletionTimestampTimeout
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, PodDeletedKey, registry.QUERY_VALUE)
	if err != nil {
		return false, err
	}
	defer k.Close()

	val, _, err := k.GetStringValue(containerID)
	if err == registry.ErrNotExist {
		logrus.WithField("id", containerID).Infof("No timestamp for pod deletion")
		return false, nil
	}

	t, err := time.Parse(time.RFC3339, val)
	if err != nil {
		// Time format is wrong, return true anyway.
		return true, err
	}

	logrus.WithField("id", containerID).Infof("Get timestamp for pod deletion [%s]", val)
	if time.Since(t) < (time.Second * time.Duration(timeout)) {
		logrus.WithField("id", containerID).Infof("timestamp for pod deletion [%s] within %d seconds", val, timeout)
		return true, nil
	}

	return false, nil
}

func RegisterDeletedWep(containerID string) error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, PodDeletedKey, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()

	if err := k.SetStringValue(containerID, time.Now().Format(time.RFC3339)); err != nil {
		return err
	}

	// loop 3 seconds until successfully read back
	retry := 0
	for retry < 30 {
		val, _, err := k.GetStringValue(containerID)
		if err == nil {
			logrus.WithField("id", containerID).Infof("Saved timestamp for pod deletion [%s]", val)
			return nil
		}
		time.Sleep(100 * time.Millisecond)
		retry++
	}

	return fmt.Errorf("timeout waiting registry update for %s", containerID)
}

// Windows special case: Kubelet has a hacky implementation of GetPodNetworkStatus() that uses a
// CNI ADD to check the status of the pod.  Detect such spurious adds and allow cni-plugin to return early,
// avoiding trying to network the pod multiple times.
func CheckForSpuriousDockerAdd(args *skel.CmdArgs,
	conf types.NetConf,
	epIDs WEPIdentifiers,
	endpoint *api.WorkloadEndpoint,
	logger *logrus.Entry) (*cniv1.Result, error) {
	var err error
	var result *cniv1.Result

	logger.Debugf("CheckForSpuriousDockerAdd: containerID: %v, ifName: %v, netns: %v, epIDs: %+v, ep: %+v", args.ContainerID, args.IfName, args.Netns, epIDs, endpoint)

	// We only check for extra CNI ADD calls in the dockershim HNS V1 flow.
	if !cri.IsDockershimV1(args.Netns) {
		logger.Debug("cni add request not from dockershim")
		return nil, nil
	}

	err = maintainWepDeletionTimestamps(conf.WindowsPodDeletionTimestampTimeout)
	if err != nil {
		logger.WithError(err).Warn("Failed to do maintenance on pod deletion timestamps.")
	}

	lookupRequest := false
	if args.Netns == "" {
		// Defensive: this case should be blocked by CNI validation.
		logger.Info("No network namespace supplied, assuming a lookup-only request.")
		lookupRequest = true
	} else if args.Netns != cri.PauseContainerNetNS {
		// When kubelet really wants to network the pod, it passes us the netns of the "pause" container, which
		// is a static value. The other requests come from checks on the other containers.
		// Application containers should be networked with the pause container endpoint to reflect DNS details.
		logger.Info("Non-pause container specified, doing a lookup-only request.")
		err = networkApplicationContainer(args)
		if err != nil {
			logger.WithError(err).Warn("Failed to network container with pause container endpoint.")
			return nil, err
		}
		lookupRequest = true
	} else if endpoint != nil && len(endpoint.Spec.IPNetworks) > 0 {
		// Defensive: datastore says the pod is already networked.  This check isn't sufficient on its own because
		// GetPodNetworkStatus() can race with a CNI DEL operation, making it look like the pod has no network.
		logger.Info("Endpoint already networked, doing a lookup-only request.")
		lookupRequest = true
	}

	if lookupRequest {
		result, err = CreateResultFromEndpoint(endpoint)
		if err == nil {
			logger.WithField("result", result).Info("Status lookup result")
		} else {
			// For example, endpoint not found (which is expected if we're racing with a CNI DEL).
			logger.WithError(err).Warn("Failed to look up pod status")
		}
		return result, err
	}

	// After checking wep not exists, next step is to check wep deletion timestamp.
	// The order is important because with DEL command running in parallel registering timestamp before deleting wep,
	// ADD command should run the process in reverse order to avoid race condition.

	// No WEP and no network, check deletion timestamp to skip recent deleted wep.
	// If WEP just been deleted, report back error.
	justDeleted, err := CheckWepJustDeleted(epIDs.ContainerID, conf.WindowsPodDeletionTimestampTimeout)
	if err != nil {
		logger.Warnf("Failed to check pod deletion timestamp. %v", err)
		return nil, err
	}
	if justDeleted {
		logger.Info("Pod just been deleted. Report error for pod status")
		return nil, fmt.Errorf("endpoint with same ID was recently deleted")
	}

	return nil, nil
}
