// Copyright (c) 2018-2020 Tigera, Inc. All rights reserved.
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

package utils

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/cni-plugin/pkg/dataplane/windows"
	"github.com/projectcalico/cni-plugin/pkg/types"
	calicoclient "github.com/projectcalico/libcalico-go/lib/clientv3"

	"golang.org/x/sys/windows/registry"
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

func EnsureVXLANTunnelAddr(ctx context.Context, calicoClient calicoclient.Interface, nodeName string, ipNet *net.IPNet, conf types.NetConf) error {
	return windows.EnsureVXLANTunnelAddr(ctx, calicoClient, nodeName, ipNet, conf)
}

func NetworkApplicationContainer(args *skel.CmdArgs) error {
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
// Remove obsolete  entries.
func MaintainWepDeletionTimestamps(timeout int) error {
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
