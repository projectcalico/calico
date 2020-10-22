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
// limitations under the License.

package startup

import (
	"context"
	"errors"
	"net"
	"os"
	"strconv"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/cni-plugin/pkg/dataplane/windows"
	api "github.com/projectcalico/libcalico-go/lib/apis/v3"
	client "github.com/projectcalico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/libcalico-go/lib/ipam"
)

const defaultNodenameFile = `c:\TigeraCalico\nodename`

var DEFAULT_INTERFACES_TO_EXCLUDE = []string{
	".*cbr.*",
	".*[Dd]ocker.*",
	".*\\(nat\\).*",
	".*Calico.*_ep", // Exclude our management endpoint.
	"Loopback.*",
}

func getOSType() string {
	return OSTypeWindows
}

// Checks that the filesystem is as expected and fix it if possible
func ensureFilesystemAsExpected() {
	logrus.Debug("ensureFilesystemAsExpected called on Windows; nothing to do.")
}

func ipv6Supported() bool {
	return false
}

// configureCloudOrchRef does not do anything for windows
func configureCloudOrchRef(node *api.Node) {
	logrus.Debug("configureCloudOrchRef called on Windows; nothing to do.")
}

func ensureNetworkForOS(ctx context.Context, c client.Interface, nodeName string) error {
	backend := os.Getenv("CALICO_NETWORKING_BACKEND")
	switch backend {
	case "none":
		logrus.Info("Backend networking is none, no network setup needed.")
	case "vxlan", "windows-bgp":
		logrus.Info("Backend networking is vxlan, ensure vxlan network.")
		rsvdAttrWindows := &ipam.HostReservedAttr{
			StartOfBlock: 3,
			EndOfBlock:   1,
			Handle:       ipam.WindowsReservedHandle,
			Note:         "windows host rsvd",
		}

		args := ipam.BlockArgs{
			Hostname:              nodeName,
			HostReservedAttrIPv4s: rsvdAttrWindows,
		}

		cidr, _, err := c.IPAM().EnsureBlock(ctx, args)
		if err != nil {
			return err
		}
		subnet := &net.IPNet{IP: cidr.IP, Mask: cidr.Mask}

		networkName := "Calico"

		if backend == "vxlan" {
			vniString := os.Getenv("VXLAN_VNI")
			vni, err := strconv.ParseInt(vniString, 10, 64)
			if err != nil {
				return err
			}
			_, err = windows.SetupVxlanNetwork(networkName, subnet, uint64(vni), logrus.WithField("subnet", subnet.String()))
			if err != nil {
				return err
			}
		} else {
			_, err = windows.SetupL2bridgeNetwork(networkName, subnet, logrus.WithField("subnet", subnet.String()))
			if err != nil {
				return err
			}
		}
	default:
		logrus.WithField("backend", backend).Errorf("Invalid backend networking type")
		return errors.New("invalid backend configuration")
	}

	logrus.Info("Ensure network is done.")
	return nil
}
