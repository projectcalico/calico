// Copyright (c) 2022 Tigera, Inc. All rights reserved.
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

package driver

import (
	"context"

	csi "github.com/container-storage-interface/spec/lib/go/csi"
)

func (d *Driver) GetPluginInfo(ctx context.Context, req *csi.GetPluginInfoRequest) (*csi.GetPluginInfoResponse, error) {
	return &csi.GetPluginInfoResponse{
		Name:          "csi.tigera.io",
		VendorVersion: VER,
	}, nil
}

func (d *Driver) GetPluginCapabilities(ctx context.Context, req *csi.GetPluginCapabilitiesRequest) (*csi.GetPluginCapabilitiesResponse, error) {
	// No extra capabilities are required.
	return &csi.GetPluginCapabilitiesResponse{}, nil
}

func (d *Driver) Probe(ctx context.Context, req *csi.ProbeRequest) (*csi.ProbeResponse, error) {
	// Not really needed since plugin health is on a per node basis.
	return &csi.ProbeResponse{}, nil
}
