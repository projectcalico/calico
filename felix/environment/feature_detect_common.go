// Copyright (c) 2023-2025 Tigera, Inc. All rights reserved.
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

package environment

type Features struct {
	// SNATFullyRandom is true if --random-fully is supported by the SNAT action.
	SNATFullyRandom bool
	// MASQFullyRandom is true if --random-fully is supported by the MASQUERADE action.
	MASQFullyRandom bool
	// RestoreSupportsLock is true if the iptables-restore command supports taking the xtables lock and the
	// associated -w and -W arguments.
	RestoreSupportsLock bool
	// ChecksumOffloadBroken is true for kernels that have broken checksum offload for packets with SNATted source
	// ports. See https://github.com/projectcalico/calico/issues/3145.  On such kernels we disable checksum offload
	// on our VXLAN and IPIP device.
	ChecksumOffloadBroken bool
	// NFLogSize is true if --nflog-size is supported by the NFLOG action.
	NFLogSize bool
	// IPIPDeviceIsL3 represent if ipip tunnels acts like other l3 devices
	IPIPDeviceIsL3 bool
	// KernelSideRouteFiltering is true if the kernel supports filtering netlink route dumps kernel-side.
	// This is much more efficient.
	KernelSideRouteFiltering bool
}

type FeatureDetectorIface interface {
	GetFeatures() *Features
	RefreshFeatures()
	FeatureGate(name string) string
}

func WithFeatureGates(gates map[string]string) Option {
	return func(detector *FeatureDetector) {
		detector.featureGates = gates
	}
}

type featureDetectorCommon struct {
	featureGates map[string]string
}

func (d *featureDetectorCommon) FeatureGate(name string) string {
	return d.featureGates[name]
}

var _ FeatureDetectorIface = (*FeatureDetector)(nil)
