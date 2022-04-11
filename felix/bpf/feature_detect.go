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

package bpf

import (
	"io"
	"reflect"
	"strconv"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/versionparse"
)

var (
	// v5Dot14Dot0 is the fist kernel version that IPIP tunnels acts like other L3
	// devices where bpf programs only see inner IP header. In RHEL based distros,
	// kernel 4.18.0 (v4Dot18Dot0_330) is the first one with this behavior.
	v5Dot14Dot0     = versionparse.MustParseVersion("5.14.0")
	v4Dot18Dot0_330 = versionparse.MustParseVersion("4.18.0-330")
)

type Features struct {
	// IPIPDeviceIsL3 represent if ipip tunnels acts like other l3 devices
	IPIPDeviceIsL3 bool
}

type FeatureDetector struct {
	lock            sync.Mutex
	featureCache    *Features
	featureOverride map[string]string
	loggedOverrides bool

	// Path to file with kernel version
	GetKernelVersionReader func() (io.Reader, error)
}

func NewFeatureDetector(overrides map[string]string) *FeatureDetector {
	return &FeatureDetector{
		GetKernelVersionReader: versionparse.GetKernelVersionReader,
		featureOverride:        overrides,
	}
}

func (d *FeatureDetector) GetFeatures() *Features {
	d.lock.Lock()
	defer d.lock.Unlock()

	if d.featureCache == nil {
		d.refreshFeaturesLockHeld()
	}

	return d.featureCache
}

func (d *FeatureDetector) RefreshFeatures() {
	d.lock.Lock()
	defer d.lock.Unlock()

	d.refreshFeaturesLockHeld()
}

func (d *FeatureDetector) refreshFeaturesLockHeld() {
	// Get the versions.  If we fail to detect a version for some reason, we use a safe default.
	log.Debug("Refreshing detected bpf features")

	kerV := d.getKernelVersion()

	// Calculate features.
	features := Features{
		IPIPDeviceIsL3: ipipDeviceIsL3(),
	}

	for k, v := range d.featureOverride {
		ovr, err := strconv.ParseBool(v)
		logCxt := log.WithFields(log.Fields{
			"flag":  k,
			"value": v,
		})
		if err != nil {
			if !d.loggedOverrides {
				logCxt.Warn("Failed to parse value for feature detection override; ignoring")
			}
			continue
		}
		field := reflect.ValueOf(&features).Elem().FieldByName(k)
		if field.IsValid() {
			field.SetBool(ovr)
		} else {
			if !d.loggedOverrides {
				logCxt.Warn("Unknown feature detection flag; ignoring")
			}
			continue
		}

		if !d.loggedOverrides {
			logCxt.Info("Overriding feature detection flag")
		}
	}
	// Avoid logging all the override values every time through this function.
	d.loggedOverrides = true

	if d.featureCache == nil || *d.featureCache != features {
		log.WithFields(log.Fields{
			"features":      features,
			"kernelVersion": kerV,
		}).Info("Updating detected bpf features")
		d.featureCache = &features
	}
}

func (d *FeatureDetector) getKernelVersion() *versionparse.Version {
	reader, err := d.GetKernelVersionReader()
	if err != nil {
		log.WithError(err).Warn("Failed to get the kernel version reader, assuming old version with no optional features")
		return v3Dot10Dot0
	}
	kernVersion, err := versionparse.GetKernelVersion(reader)
	if err != nil {
		log.WithError(err).Warn("Failed to get kernel version, assuming old version with no optional features")
		return v3Dot10Dot0
	}
	return kernVersion
}

func ipipDeviceIsL3() bool {
	switch versionparse.GetDistributionName() {
	case "rhel":
		if err := isAtLeastKernel(v4Dot18Dot0_330); err != nil {
			return false
		}
		return true
	default:
		if err := isAtLeastKernel(v5Dot14Dot0); err != nil {
			return false
		}
		return true
	}
}
