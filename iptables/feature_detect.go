// Copyright (c) 2018 Tigera, Inc. All rights reserved.
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

package iptables

import (
	"io/ioutil"
	"regexp"
	"sync"

	"github.com/hashicorp/go-version"
	log "github.com/sirupsen/logrus"
)

var (
	vXDotYDotZRegexp    = regexp.MustCompile(`v(\d+\.\d+\.\d+)`)
	kernelVersionRegexp = regexp.MustCompile(`Linux version (\d+\.\d+\.\d+)`)

	// iptables versions:
	// v1Dot4Dot7 is the oldest version we've ever supported.
	v1Dot4Dot7 = mustParseVersion("1.4.7")
	// v1Dot6Dot0 added --random-fully to SNAT.
	v1Dot6Dot0 = mustParseVersion("1.6.0")
	// v1Dot6Dot2 added --random-fully to MASQUERADE
	v1Dot6Dot2 = mustParseVersion("1.6.2")

	// Linux kernel versions:
	// v3Dot10Dot0 is the oldest version we support at time of writing.
	v3Dot10Dot0 = mustParseVersion("3.10.0")
	// v3Dot14Dot0 added the random-fully feature on the iptables interface.
	v3Dot14Dot0 = mustParseVersion("3.14.0")
)

type Features struct {
	// SNATFullyRandom is true if --fully-random is supported by the SNAT action.
	SNATFullyRandom bool
	// MASQFullyRandom is true if --fully-random is supported by the MASQUERADE action.
	MASQFullyRandom bool
	// RestoreSupportsLock is true if the iptables-restore command supports taking the xtables lock and the
	// associated -w and -W arguments.
	RestoreSupportsLock bool
}

type FeatureDetector struct {
	lock         sync.Mutex
	featureCache *Features

	// Shim for reading ioutil.ReadFile
	ReadFile func(name string) ([]byte, error)
	// Factory for making commands, used by UTs to shim exec.Command().
	NewCmd cmdFactory
}

func NewFeatureDetector() *FeatureDetector {
	return &FeatureDetector{
		ReadFile: ioutil.ReadFile,
		NewCmd:   newRealCmd,
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
	log.Debug("Refreshing detected iptables features")
	iptV := d.getIptablesVersion()
	kerV := d.getKernelVersion()

	// Calculate the features.
	features := Features{
		SNATFullyRandom:     iptV.Compare(v1Dot6Dot0) >= 0 && kerV.Compare(v3Dot14Dot0) >= 0,
		MASQFullyRandom:     iptV.Compare(v1Dot6Dot2) >= 0 && kerV.Compare(v3Dot14Dot0) >= 0,
		RestoreSupportsLock: iptV.Compare(v1Dot6Dot2) >= 0,
	}

	if d.featureCache == nil || *d.featureCache != features {
		log.WithField("features", features).Info("Updating detected iptables features")
		d.featureCache = &features
	}
}

func (d *FeatureDetector) getIptablesVersion() *version.Version {
	cmd := d.NewCmd("iptables", "--version")
	out, err := cmd.Output()
	if err != nil {
		log.WithError(err).Warn("Failed to get iptables version, assuming old version with no optional features")
		return v1Dot4Dot7
	}
	s := string(out)
	matches := vXDotYDotZRegexp.FindStringSubmatch(s)
	if len(matches) == 0 {
		log.WithField("rawVersion", s).Warn(
			"Failed to parse iptables version, assuming old version with no optional features")
		return v1Dot4Dot7
	}
	parsedVersion, err := version.NewVersion(matches[1])
	if err != nil {
		log.WithField("rawVersion", s).WithError(err).Warn(
			"Failed to parse iptables version, assuming old version with no optional features")
		return v1Dot4Dot7
	}
	return parsedVersion
}

func (d *FeatureDetector) getKernelVersion() *version.Version {
	kernVersion, err := d.ReadFile("/proc/version")
	if err != nil {
		log.WithError(err).Warn("Failed to get kernel version, assuming old version with no optional features")
		return v3Dot10Dot0
	}
	s := string(kernVersion)
	matches := kernelVersionRegexp.FindStringSubmatch(s)
	if len(matches) == 0 {
		log.WithField("rawVersion", s).Warn(
			"Failed to parse kernel version, assuming old version with no optional features")
		return v3Dot10Dot0
	}
	parsedVersion, err := version.NewVersion(matches[1])
	if err != nil {
		log.WithField("rawVersion", s).WithError(err).Warn(
			"Failed to parse kernel version, assuming old version with no optional features")
		return v3Dot10Dot0
	}
	return parsedVersion
}

func mustParseVersion(v string) *version.Version {
	ver, err := version.NewVersion(v)
	if err != nil {
		log.WithError(err).Panic("Failed to parse version.")
	}
	return ver
}
