// Copyright (c) 2018-2022 Tigera, Inc. All rights reserved.
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

package detector

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os/exec"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/iptables/cmdshim"
)

var (
	vXDotYDotZRegexp = regexp.MustCompile(`v(\d+\.\d+\.\d+)`)

	// iptables versions:
	// v1Dot4Dot7 is the oldest version we've ever supported.
	v1Dot4Dot7 = MustParseVersion("1.4.7")
	// v1Dot6Dot0 added --random-fully to SNAT.
	v1Dot6Dot0 = MustParseVersion("1.6.0")
	// v1Dot6Dot2 added --random-fully to MASQUERADE and the xtables lock to iptables-restore.
	v1Dot6Dot2 = MustParseVersion("1.6.2")

	// Linux kernel versions:
	// v3Dot10Dot0 is the oldest version we support at time of writing.
	v3Dot10Dot0 = MustParseVersion("3.10.0")
	// v3Dot14Dot0 added the random-fully feature on the iptables interface.
	v3Dot14Dot0 = MustParseVersion("3.14.0")
	// v5Dot7Dot0 contains a fix for checksum offloading.
	v5Dot7Dot0 = MustParseVersion("5.7.0")
	// v5Dot14Dot0 is the fist kernel version that IPIP tunnels acts like other L3
	// devices where bpf programs only see inner IP header. In RHEL based distros,
	// kernel 4.18.0 (v4Dot18Dot0_330) is the first one with this behavior.
	v5Dot14Dot0     = MustParseVersion("5.14.0")
	v4Dot18Dot0_330 = MustParseVersion("4.18.0-330")
)

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
	// on our VXLAN device.
	ChecksumOffloadBroken bool
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
	// Factory for making commands, used by iptables UTs to shim exec.Command().
	NewCmd cmdshim.CmdFactory
}

func NewFeatureDetector(overrides map[string]string) *FeatureDetector {
	return &FeatureDetector{
		GetKernelVersionReader: GetKernelVersionReader,
		NewCmd:                 cmdshim.NewRealCmd,
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
	log.Debug("Refreshing detected iptables features")

	iptV := d.getIptablesVersion()
	kerV := d.getKernelVersion()

	// Calculate the features.
	features := Features{
		SNATFullyRandom:       iptV.Compare(v1Dot6Dot0) >= 0 && kerV.Compare(v3Dot14Dot0) >= 0,
		MASQFullyRandom:       iptV.Compare(v1Dot6Dot2) >= 0 && kerV.Compare(v3Dot14Dot0) >= 0,
		RestoreSupportsLock:   iptV.Compare(v1Dot6Dot2) >= 0,
		ChecksumOffloadBroken: kerV.Compare(v5Dot7Dot0) < 0,
		IPIPDeviceIsL3:        d.ipipDeviceIsL3(),
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
			"features":        features,
			"kernelVersion":   kerV,
			"iptablesVersion": iptV,
		}).Info("Updating detected iptables features")
		d.featureCache = &features
	}
}

func (d *FeatureDetector) getIptablesVersion() *Version {
	cmd := d.NewCmd("iptables", "--version")
	out, err := cmd.Output()
	if err != nil {
		log.WithError(err).Warn("Failed to get iptables version, assuming old version with no optional features")
		return v1Dot4Dot7
	}
	s := string(out)
	log.WithField("rawVersion", s).Debug("Ran iptables --version")
	matches := vXDotYDotZRegexp.FindStringSubmatch(s)
	if len(matches) == 0 {
		log.WithField("rawVersion", s).Warn(
			"Failed to parse iptables version, assuming old version with no optional features")
		return v1Dot4Dot7
	}
	parsedVersion, err := NewVersion(matches[1])
	if err != nil {
		log.WithField("rawVersion", s).WithError(err).Warn(
			"Failed to parse iptables version, assuming old version with no optional features")
		return v1Dot4Dot7
	}
	log.WithField("version", parsedVersion).Debug("Parsed iptables version")
	return parsedVersion
}

func (d *FeatureDetector) getKernelVersion() *Version {
	reader, err := d.GetKernelVersionReader()
	if err != nil {
		log.WithError(err).Warn("Failed to get the kernel version reader, assuming old version with no optional features")
		return v3Dot10Dot0
	}
	kernVersion, err := GetKernelVersion(reader)
	if err != nil {
		log.WithError(err).Warn("Failed to get kernel version, assuming old version with no optional features")
		return v3Dot10Dot0
	}
	return kernVersion
}

func countRulesInIptableOutput(in []byte) int {
	count := 0
	for _, x := range bytes.Split(in, []byte("\n")) {
		if len(x) >= 1 && x[0] == '-' {
			count++
		}
	}
	return count
}

// GetIptablesBackend attempts to detect the iptables backend being used where Felix is running.
// This code is duplicating the detection method found at
// https://github.com/kubernetes/kubernetes/blob/623b6978866b5d3790d17ff13601ef9e7e4f4bf0/build/debian-iptables/iptables-wrapper#L28
// If there is a specifiedBackend then it is used but if it does not match the detected
// backend then a warning is logged.
func DetectBackend(lookPath func(file string) (string, error), newCmd cmdshim.CmdFactory, specifiedBackend string) string {
	ip6LgcySave := FindBestBinary(lookPath, 6, "legacy", "save")
	ip4LgcySave := FindBestBinary(lookPath, 4, "legacy", "save")
	ip6l, _ := newCmd(ip6LgcySave).Output()
	ip4l, _ := newCmd(ip4LgcySave).Output()
	log.WithField("ip6l", string(ip6l)).Debug("Ip6tables legacy save out")
	log.WithField("ip4l", string(ip4l)).Debug("Iptables legacy save out")
	legacyLines := countRulesInIptableOutput(ip6l) + countRulesInIptableOutput(ip4l)
	var detectedBackend string
	if legacyLines >= 10 {
		detectedBackend = "legacy"
	} else {
		ip6NftSave := FindBestBinary(lookPath, 6, "nft", "save")
		ip4NftSave := FindBestBinary(lookPath, 4, "nft", "save")
		ip6n, _ := newCmd(ip6NftSave).Output()
		log.WithField("ip6n", string(ip6n)).Debug("Ip6tables save out")
		ip4n, _ := newCmd(ip4NftSave).Output()
		log.WithField("ip4n", string(ip4n)).Debug("Iptables save out")
		nftLines := countRulesInIptableOutput(ip6n) + countRulesInIptableOutput(ip4n)
		if legacyLines >= nftLines {
			detectedBackend = "legacy"
		} else {
			detectedBackend = "nft"
		}
	}
	log.WithField("detectedBackend", detectedBackend).Debug("Detected Iptables backend")

	specifiedBackend = strings.ToLower(specifiedBackend)
	if specifiedBackend != "auto" {
		if specifiedBackend != detectedBackend {
			log.WithFields(log.Fields{"detectedBackend": detectedBackend, "specifiedBackend": specifiedBackend}).Warn("Iptables backend specified does not match the detected backend, using specified backend")
		}
		return specifiedBackend
	}
	return detectedBackend
}

// FindBestBinary tries to find an iptables binary for the specific variant (legacy/nftables mode) and returns the name
// of the binary.  Falls back on iptables-restore/iptables-save if the specific variant isn't available.
// Panics if no binary can be found.
func FindBestBinary(lookPath func(file string) (string, error), ipVersion uint8, backendMode, saveOrRestore string) string {
	if lookPath == nil {
		lookPath = exec.LookPath
	}
	verInfix := ""
	if ipVersion == 6 {
		verInfix = "6"
	}
	candidates := []string{
		"ip" + verInfix + "tables-" + backendMode + "-" + saveOrRestore,
		"ip" + verInfix + "tables-" + saveOrRestore,
	}

	logCxt := log.WithFields(log.Fields{
		"ipVersion":     ipVersion,
		"backendMode":   backendMode,
		"saveOrRestore": saveOrRestore,
		"candidates":    candidates,
	})

	for _, candidate := range candidates {
		_, err := lookPath(candidate)
		if err == nil {
			logCxt.WithField("command", candidate).Info("Looked up iptables command")
			return candidate
		}
	}

	logCxt.Panic("Failed to find iptables command")
	return ""
}

func (d *FeatureDetector) isAtLeastKernel(v *Version) error {
	versionReader, err := d.GetKernelVersionReader()
	if err != nil {
		return fmt.Errorf("failed to get kernel version reader: %v", err)
	}

	kernelVersion, err := GetKernelVersion(versionReader)
	if err != nil {
		return fmt.Errorf("failed to get kernel version: %v", err)
	}

	if kernelVersion.Compare(v) < 0 {
		return fmt.Errorf("kernel is too old (have: %v but want at least: %v)", kernelVersion, v)
	}

	return nil
}

func (d *FeatureDetector) getDistributionName() string {
	versionReader, err := d.GetKernelVersionReader()
	if err != nil {
		log.Errorf("failed to get kernel version reader: %v", err)
		return DefaultDistro
	}

	kernVersion, err := ioutil.ReadAll(versionReader)
	if err != nil {
		log.WithError(err).Warn("Failed to read kernel version from reader")
		return DefaultDistro
	}
	return GetDistFromString(string(kernVersion))
}

func (d *FeatureDetector) ipipDeviceIsL3() bool {
	switch d.getDistributionName() {
	case RedHat:
		if err := d.isAtLeastKernel(v4Dot18Dot0_330); err != nil {
			return false
		}
		return true
	default:
		if err := d.isAtLeastKernel(v5Dot14Dot0); err != nil {
			return false
		}
		return true
	}
}
