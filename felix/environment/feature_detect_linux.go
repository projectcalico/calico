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

package environment

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/projectcalico/calico/felix/netlinkshim"

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

type FeatureDetector struct {
	featureDetectorCommon

	lock            sync.Mutex
	featureCache    *Features
	featureOverride map[string]string
	loggedOverrides bool

	// Path to file with kernel version
	GetKernelVersionReader func() (io.Reader, error)
	// Factory for making commands, used by iptables UTs to shim exec.Command().
	NewCmd cmdshim.CmdFactory

	newNetlinkHandle            func() (netlinkshim.Interface, error)
	cachedNetlinkSupportsStrict *bool
}

type Option func(detector *FeatureDetector)

func WithNetlinkOverride(f func() (netlinkshim.Interface, error)) Option {
	return func(detector *FeatureDetector) {
		detector.newNetlinkHandle = f
	}
}

func NewFeatureDetector(overrides map[string]string, opts ...Option) *FeatureDetector {
	fd := &FeatureDetector{
		GetKernelVersionReader: GetKernelVersionReader,
		NewCmd:                 cmdshim.NewRealCmd,
		featureOverride:        overrides,
		newNetlinkHandle:       netlinkshim.NewRealNetlink,
	}
	for _, opt := range opts {
		opt(fd)
	}
	return fd
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

	netlinkSupportsStrict, err := d.netlinkSupportsStrict()
	if err != nil {
		log.WithError(err).Panic("Failed to do netlink feature detection.")
	}

	// Calculate the features.
	features := Features{
		SNATFullyRandom:          iptV.Compare(v1Dot6Dot0) >= 0 && kerV.Compare(v3Dot14Dot0) >= 0,
		MASQFullyRandom:          iptV.Compare(v1Dot6Dot2) >= 0 && kerV.Compare(v3Dot14Dot0) >= 0,
		RestoreSupportsLock:      iptV.Compare(v1Dot6Dot2) >= 0,
		ChecksumOffloadBroken:    kerV.Compare(v5Dot7Dot0) <= 0,
		IPIPDeviceIsL3:           d.ipipDeviceIsL3(),
		KernelSideRouteFiltering: netlinkSupportsStrict,
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

func (d *FeatureDetector) kernelIsAtLeast(v *Version) (bool, *Version, error) {
	versionReader, err := d.GetKernelVersionReader()
	if err != nil {
		return false, nil, fmt.Errorf("failed to get kernel version reader: %w", err)
	}

	kernelVersion, err := GetKernelVersion(versionReader)
	if err != nil {
		return false, nil, fmt.Errorf("failed to get kernel version: %w", err)
	}

	return kernelVersion.Compare(v) >= 0, kernelVersion, nil
}

// KernelIsAtLeast returns whether the predicate is true or not and an error in
// case it was not able to determine it.
func (d *FeatureDetector) KernelIsAtLeast(v string) (bool, error) {
	ver, err := NewVersion(v)
	if err != nil {
		return false, fmt.Errorf("failed to parse kernel version: %w", err)
	}

	ok, _, err := d.kernelIsAtLeast(ver)

	return ok, err
}

func (d *FeatureDetector) isAtLeastKernel(v *Version) error {
	ok, kernelVersion, err := d.kernelIsAtLeast(v)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("kernel is too old (have: %s but want at least: %s)", kernelVersion, v)
	}

	return nil
}

func (d *FeatureDetector) getDistributionName() string {
	versionReader, err := d.GetKernelVersionReader()
	if err != nil {
		log.Errorf("failed to get kernel version reader: %v", err)
		return DefaultDistro
	}

	kernVersion, err := io.ReadAll(versionReader)
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

func (d *FeatureDetector) netlinkSupportsStrict() (bool, error) {
	if d.cachedNetlinkSupportsStrict != nil {
		return *d.cachedNetlinkSupportsStrict, nil
	}
	h, err := d.newNetlinkHandle()
	if err != nil {
		return false, fmt.Errorf("failed to open netlink handle to check supported features: %w", err)
	}
	defer h.Delete()
	err = h.SetStrictCheck(true)
	if err == nil {
		log.Debug("Kernel support strict netlink mode")
		result := true
		d.cachedNetlinkSupportsStrict = &result
		return result, nil
	} else if errors.Is(err, unix.ENOPROTOOPT) {
		// Expected on older kernels with no support.
		log.Debug("Kernel does not support strict netlink mode")
		result := false
		d.cachedNetlinkSupportsStrict = &result
		return result, nil
	}
	log.WithError(err).Warn("Kernel returned unexpected error when trying to detect if " +
		"netlink supports strict mode.  Assuming no support (this may result in higher CPU usage).")
	return false, nil
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

// hasKubernetesChains tries to find in the output of the binary if the Kubernetes
// chains exists
func hasKubernetesChains(output []byte) bool {
	return strings.Contains(string(output), "KUBE-IPTABLES-HINT") || strings.Contains(string(output), "KUBE-KUBELET-CANARY")
}

// GetIptablesBackend attempts to detect the iptables backend being used where Felix is running.
// This code is duplicating the detection method found at
// https://github.com/kubernetes-sigs/iptables-wrappers/blob/master/iptables-wrapper-installer.sh#L107
// If there is a specifiedBackend then it is used but if it does not match the detected
// backend then a warning is logged.
func DetectBackend(lookPath func(file string) (string, error), newCmd cmdshim.CmdFactory, specifiedBackend string) string {
	ip6NftSave := FindBestBinary(lookPath, 6, "nft", "save")
	ip4NftSave := FindBestBinary(lookPath, 4, "nft", "save")

	ip6nm, _ := newCmd(ip6NftSave, "-t", "mangle").Output()
	log.WithField("ip6n", string(ip6nm)).Debug("Ip6tables save out")
	ip4nm, _ := newCmd(ip4NftSave, "-t", "mangle").Output()
	log.WithField("ip4n", string(ip4nm)).Debug("Iptables save out")

	var detectedBackend string
	if hasKubernetesChains(ip6nm) || hasKubernetesChains(ip4nm) {
		detectedBackend = "nft"
	} else {
		ip6LgcySave := FindBestBinary(lookPath, 6, "legacy", "save")
		ip4LgcySave := FindBestBinary(lookPath, 4, "legacy", "save")
		ip6lm, _ := newCmd(ip6LgcySave, "-t", "mangle").Output()
		log.WithField("ip6l", string(ip6lm)).Debug("Ip6tables legacy save -t mangle out")
		ip4lm, _ := newCmd(ip4LgcySave, "-t", "mangle").Output()
		log.WithField("ip4l", string(ip4lm)).Debug("Iptables legacy save -t mangle out")

		if hasKubernetesChains(ip6lm) || hasKubernetesChains(ip4lm) {
			detectedBackend = "legacy"
		} else {
			ip6l, _ := newCmd(ip6LgcySave).Output()
			log.WithField("ip6l", string(ip6l)).Debug("Ip6tables legacy save out")
			ip4l, _ := newCmd(ip4LgcySave).Output()
			log.WithField("ip4l", string(ip4l)).Debug("Iptables legacy save out")
			legacyLines := countRulesInIptableOutput(ip6l) + countRulesInIptableOutput(ip4l)

			ip6n, _ := newCmd(ip6NftSave).Output()
			log.WithField("ip6n", string(ip6n)).Debug("Ip6tables save out")
			ip4n, _ := newCmd(ip4NftSave).Output()
			log.WithField("ip4n", string(ip4n)).Debug("Iptables save out")
			nftLines := countRulesInIptableOutput(ip6n) + countRulesInIptableOutput(ip4n)
			if legacyLines >= nftLines {
				detectedBackend = "legacy" // default to legacy mode
			} else {
				detectedBackend = "nft"
			}
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

type FakeFeatureDetector struct {
	Features
}

func (f *FakeFeatureDetector) FeatureGate(name string) string {
	return ""
}

func (f *FakeFeatureDetector) RefreshFeatures() {
}

func (f *FakeFeatureDetector) GetFeatures() *Features {
	cp := f.Features
	return &cp
}

var _ FeatureDetectorIface = (*FakeFeatureDetector)(nil)
