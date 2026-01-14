// Copyright (c) 2020-2025 Tigera, Inc. All rights reserved.
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

package tc

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path"
	"strings"
	"sync"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/bpf/bpfdefs"
	"github.com/projectcalico/calico/felix/bpf/hook"
	"github.com/projectcalico/calico/felix/bpf/libbpf"
	"github.com/projectcalico/calico/felix/bpf/maps"
	tcdefs "github.com/projectcalico/calico/felix/bpf/tc/defs"
	"github.com/projectcalico/calico/felix/dataplane/linux/qos"
)

type AttachPoint struct {
	bpf.AttachPoint

	LogFilter                   string
	LogFilterIdx                int
	Type                        tcdefs.EndpointType
	ToOrFrom                    tcdefs.ToOrFromEp
	HookLayoutV4                hook.Layout
	HookLayoutV6                hook.Layout
	HostIPv4                    net.IP
	HostIPv6                    net.IP
	HostTunnelIPv4              net.IP
	HostTunnelIPv6              net.IP
	IntfIPv4                    net.IP
	IntfIPv6                    net.IP
	ToHostDrop                  bool
	DSR                         bool
	DSROptoutCIDRs              bool
	SkipEgressRedirect          bool
	TunnelMTU                   uint16
	VXLANPort                   uint16
	WgPort                      uint16
	Wg6Port                     uint16
	ExtToServiceConnmark        uint32
	PSNATStart                  uint16
	PSNATEnd                    uint16
	RPFEnforceOption            uint8
	NATin                       uint32
	NATout                      uint32
	NATOutgoingExcludeHosts     bool
	UDPOnly                     bool
	RedirectPeer                bool
	FlowLogsEnabled             bool
	OverlayTunnelID             uint32
	AttachType                  apiv3.BPFAttachOption
	IngressPacketRateConfigured bool
	EgressPacketRateConfigured  bool
	DSCP                        int8
	MaglevLUTSize               uint32
	ProgramsMap                 maps.Map
}

var ErrDeviceNotFound = errors.New("device not found")
var ErrInterrupted = errors.New("dump interrupted")

func (ap *AttachPoint) Log() *log.Entry {
	return log.WithFields(log.Fields{
		"iface": ap.Iface,
		"type":  ap.Type,
		"hook":  ap.Hook,
	})
}

func (ap *AttachPoint) loadObject(file string, configurator bpf.ObjectConfigurator) (*libbpf.Obj, error) {
	obj, err := bpf.LoadObjectWithOptions(file, ap.Configure(), configurator)
	if err != nil {
		return nil, fmt.Errorf("error loading %s: %w", file, err)
	}
	return obj, nil
}

func (ap *AttachPoint) attachTCXProgram(binaryToLoad string) error {
	logCxt := log.WithField("attachPoint", ap)
	obj, err := ap.loadObject(binaryToLoad, func(obj *libbpf.Obj) error {
		attachType := libbpf.AttachTypeTcxEgress
		if ap.Hook == hook.Ingress {
			attachType = libbpf.AttachTypeTcxIngress
		}
		return obj.SetAttachType("cali_tc_preamble", attachType)
	})
	if err != nil {
		logCxt.Warn("Failed to load program")
		return fmt.Errorf("object %w", err)
	}
	defer obj.Close()
	progPinPath := ap.ProgPinPath()
	if _, err := os.Stat(progPinPath); err == nil {
		link, err := libbpf.OpenLink(progPinPath)
		if err != nil {
			return fmt.Errorf("error opening link %s : %w", progPinPath, err)
		}
		defer link.Close()
		if err := link.Update(obj, "cali_tc_preamble"); err != nil {
			if errors.Is(err, unix.ENOLINK) {
				// The link was deleted out from under us, so try attaching a new one.
				logCxt.Debug("Link severed from interface, re-attaching")
				os.Remove(progPinPath)
				goto attachNew
			}
			return fmt.Errorf("error updating program %s : %w", progPinPath, err)
		}
		return nil
	}
attachNew:
	link, err := obj.AttachTCX("cali_tc_preamble", ap.Iface)
	if err != nil {
		return err
	}
	defer link.Close()
	err = link.Pin(progPinPath)
	if err != nil {
		return fmt.Errorf("error pinning link %w", err)
	}
	return nil
}

// AttachProgram attaches a BPF program from a file to the TC attach point
func (ap *AttachPoint) AttachProgram() error {
	logCxt := log.WithField("attachPoint", ap)
	// By now the attach type specific generic set of programs is loaded and we
	// only need to load and configure the preamble that will pass the
	// configuration further to the selected set of programs.

	binaryToLoad := path.Join(bpfdefs.ObjectDir, fmt.Sprintf("tc_preamble_%s.o", ap.Hook))
	if ap.AttachType == apiv3.BPFAttachOptionTCX {
		err := ap.attachTCXProgram(binaryToLoad)
		if err != nil {
			return fmt.Errorf("error attaching tcx program %s:%s:%w", ap.Iface, ap.Hook, err)
		}
		// Remove the clsact qdisc so that it removes any existing tc programs from the previous runs.
		err = RemoveQdisc(ap.Iface)
		if err != nil {
			log.Errorf("error removing qdisc from %s:%s", ap.Iface, err)
		}
		logCxt.Info("Program attached to tcx.")
		return nil
	}

	/* XXX we should remember the tag of the program and skip the rest if the tag is
	* still the same */
	progsAttached, err := ListAttachedPrograms(ap.Iface, ap.Hook.String(), true)
	if err != nil {
		return err
	}

	prio, handle := findFilterPriority(progsAttached)
	obj, err := ap.loadObject(binaryToLoad, nil)
	if err != nil {
		logCxt.Warn("Failed to load program")
		return fmt.Errorf("object %w", err)
	}
	defer obj.Close()

	err = obj.AttachClassifier("cali_tc_preamble", ap.Iface, ap.Hook == hook.Ingress, prio, handle)
	if err != nil {
		logCxt.Warnf("Failed to attach to TC section cali_tc_preamble")
		return err
	}
	logCxt.Info("Program attached to tc.")
	// Remove any tcx program.
	if _, err := os.Stat(ap.ProgPinPath()); err == nil {
		logCxt.Info("Removing any existing tcx program")
		err = ap.detachTcxProgram()
		if err != nil {
			logCxt.Warnf("error removing tcx program from %s", err)
		}
	}
	return nil
}

func (ap *AttachPoint) ProgPinPath() string {
	return path.Join(bpfdefs.TcxPinDir, fmt.Sprintf("%s_%s", strings.ReplaceAll(ap.Iface, ".", ""), ap.Hook))
}

func (ap *AttachPoint) detachTcxProgram() error {
	progPinPath := ap.ProgPinPath()
	defer os.Remove(progPinPath)
	link, err := libbpf.OpenLink(progPinPath)
	if err != nil {
		return fmt.Errorf("error opening link %s:%w", progPinPath, err)
	}
	defer link.Close()
	err = link.Detach()
	if err != nil {
		return fmt.Errorf("error detaching link %s:%w", progPinPath, err)
	}
	return nil
}

func (ap *AttachPoint) detachTcProgram() error {
	progsToClean, err := ListAttachedPrograms(ap.Iface, ap.Hook.String(), true)
	if err != nil {
		return err
	}
	return ap.detachPrograms(progsToClean)
}

func (ap *AttachPoint) DetachProgram() error {
	err := ap.detachTcxProgram()
	if err != nil {
		log.Warnf("error detaching tcx program from %s hook %s : %s", ap.Iface, ap.Hook, err)
	}
	err = ap.detachTcProgram()
	if err != nil {
		log.Warnf("error detaching tc program from %s hook %s : %s", ap.Iface, ap.Hook, err)
	}
	return nil
}

func (ap *AttachPoint) detachPrograms(progsToClean []attachedProg) error {
	var progErrs []error
	for _, p := range progsToClean {
		log.WithField("prog", p).Debug("Cleaning up old calico program")
		attemptCleanup := func() error {
			if p.Filter == nil {
				return fmt.Errorf("calico program %+v: Filter is 'nil'", p)
			}
			err := netlink.FilterDel(*p.Filter)
			return err
		}
		err := attemptCleanup()
		if errors.Is(err, ErrInterrupted) {
			// This happens if the interface is deleted in the middle of deleting the filter.
			log.Debug("First cleanup hit 'Dump was interrupted', retrying (once).")
			err = attemptCleanup()
		}
		if errors.Is(err, ErrDeviceNotFound) {
			continue
		}
		if err != nil {
			log.WithError(err).WithField("prog", p).Warn("Failed to clean up old calico program.")
			progErrs = append(progErrs, err)
		}
	}

	if len(progErrs) != 0 {
		return fmt.Errorf("failed to clean up one or more old calico programs: %v", progErrs)
	}

	return nil
}

type attachedProg struct {
	Pref   int
	Handle uint32
	Filter *netlink.Filter
}

func ListAttachedTcxPrograms(iface, attachHook string) ([]string, error) {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return nil, fmt.Errorf("error getting link for %s:%w", iface, err)
	}
	progId, _, progCnt, err := libbpf.ProgQueryTcx(link.Attrs().Index, attachHook == hook.Ingress.String())
	if err != nil {
		return nil, fmt.Errorf("error querying program for %s:%s:%w", iface, attachHook, err)
	}
	progNames := []string{}
	for i := range progCnt {
		name, err := libbpf.ProgName(progId[i])
		if err != nil {
			continue
		}
		progNames = append(progNames, name)
	}
	return progNames, nil
}

func ListAttachedPrograms(iface, hook string, includeLegacy bool) ([]attachedProg, error) {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return nil, fmt.Errorf("failed to get host device %s: %w", iface, err)
	}
	var parent uint32
	switch hook {
	case "ingress":
		parent = netlink.HANDLE_MIN_INGRESS
	case "egress":
		parent = netlink.HANDLE_MIN_EGRESS
	default:
		return nil, fmt.Errorf("failed to parse hook '%s'", hook)
	}
	filters, err := netlink.FilterList(link, parent)
	if err != nil {
		return nil, fmt.Errorf("failed to list filters on dev %s: %w", iface, err)
	}
	var progsAttached []attachedProg
	for _, filter := range filters {
		bpfFilter, ok := filter.(*netlink.BpfFilter)
		if !ok {
			continue
		}
		if strings.Contains(bpfFilter.Name, "cali_tc_preambl") || (includeLegacy && strings.Contains(bpfFilter.Name, "calico")) {
			p := attachedProg{
				Pref:   int(bpfFilter.Attrs().Priority),
				Handle: bpfFilter.Attrs().Handle,
				Filter: &filter,
			}
			log.WithField("prog", p).Debug("Found old calico program")
			progsAttached = append(progsAttached, p)
		}
	}

	return progsAttached, nil
}

// ProgramName returns the name of the program associated with this AttachPoint
func (ap *AttachPoint) ProgramName() string {
	return tcdefs.SectionName(ap.Type, ap.ToOrFrom)
}

// EnsureQdisc makes sure that qdisc is attached to the given interface
func EnsureQdisc(ifaceName string) (bool, error) {
	hasQdisc, err := HasQdisc(ifaceName)
	if err != nil {
		return false, err
	}
	if hasQdisc {
		log.WithField("iface", ifaceName).Debug("Already have a clsact qdisc on this interface")
		return true, nil
	}

	// Clean up QoS config as it is currently not suppored by the BPF dataplane
	// and should be removed when transitioning from iptables or nftables to BPF.
	var errs []error
	err = qos.RemoveIngressQdisc(ifaceName)
	if err != nil {
		errs = append(errs, fmt.Errorf("error removing QoS ingress qdisc from interface %s: %w", ifaceName, err))
	}
	err = qos.RemoveEgressQdisc(ifaceName)
	if err != nil {
		errs = append(errs, fmt.Errorf("error removing QoS egress qdisc from interface %s: %w", ifaceName, err))
	}

	err = libbpf.CreateQDisc(ifaceName)
	if err != nil {
		errs = append(errs, fmt.Errorf("error creating qdisc on interface %s: %w", ifaceName, err))
	}

	return false, errors.Join(errs...)
}

func HasQdisc(ifaceName string) (bool, error) {
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return false, fmt.Errorf("failed to get link for interface '%s': %w", ifaceName, err)
	}

	qdiscs, err := netlink.QdiscList(link)
	if err != nil {
		return false, fmt.Errorf("failed to list qdiscs for interface '%s': %w", ifaceName, err)
	}

	for _, qdisc := range qdiscs {
		_, isClsact := qdisc.(*netlink.Clsact)
		if isClsact {
			return true, nil
		}
	}

	return false, nil
}

// RemoveQdisc makes sure that there is no qdisc attached to the given interface
func RemoveQdisc(ifaceName string) error {
	hasQdisc, err := HasQdisc(ifaceName)
	if err != nil {
		return err
	}
	if !hasQdisc {
		return nil
	}
	return libbpf.RemoveQDisc(ifaceName)
}

func findFilterPriority(progsToClean []attachedProg) (int, uint32) {
	prio := 0
	handle := uint32(0)
	for _, p := range progsToClean {
		if p.Pref > prio {
			prio = p.Pref
			handle = p.Handle
		}
	}
	return prio, handle
}

func (ap *AttachPoint) Config() string {
	return fmt.Sprintf("%+v", ap)
}

func (ap *AttachPoint) Configure() *libbpf.TcGlobalData {
	globalData := &libbpf.TcGlobalData{
		ExtToSvcMark:  ap.ExtToServiceConnmark,
		VxlanPort:     ap.VXLANPort,
		Tmtu:          ap.TunnelMTU,
		PSNatStart:    ap.PSNATStart,
		PSNatLen:      ap.PSNATEnd,
		WgPort:        ap.WgPort,
		Wg6Port:       ap.Wg6Port,
		NatIn:         ap.NATin,
		NatOut:        ap.NATout,
		LogFilterJmp:  uint32(ap.LogFilterIdx),
		DSCP:          ap.DSCP,
		MaglevLUTSize: ap.MaglevLUTSize,
	}

	if ap.Profiling == "Enabled" {
		globalData.Profiling = 1
	}

	copy(globalData.HostIPv4[0:4], ap.HostIPv4.To4())
	copy(globalData.HostIPv6[:], ap.HostIPv6.To16())

	copy(globalData.IntfIPv4[0:4], ap.IntfIPv4.To4())
	copy(globalData.IntfIPv6[:], ap.IntfIPv6.To16())

	if globalData.VxlanPort == 0 {
		globalData.VxlanPort = 4789
	}

	if ap.DSROptoutCIDRs {
		globalData.Flags |= libbpf.GlobalsNoDSRCidrs
	}

	if ap.SkipEgressRedirect {
		globalData.Flags |= libbpf.GlobalsSkipEgressRedirect
	}

	if ap.IngressPacketRateConfigured {
		globalData.Flags |= libbpf.GlobalsIngressPacketRateConfigured
	}

	if ap.EgressPacketRateConfigured {
		globalData.Flags |= libbpf.GlobalsEgressPacketRateConfigured
	}

	switch ap.RPFEnforceOption {
	case tcdefs.RPFEnforceOptionStrict:
		globalData.Flags |= libbpf.GlobalsRPFOptionEnabled
		globalData.Flags |= libbpf.GlobalsRPFOptionStrict
	case tcdefs.RPFEnforceOptionLoose:
		globalData.Flags |= libbpf.GlobalsRPFOptionEnabled
	}

	if ap.UDPOnly {
		globalData.Flags |= libbpf.GlobalsLoUDPOnly
	}

	if ap.RedirectPeer {
		globalData.Flags |= libbpf.GlobalsRedirectPeer
	}

	if ap.FlowLogsEnabled {
		globalData.Flags |= libbpf.GlobalsFlowLogsEnabled
	}

	if ap.NATOutgoingExcludeHosts {
		globalData.Flags |= libbpf.GlobalsNATOutgoingExcludeHosts
	}

	globalData.HostTunnelIPv4 = globalData.HostIPv4
	globalData.HostTunnelIPv6 = globalData.HostIPv6

	copy(globalData.HostTunnelIPv4[0:4], ap.HostTunnelIPv4.To4())
	copy(globalData.HostTunnelIPv6[:], ap.HostTunnelIPv6.To16())

	for i := 0; i < len(globalData.Jumps); i++ {
		globalData.Jumps[i] = 0xffffffff   /* uint32(-1) */
		globalData.JumpsV6[i] = 0xffffffff /* uint32(-1) */
	}

	if ap.HookLayoutV4 != nil {
		log.WithField("HookLayout", ap.HookLayoutV4).Debugf("Configure")
		for p, i := range ap.HookLayoutV4 {
			globalData.Jumps[p] = uint32(i)
		}
		globalData.Jumps[tcdefs.ProgIndexPolicy] = uint32(ap.PolicyIdxV4)
	}

	if ap.HookLayoutV6 != nil {
		log.WithField("HookLayout", ap.HookLayoutV6).Debugf("Configure")
		for p, i := range ap.HookLayoutV6 {
			globalData.JumpsV6[p] = uint32(i)
		}
		globalData.JumpsV6[tcdefs.ProgIndexPolicy] = uint32(ap.PolicyIdxV6)
	}

	in := []byte("---------------")
	copy(in, ap.Iface)
	globalData.IfaceName = string(in)

	return globalData
}

var IsTcxSupported = sync.OnceValue(func() bool {
	name := "testTcx"
	la := netlink.NewLinkAttrs()
	la.Name = name
	la.Flags = net.FlagUp
	var veth netlink.Link = &netlink.Veth{
		LinkAttrs: la,
		PeerName:  name + "b",
	}
	err := netlink.LinkAdd(veth)
	if err != nil {
		return false
	}

	defer func() {
		if err := netlink.LinkDel(veth); err != nil {
			log.Warnf("failed delete veth interface testTcx %s", err)
		}
	}()

	binaryToLoad := path.Join(bpfdefs.ObjectDir, "tcx_test.o")
	obj, err := bpf.LoadObject(binaryToLoad, &libbpf.TcGlobalData{})
	if err != nil {
		return false
	}
	defer obj.Close()
	_, err = obj.AttachTCX("cali_tcx_test", name)
	return err == nil
})
