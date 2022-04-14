// Copyright (c) 2019-2022 Tigera, Inc. All rights reserved.

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

// Test can simply be run with:
// sudo -E go test -v ./bpf/ -count=1

package bpf

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"testing"

	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/logutils"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/detector"
	"github.com/projectcalico/calico/felix/labelindex"
)

var (
	bpfDP BPFDataplane
)

func cleanup(calicoDir string) error {
	if calicoDir != "" {
		os.RemoveAll(calicoDir)
	}

	if err := maybeDeleteIface("test_A"); err != nil {
		return fmt.Errorf("%v", err)
	}
	if err := maybeDeleteIface("test_C"); err != nil {
		return fmt.Errorf("%v", err)
	}
	if err := maybeDeleteIface("test_E"); err != nil {
		return fmt.Errorf("%v", err)
	}
	return nil
}

func setup() {
	logutils.ConfigureEarlyLogging()
	log.SetLevel(log.DebugLevel)

	_ = cleanup("")

	bpfCalicoSubdir = "calico_test"
	log.SetLevel(log.DebugLevel)

	root := os.Geteuid() == 0
	xdp := SupportsXDP() == nil
	_, err := exec.LookPath("bpftool")
	hasBPFtool := err == nil

	forceRealLib := os.Getenv("BPF_FORCE_REAL_LIB")

	if forceRealLib != "" || (root && xdp && hasBPFtool) {
		log.Info("Running with real BPF lib")
		bpfDP, _ = NewBPFLib("../bpf-apache/bin/")
	} else {
		log.WithFields(log.Fields{"root": root, "xdp": xdp, "hasbpftool": hasBPFtool}).Info("Running with mock BPF lib")
		bpfDP = NewMockBPFLib("../bpf-apache/bin/")
	}
	wd, _ := os.Getwd()
	log.Info("Current directory: ", wd)
}

func TestMain(m *testing.M) {
	setup()
	retCode := m.Run()
	_ = cleanup(bpfDP.GetBPFCalicoDir())
	os.Exit(retCode)
}

func TestCreateCIDRMap(t *testing.T) {
	t.Log("Creating a map should be possible")
	_, err := bpfDP.NewCIDRMap("myiface1", IPFamilyV4)
	if err != nil {
		t.Fatalf("cannot create map: %v", err)
	}
}

func TestValidMap(t *testing.T) {
	t.Log("A non-existent map should not be valid")
	v, err := bpfDP.IsValidMap("valid1", IPFamilyV4)
	if err == nil || v {
		t.Fatalf("checking map validity should have failed: v=%v err=%v", v, err)
	}

	_, err = bpfDP.NewCIDRMap("valid1", IPFamilyV4)
	if err != nil {
		t.Fatalf("cannot create map: %v", err)
	}

	t.Log("A created map should be valid")
	v, err = bpfDP.IsValidMap("valid1", IPFamilyV4)
	if err != nil {
		t.Fatalf("cannot check map validity: %v", err)
	}
	if !v {
		t.Fatalf("map should have been valid")
	}

	err = bpfDP.RemoveCIDRMap("valid1", IPFamilyV4)
	if err != nil {
		t.Fatalf("cannot delete map: %v", err)
	}

	t.Log("After removing a map, it should not be valid")
	v, err = bpfDP.IsValidMap("valid1", IPFamilyV4)
	if err == nil || v {
		t.Fatalf("checking map validity should have failed: v=%v err=%v", v, err)
	}
}

func TestRemoveCIDRMap(t *testing.T) {
	_, err := bpfDP.NewCIDRMap("foo1", IPFamilyV4)
	if err != nil {
		t.Fatalf("cannot create map: %v", err)
	}

	t.Log("Removing a map should succeed")
	err = bpfDP.RemoveCIDRMap("foo1", IPFamilyV4)
	if err != nil {
		t.Fatalf("cannot delete map: %v", err)
	}

	t.Log("Removing an already removed map should fail")
	err = bpfDP.RemoveCIDRMap("foo1", IPFamilyV4)
	if err == nil {
		t.Fatalf("deleting already deleted map should have failed: %v", err)
	}

	t.Log("Removing a non-existent map should fail")
	err = bpfDP.RemoveCIDRMap("none1", IPFamilyV4)
	if err == nil {
		t.Fatalf("map deletion should have failed: %v", err)
	}
}

func strSliceContains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func TestListCIDRMap(t *testing.T) {
	_, err := bpfDP.NewCIDRMap("foo1", IPFamilyV4)
	if err != nil {
		t.Fatalf("cannot create map: %v", err)
	}
	_, err = bpfDP.NewCIDRMap("foo2", IPFamilyV4)
	if err != nil {
		t.Fatalf("cannot create map: %v", err)
	}
	_, err = bpfDP.NewCIDRMap("foo3", IPFamilyV4)
	if err != nil {
		t.Fatalf("cannot create map: %v", err)
	}
	err = bpfDP.RemoveCIDRMap("foo3", IPFamilyV4)
	if err != nil {
		t.Fatalf("cannot delete map: %v", err)
	}

	t.Log("After creating a few CIDR maps, they should appear when listing CIDR maps")
	arr, err := bpfDP.ListCIDRMaps(IPFamilyV4)
	if err != nil {
		t.Fatalf("cannot list map: %v", err)
	}
	if !strSliceContains(arr, "foo1") {
		t.Fatalf("map list should contain foo1: %v", arr)
	}
	if !strSliceContains(arr, "foo2") {
		t.Fatalf("map list should contain foo2: %v", arr)
	}
	if strSliceContains(arr, "foo3") {
		t.Fatalf("map list should NOT contain foo3: %v", arr)
	}

	err = bpfDP.RemoveCIDRMap("foo1", IPFamilyV4)
	if err != nil {
		t.Fatalf("cannot delete map: %v", err)
	}
	err = bpfDP.RemoveCIDRMap("foo2", IPFamilyV4)
	if err != nil {
		t.Fatalf("cannot delete map: %v", err)
	}
}

func TestCIDRMapContent(t *testing.T) {
	_, err := bpfDP.NewCIDRMap("foo1", IPFamilyV4)
	if err != nil {
		t.Fatalf("cannot create map: %v", err)
	}

	ip := net.ParseIP("192.2.0.0")
	ip2 := net.ParseIP("127.0.0.0")
	ip3 := net.ParseIP("5.6.7.8")
	ip3test := net.ParseIP("5.6.7.42")
	ipWrong := net.ParseIP("8.8.8.8")
	mask := 16
	mask2 := 32
	mask3 := 24

	t.Log("Looking up a value that wasn't added to the CIDR map should fail")
	_, err = bpfDP.LookupCIDRMap("foo1", IPFamilyV4, ip, mask)
	if err == nil {
		t.Fatalf("lookup should have failed")
	}

	err = bpfDP.UpdateCIDRMap("foo1", IPFamilyV4, ip, mask, 51)
	if err != nil {
		t.Fatalf("cannot update map: %v", err)
	}
	err = bpfDP.UpdateCIDRMap("foo1", IPFamilyV4, ip2, mask, 52)
	if err != nil {
		t.Fatalf("cannot update map: %v", err)
	}
	err = bpfDP.UpdateCIDRMap("foo1", IPFamilyV4, ip3, mask3, 53)
	if err != nil {
		t.Fatalf("cannot update map: %v", err)
	}

	t.Log("Dumping a CIDR map should return expected entries")
	foo1Contents, err := bpfDP.DumpCIDRMap("foo1", IPFamilyV4)
	if err != nil {
		t.Fatalf("cannot dump map: %v", err)
	}
	if len(foo1Contents) != 3 {
		t.Fatalf("invalid contents of the map: %v", foo1Contents)
	}
	visited := make(map[uint32]struct{}, len(foo1Contents))
	for ipmask, value := range foo1Contents {
		var wantedIP net.IP
		var wantedMask int
		if _, ok := visited[value]; ok {
			t.Fatalf("expected only one value %v in the map", value)
		}
		switch value {
		case 51:
			wantedIP = ip
			wantedMask = mask
		case 52:
			wantedIP = ip2
			wantedMask = mask
		case 53:
			wantedIP = ip3
			wantedMask = mask3
		default:
			t.Fatalf("Invalid value in the map: %v", value)
		}
		netip := ipmask.ToIPNet()
		comp := bytes.Compare(netip.IP.To16(), wantedIP.To16())
		if comp != 0 {
			t.Fatalf("Invalid ip %v, expected %v", netip.IP, wantedIP)
		}
		ones, _ := netip.Mask.Size()
		if ones != wantedMask {
			t.Fatalf("Invalid mask %v, wanted %v", netip.Mask, wantedMask)
		}
		visited[value] = struct{}{}
	}

	t.Log("Removing a non-existent element of a CIDR map should fail")
	err = bpfDP.RemoveItemCIDRMap("foo1", IPFamilyV4, ipWrong, mask2)
	if err == nil {
		t.Fatalf("remove item from map should have failed")
	}

	t.Log("Looking up an existent element on a CIDR map should succeed and return the right value")
	v, err := bpfDP.LookupCIDRMap("foo1", IPFamilyV4, ip, mask)
	if err != nil {
		t.Fatalf("cannot lookup map: %v", err)
	}
	if v != 51 {
		t.Fatalf("wrong value found in map: %d %v", v, err)
	}

	v, err = bpfDP.LookupCIDRMap("foo1", IPFamilyV4, ip3, mask3)
	if err != nil {
		t.Fatalf("cannot lookup map: %v", err)
	}
	if v != 53 {
		t.Fatalf("wrong value found in map: %d %v", v, err)
	}

	// TODO this exercises LPM maps, not implemented in mock
	_, ok := bpfDP.(*BPFLib)
	if ok {
		t.Log("Looking up an IP contained in a existent subnet on a CIDR map should succeed and return the right value")
		v, err = bpfDP.LookupCIDRMap("foo1", IPFamilyV4, ip3test, mask3)
		if err != nil {
			t.Fatalf("cannot lookup [%v, %v] map: %v", ip3test, mask3, err)
		}
		if v != 53 {
			t.Fatalf("wrong value found in map: %d %v", v, err)
		}
	}

	v, err = bpfDP.LookupCIDRMap("foo1", IPFamilyV4, ip2, mask)
	if err != nil {
		t.Fatalf("cannot lookup map: %v", err)
	}
	if v != 52 {
		t.Fatalf("wrong value found in map: %d %v", v, err)
	}

	err = bpfDP.RemoveItemCIDRMap("foo1", IPFamilyV4, ip, mask)
	if err != nil {
		t.Fatalf("cannot remove item from map: %v", err)
	}
	err = bpfDP.RemoveItemCIDRMap("foo1", IPFamilyV4, ip, mask)
	if err == nil {
		fmt.Printf("[KERNEL BUG] removing item from map after it's already removed should have failed: %v\n", err)
	}

	t.Log("Removing a CIDR map should succeed")
	err = bpfDP.RemoveCIDRMap("foo1", IPFamilyV4)
	if err != nil {
		t.Fatalf("cannot delete map: %v", err)
	}

	t.Log("Looking up on a removed a CIDR map should fail")
	_, err = bpfDP.LookupCIDRMap("foo1", IPFamilyV4, ip2, mask)
	if err == nil {
		t.Fatalf("map should have been deleted")
	}
}

var objFile = "filter.o"

func TestXDP(t *testing.T) {
	cmdVethPairArgs := []string{"-c", "ip link add test_A type veth peer name test_B || true"}
	output, err := exec.Command("/bin/sh", cmdVethPairArgs...).CombinedOutput()
	if err != nil {
		t.Fatalf("cannot create veth pair: %v\n%s", err, output)
	}

	t.Log("Loading an XDP program to a veth iface should succeed")
	err = bpfDP.loadXDPRaw(objFile, "test_A", XDPGeneric, nil)
	if err != nil {
		t.Fatalf("cannot load xdp: %v", err)
	}

	t.Log("Removing an XDP program from a veth iface should succeed")
	err = bpfDP.RemoveXDP("test_A", XDPGeneric)
	if err != nil {
		t.Fatalf("cannot remove xdp: %v", err)
	}

	t.Log("Getting the XDP tag of an iface that doesn't have an XDP program attached should fail")
	_, err = bpfDP.GetXDPTag("test_A")
	if err == nil {
		t.Fatalf("GetXDPTag should have failed")
	}

	err = bpfDP.loadXDPRaw(objFile, "test_A", XDPGeneric, nil)
	if err != nil {
		t.Fatalf("cannot load xdp: %v", err)
	}

	t.Log("Getting the XDP tag of an iface with an XDP program attached should succeed")
	tag, err := bpfDP.GetXDPTag("test_A")
	if err != nil {
		t.Fatalf("cannot get xdp tag: %v", err)
	}

	t.Log("Getting the XDP tag of an XDP object file should succeed and return the expected tag")
	fileTag, err := bpfDP.GetXDPObjTag(objFile)
	if err != nil {
		t.Fatalf("cannot get xdp tag from object file: %v", err)
	}
	if fileTag != tag {
		t.Fatalf("got wrong tag: tag=%q fileTag=%q", tag, fileTag)
	}

	t.Log("Getting the XDP tag of the default XDP object should succeed and return the expected tag")
	fileTag, err = bpfDP.GetXDPObjTagAuto()
	if err != nil {
		t.Fatalf("cannot get xdp tag from asset file: %v", err)
	}
	if fileTag != tag {
		t.Fatalf("got wrong tag: tag=%q fileTag=%q", tag, fileTag)
	}

	t.Log("Getting the XDP tag of a non-existent XDP object file should fail")
	_, err = bpfDP.GetXDPObjTag("/NONE")
	if err == nil {
		t.Fatalf("getting xdp tag should have failed")
	}

	t.Log("Getting the maps from an iface with an XDP program attached should succeed and return the right number of maps")
	arr, err := bpfDP.GetMapsFromXDP("test_A")
	if err != nil {
		t.Fatalf("cannot get maps ids from XDP: %v", err)
	}
	if len(arr) != 2 || arr[0] <= 0 || arr[1] <= 0 {
		t.Fatalf("got bad maps ids from XDP: %v", arr)
	}

	t.Log("Getting the maps from an iface without an XDP program attached should fail")
	_, err = bpfDP.GetMapsFromXDP("test_B") // other iface
	if err == nil {
		t.Fatalf("getting maps ids from XDP should have failed")
	}

	t.Log("Getting the XDP program ID from an iface with an XDP program attached should succeed")
	xdpID, err := bpfDP.GetXDPID("test_A")
	if err != nil {
		t.Fatalf("cannot get xdp id: %v", err)
	}
	if xdpID <= 0 {
		t.Fatalf("bad xdp id: %v", xdpID)
	}

	t.Log("Getting the XDP program mode from an iface with an XDP program attached should succeed")
	xdpMode, err := bpfDP.GetXDPMode("test_A")
	if err != nil {
		t.Fatalf("cannot get xdp id: %v", err)
	}
	if xdpMode != XDPGeneric {
		t.Fatalf("bad xdp mode: %v, should be %s", xdpMode.String(), XDPGeneric.String())
	}

	t.Log("Removing an XDP program from a veth iface should succeed")
	err = bpfDP.RemoveXDP("test_A", XDPGeneric)
	if err != nil {
		t.Fatalf("cannot remove xdp: %v", err)
	}

	_, err = bpfDP.GetXDPID("test_A")
	if err == nil {
		t.Fatalf("getting xdp id after deletion should have failed: %v", err)
	}

	_, err = bpfDP.GetXDPMode("test_A")
	if err == nil {
		t.Fatalf("getting xdp mode after deletion should have failed: %v", err)
	}

	_, err = bpfDP.GetMapsFromXDP("test_A")
	if err == nil {
		t.Fatalf("getting maps ids from XDP after deletion should have failed")
	}
}

func TestLoadBadXDP(t *testing.T) {
	t.Log("Loading bad XDP programs should fail")
	err := bpfDP.LoadXDP("/NONE", "COFFEE", XDPGeneric)
	if err == nil {
		t.Fatalf("loading xdp should have failed")
	}

	err = bpfDP.LoadXDP(objFile, "COFFEE", XDPGeneric)
	if err == nil {
		t.Fatalf("loading xdp should have failed")
	}
}

func TestRemoveBadXDP(t *testing.T) {
	t.Log("Removing an XDP program from a non-existent iface should fail")
	err := bpfDP.RemoveXDP("CAKE", XDPGeneric)
	if err == nil {
		t.Fatalf("removing xdp should have failed")
	}
}

func TestGetBadXDPTag(t *testing.T) {
	t.Log("Getting the XDP tag from bad ifaces should fail")
	tag, err := bpfDP.GetXDPTag("lo")
	if err == nil {
		t.Fatalf("getting xdp tag on lo should have failed: tag=%v", tag)
	}

	tag, err = bpfDP.GetXDPTag("DUMMY")
	if err == nil {
		t.Fatalf("getting xdp tag on DUMMY should have failed: tag=%v", tag)
	}
}
func TestGetBadXDPID(t *testing.T) {
	t.Log("Getting the XDP ID from a non-existent iface should fail")
	id, err := bpfDP.GetXDPID("DUMMY")
	if err == nil {
		t.Fatalf("getting xdp id should have failed: tag=%v", id)
	}
}

func TestLoadXDP(t *testing.T) {
	err := cleanup(bpfDP.GetBPFCalicoDir())
	if err != nil {
		t.Fatalf("cannot cleanup: %v", err)
	}

	cmdVethPairArgs := []string{"-c", "ip link add test_E type veth peer name test_F || true"}
	output, err := exec.Command("/bin/sh", cmdVethPairArgs...).CombinedOutput()
	if err != nil {
		t.Fatalf("cannot create veth pair: %v\n%s", err, output)
	}

	t.Log("Creating a failsafe map should succeed")
	_, err = bpfDP.NewFailsafeMap()
	if err != nil {
		t.Fatalf("cannot create map: %v", err)
	}

	t.Log("Creating a CIDR map should succeed")
	_, err = bpfDP.NewCIDRMap("test_E", IPFamilyV4)
	if err != nil {
		t.Fatalf("cannot create map: %v", err)
	}

	t.Log("Loading an XDP program to a veth iface should succeed")
	err = bpfDP.LoadXDP(objFile, "test_E", XDPGeneric)
	if err != nil {
		t.Fatalf("cannot load xdp: %v", err)
	}

	_, err = bpfDP.NewCIDRMap("test_F", IPFamilyV4)
	if err != nil {
		t.Fatalf("cannot create map: %v", err)
	}

	err = bpfDP.RemoveXDP("test_E", XDPGeneric)
	if err != nil {
		t.Fatalf("cannot remove xdp: %v", err)
	}

	t.Log("Loading an XDP program from the default XDP object to a veth iface should succeed")
	err = bpfDP.LoadXDPAuto("test_E", XDPGeneric)
	if err != nil {
		t.Fatalf("cannot load xdp: %v", err)
	}

	err = bpfDP.LoadXDPAuto("test_F", XDPGeneric)
	if err != nil {
		t.Fatalf("cannot load xdp: %v", err)
	}
}

func TestCreateAndRemoveFailsafeMap(t *testing.T) {
	err := cleanup(bpfDP.GetBPFCalicoDir())
	if err != nil {
		t.Fatalf("cannot cleanup: %v", err)
	}

	t.Log("Creating and removing a failsafe map should succeed")
	_, err = bpfDP.NewFailsafeMap()
	if err != nil {
		t.Fatalf("cannot create failsafe map: %v", err)
	}
	err = bpfDP.RemoveFailsafeMap()
	if err != nil {
		t.Fatalf("cannot delete map: %v", err)
	}
	t.Log("Removing an already removed failsafe map should fail")
	err = bpfDP.RemoveFailsafeMap()
	if err == nil {
		t.Fatalf("map deletion should have failed: %v", err)
	}
}

func TestFailsafeMapContent(t *testing.T) {
	_, err := bpfDP.NewFailsafeMap()
	if err != nil {
		t.Fatalf("cannot create map: %v", err)
	}

	port1 := uint16(8080)
	port2 := uint16(9090)
	portWrong := uint16(1010)

	t.Log("Looking up from an empty failsafe map should fail")
	exists, err := bpfDP.LookupFailsafeMap(1, port1)
	if err == nil && exists {
		t.Fatalf("lookup should have failed")
	}

	t.Log("Updating a failsafe map should succeed")
	err = bpfDP.UpdateFailsafeMap(uint8(labelindex.ProtocolTCP), port1)
	if err != nil {
		t.Fatalf("cannot update map: %v", err)
	}
	err = bpfDP.UpdateFailsafeMap(uint8(labelindex.ProtocolUDP), port2)
	if err != nil {
		t.Fatalf("cannot update map: %v", err)
	}

	t.Log("Removing a non-existent item from a failsafe map should fail")
	err = bpfDP.RemoveItemFailsafeMap(10, portWrong)
	if err == nil {
		t.Fatalf("remove item from map should have failed")
	}

	t.Log("Looking up items from a failsafe map should succeed")
	exists, err = bpfDP.LookupFailsafeMap(uint8(labelindex.ProtocolTCP), port1)
	if err != nil || !exists {
		t.Fatalf("cannot lookup map: %v exists=%v", err, exists)
	}

	exists, err = bpfDP.LookupFailsafeMap(uint8(labelindex.ProtocolUDP), port2)
	if err != nil || !exists {
		t.Fatalf("cannot lookup map: %v exists=%v", err, exists)
	}

	t.Log("Removing an existent item from a failsafe map should succeed")
	err = bpfDP.RemoveItemFailsafeMap(uint8(labelindex.ProtocolTCP), port1)
	if err != nil {
		t.Fatalf("cannot remove item from map: %v", err)
	}
	t.Log("Removing an already removed item from a failsafe map should fail")
	err = bpfDP.RemoveItemFailsafeMap(uint8(labelindex.ProtocolTCP), port1)
	if err == nil {
		t.Fatalf("removing already removed item should have failed")
	}

	t.Log("Removing a failsafe map should succeed")
	err = bpfDP.RemoveFailsafeMap()
	if err != nil {
		t.Fatalf("cannot delete map: %v", err)
	}

	t.Log("Looking up from a removed failsafe map should fail")
	exists, err = bpfDP.LookupFailsafeMap(uint8(labelindex.ProtocolTCP), port1)
	if err == nil || exists {
		t.Fatalf("map should have been deleted")
	}
}

func TestGetXDPIfaces(t *testing.T) {
	cmdVethPairArgs := []string{"-c", "ip link add test_C type veth peer name test_D || true"}
	output, err := exec.Command("/bin/sh", cmdVethPairArgs...).CombinedOutput()
	if err != nil {
		t.Fatalf("cannot create veth pair: %v\n%s", err, output)
	}

	err = bpfDP.loadXDPRaw(objFile, "test_C", XDPGeneric, nil)
	if err != nil {
		t.Fatalf("cannot load xdp: %v", err)
	}

	err = bpfDP.loadXDPRaw(objFile, "test_D", XDPGeneric, nil)
	if err != nil {
		t.Fatalf("cannot load xdp: %v", err)
	}

	t.Log("Getting XDP ifaces should list the ifaces with XDP programs attached")
	ifaces, err := bpfDP.GetXDPIfaces()
	if err != nil {
		t.Fatalf("cannot get xdp ifaces: %v", err)
	}

	if !strSliceContains(ifaces, "test_C") {
		t.Fatalf("map list should contain test_C: %v", ifaces)
	}

	if !strSliceContains(ifaces, "test_D") {
		t.Fatalf("map list should contain test_D: %v", ifaces)
	}
}

func TestGetFailsafeMapID(t *testing.T) {
	t.Log("Getting the ID of a non-existent failsafe map should fail")
	_, err := bpfDP.GetFailsafeMapID()
	if err == nil {
		t.Fatalf("getting map ID should have failed")
	}

	_, err = bpfDP.NewFailsafeMap()
	if err != nil {
		t.Fatalf("cannot create map: %v", err)
	}

	t.Log("Getting the ID of a failsafe map should succeed")
	_, err = bpfDP.GetFailsafeMapID()
	if err != nil {
		t.Fatalf("cannot get map ID: %v", err)
	}
}

func TestGetCIDRMapID(t *testing.T) {
	_, err := bpfDP.NewCIDRMap("myiface2", IPFamilyV4)
	if err != nil {
		t.Fatalf("cannot create map: %v", err)
	}

	t.Log("Getting the ID of a CIDR map should succeed")
	_, err = bpfDP.GetCIDRMapID("myiface2", IPFamilyV4)
	if err != nil {
		t.Fatalf("cannot get map ID: %v", err)
	}
}

func TestMemberToIPMask(t *testing.T) {
	member := "192.168.1.10/16"

	expectedIP := net.IPv4(192, 168, 1, 10)
	expectedMask := 16

	t.Log("MemberToIPMask should convert a string member to an ip and a mask")
	ip, mask, err := MemberToIPMask(member)
	if err != nil {
		t.Fatalf("cannot convert member (%s) to ip and mask: %v", member, err)
	}
	if !ip.Equal(expectedIP) {
		t.Fatalf("got wrong IP: ip=%v expectedIP=%q", ip, expectedIP)
	}
	if mask != expectedMask {
		t.Fatalf("got wrong mask: mask=%v expectedMask=%q", mask, expectedMask)
	}

	member = "192.168.1.1"
	expectedIP = net.IPv4(192, 168, 1, 1)
	expectedMask = 32

	ip, mask, err = MemberToIPMask(member)
	if err != nil {
		t.Fatalf("cannot convert member (%s) to ip and mask: %v", member, err)
	}
	if !ip.Equal(expectedIP) {
		t.Fatalf("got wrong IP: ip=%v expectedIP=%q", ip, expectedIP)
	}
	if mask != expectedMask {
		t.Fatalf("got wrong mask: mask=%v expectedMask=%q", mask, expectedMask)
	}
}

func TestIPv6NotSupported(t *testing.T) {
	t.Log("Creating an IPv6 CIDR map should fail for now")
	_, err := bpfDP.NewCIDRMap("myiface2", IPFamilyV6)
	if err == nil {
		t.Fatalf("creating an IPv6 blacklist should have failed")
	}
}

func TestVersionParse(t *testing.T) {
	RegisterTestingT(t)
	t.Log("Test version parsing")
	ubuntuVersionStr := "Linux version 5.3.0-39-generic (buildd@lcy01-amd64-016) (gcc version 9.3.0 (Ubuntu 9.3.0-10ubuntu2)) #43-Ubuntu SMP Fri Jun 19 10:28:31 UTC 2020"
	rhelVersionStr := "Linux version 4.18.0-193.el8.x86_64 (mockbuild@x86-vm-08.build.eng.bos.redhat.com) (gcc version 8.3.1 20191121 (Red Hat 8.3.1-5) (GCC)) #1 SMP Fri Mar 27 14:35:58 UTC 2020"
	fedVersionStr := "Linux version 5.3.0-193.el8.x86_64 (mockbuild@x86-vm-08.build.eng.bos.redhat.com) (gcc version 8.3.1 20191121 (Fedora 8.3.1-5) (GCC)) #1 SMP Fri Mar 27 14:35:58 UTC 2020"
	type comparisonTest struct {
		a, b     string
		expected int
	}

	versionStrTest := func(versionStr, distStr string, expected int) {
		distName := detector.GetDistFromString(versionStr)
		Expect(distName).To(Equal(distStr))
		parsedVer, err := detector.GetVersionFromString(versionStr)
		Expect(err).NotTo(HaveOccurred())
		expVer := GetMinKernelVersionForDistro(distName)
		Expect(parsedVer.Compare(expVer)).To(Equal(expected))
	}

	versionStrTest(ubuntuVersionStr, "ubuntu", 1)
	versionStrTest(rhelVersionStr, "rhel", 0)
	versionStrTest(fedVersionStr, "default", 1)

	// Tests to verify the compare function in detector
	tests := []comparisonTest{
		{a: "4.18.0-193", b: "4.18.0-194", expected: -1},
		{a: "4.18.0-193", b: "4.18.0-192", expected: 1},
		{a: "4.18.0-193", b: "4.18.0-193", expected: 0},
		{a: "4.18.0-193", b: "4.18.0", expected: 1},
		{a: "4.18.0-193", b: "4.19.0", expected: -1},
		{a: "4.18.0-193", b: "5.3.0", expected: -1},
	}

	for _, test := range tests {
		t.Log("Comparing ", test.a, " to ", test.b)
		ver1 := detector.MustParseVersion(test.a)
		ver2 := detector.MustParseVersion(test.b)
		Expect(ver1.Compare(ver2)).To(Equal(test.expected))
	}
}
