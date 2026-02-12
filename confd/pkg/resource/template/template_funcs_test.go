package template

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/kelseyhightower/memkv"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/encap"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
)

func Test_hashToIPv4_invalid_range(t *testing.T) {
	expectedRouterId := "207.94.5.27"
	nodeName := "Testrobin123"
	actualRouterId, err := HashToIPv4(nodeName) //invalid router_id 239.94.5.27
	if err != nil {
		t.Fatalf(`HashToIPv4(%s) returned unexpected error: %v`, nodeName, err)
	}
	if expectedRouterId != actualRouterId {
		t.Errorf(`HashToIPv4(%s) = %s, want %s`, nodeName, actualRouterId, expectedRouterId)
	}
}

func Test_hashToIPv4_valid_range(t *testing.T) {
	expectedRouterId := "109.174.215.226"
	nodeName := "nodeTest"
	actualRouterId, err := HashToIPv4(nodeName) //invalid router_id 239.94.5.27
	if err != nil {
		t.Fatalf(`HashToIPv4(%s) returned unexpected error: %v`, nodeName, err)
	}
	if expectedRouterId != actualRouterId {
		t.Errorf(`HashToIPv4(%s) = %s, want %s`, nodeName, actualRouterId, expectedRouterId)
	}
}

func Test_bgpFilterFunctionName(t *testing.T) {
	str := "should-not-be-truncated"
	direction := "import"
	version := "4"
	maxFuncNameLen := 66 //Max BIRD symbol length of 64 + 2 for bookending single quotes
	output, err := BGPFilterFunctionName(str, direction, version)
	if err != nil {
		t.Errorf("Unexpected error calling BGPFilterFunctionName(%s, %s, %s): %s", str, direction, version, err)
	}
	if len(output) > maxFuncNameLen {
		t.Errorf(`BGPFilterFunctionName(%s, %s, %s) has length %d which is greater than the maximum allowed of %d`,
			str, direction, version, len(output), maxFuncNameLen)
	}

	str = "very-long-name-that-should-be-truncated-because-it-is-longer-than-the-max-bird-symbol-length-of-64-chars"
	output, err = BGPFilterFunctionName(str, direction, version)
	if err != nil {
		t.Errorf("Unexpected error calling BGPFilterFunctionName(%s, %s, %s): %s", str, direction, version, err)
	}
	if len(output) > maxFuncNameLen {
		t.Errorf(`BGPFilterFunctionName(%s, %s, %s) has length %d which is greater than the maximum allowed of %d`,
			str, direction, version, len(output), maxFuncNameLen)
	}
}

func Test_BGPFilterBIRDFuncs(t *testing.T) {
	testFilter := v3.BGPFilter{}
	testFilter.Name = "test-bgpfilter"
	testFilter.Spec = v3.BGPFilterSpec{
		ImportV4: []v3.BGPFilterRuleV4{
			{Action: "Accept", Source: "RemotePeers", Interface: "vxlan.calico", MatchOperator: "NotIn", CIDR: "55.4.0.0/16"},
			{Action: "Reject", Source: "RemotePeers", MatchOperator: "NotIn", CIDR: "55.4.0.0/16"},
			{Action: "Reject", Source: "RemotePeers", MatchOperator: "NotIn", CIDR: "55.4.0.0/16", PrefixLength: &v3.BGPFilterPrefixLengthV4{Min: int32Helper(16), Max: int32Helper(24)}},
			{Action: "Reject", Interface: "eth0", MatchOperator: "NotIn", CIDR: "55.4.0.0/16"},
			{Action: "Accept", Interface: "eth0", Source: "RemotePeers"},
			{Action: "Reject", Interface: "eth0", Source: "RemotePeers", PrefixLength: &v3.BGPFilterPrefixLengthV4{Min: int32Helper(16), Max: int32Helper(24)}},
			{Action: "Reject", MatchOperator: "Equal", CIDR: "44.4.0.0/16"},
			{Action: "Accept", Source: "RemotePeers"},
			{Action: "Reject", Interface: "extraiface"},
			{Action: "Reject"},
		},
		ExportV4: []v3.BGPFilterRuleV4{
			{Action: "Reject", Source: "RemotePeers", Interface: "vxlan.calico", MatchOperator: "NotIn", CIDR: "55.4.0.0/16"},
			{Action: "Reject", Source: "RemotePeers", MatchOperator: "NotIn", CIDR: "88.7.0.0/16"},
			{Action: "Reject", Source: "RemotePeers", MatchOperator: "NotIn", CIDR: "88.7.0.0/16", PrefixLength: &v3.BGPFilterPrefixLengthV4{Max: int32Helper(24)}},
			{Action: "Accept", Interface: "eth0", MatchOperator: "NotIn", CIDR: "55.4.0.0/16"},
			{Action: "Reject", Interface: "eth0", Source: "RemotePeers"},
			{Action: "Accept", MatchOperator: "In", CIDR: "77.7.0.0/16"},
			{Action: "Accept", Source: "RemotePeers"},
			{Action: "Accept", Interface: "extraiface"},
			{Action: "Reject"},
		},
		ImportV6: []v3.BGPFilterRuleV6{
			{Action: "Reject", Source: "RemotePeers", Interface: "vxlan.calico", MatchOperator: "NotIn", CIDR: "7000:1::0/64"},
			{Action: "Reject", Source: "RemotePeers", MatchOperator: "NotEqual", CIDR: "8000:1::0/64"},
			{Action: "Accept", Interface: "eth0", MatchOperator: "NotIn", CIDR: "6000:1::0/64"},
			{Action: "Accept", Interface: "eth0", MatchOperator: "NotIn", CIDR: "6000:1::0/64", PrefixLength: &v3.BGPFilterPrefixLengthV6{Min: int32Helper(96)}},
			{Action: "Reject", Interface: "eth0", Source: "RemotePeers"},
			{Action: "Accept", MatchOperator: "NotEqual", CIDR: "7000:1::0/64"},
			{Action: "Accept", MatchOperator: "NotEqual", CIDR: "7000:1::0/64", PrefixLength: &v3.BGPFilterPrefixLengthV6{Max: int32Helper(96)}},
			{Action: "Accept", Source: "RemotePeers"},
			{Action: "Accept", Interface: "extraiface"},
			{Action: "Reject"},
		},
		ExportV6: []v3.BGPFilterRuleV6{
			{Action: "Accept", Source: "RemotePeers", Interface: "vxlan.calico", MatchOperator: "NotIn", CIDR: "b000:1::0/64"},
			{Action: "Reject", Source: "RemotePeers", MatchOperator: "NotIn", CIDR: "a000:1::0/64"},
			{Action: "Reject", Interface: "eth0", MatchOperator: "NotIn", CIDR: "c000:1::0/64"},
			{Action: "Reject", Interface: "eth0", MatchOperator: "NotIn", CIDR: "c000:1::0/64", PrefixLength: &v3.BGPFilterPrefixLengthV6{Min: int32Helper(120), Max: int32Helper(128)}},
			{Action: "Accept", Interface: "eth0", Source: "RemotePeers"},
			{Action: "Accept", MatchOperator: "NotIn", CIDR: "9000:1::0/64"},
			{Action: "Accept", MatchOperator: "NotIn", CIDR: "9000:1::0/64", PrefixLength: &v3.BGPFilterPrefixLengthV6{Min: int32Helper(96), Max: int32Helper(120)}},
			{Action: "Accept", Source: "RemotePeers"},
			{Action: "Reject", Interface: "extraiface"},
			{Action: "Reject"},
		},
	}
	expectedBIRDCfgStrV4 := []string{
		"# v4 BGPFilter test-bgpfilter",
		"function 'bgp_test-bgpfilter_importFilterV4'() {",
		"  if ((net !~ 55.4.0.0/16)&&((defined(source))&&(source ~ [ RTS_BGP ]))&&((defined(ifname))&&(ifname ~ \"vxlan.calico\"))) then { accept; }",
		"  if ((net !~ 55.4.0.0/16)&&((defined(source))&&(source ~ [ RTS_BGP ]))) then { reject; }",
		"  if ((net !~ [ 55.4.0.0/16{16,24} ])&&((defined(source))&&(source ~ [ RTS_BGP ]))) then { reject; }",
		"  if ((net !~ 55.4.0.0/16)&&((defined(ifname))&&(ifname ~ \"eth0\"))) then { reject; }",
		"  if (((defined(source))&&(source ~ [ RTS_BGP ]))&&((defined(ifname))&&(ifname ~ \"eth0\"))) then { accept; }",
		"  if (((defined(source))&&(source ~ [ RTS_BGP ]))&&((defined(ifname))&&(ifname ~ \"eth0\"))) then { reject; }",
		"  if ((net = 44.4.0.0/16)) then { reject; }",
		"  if (((defined(source))&&(source ~ [ RTS_BGP ]))) then { accept; }",
		"  if (((defined(ifname))&&(ifname ~ \"extraiface\"))) then { reject; }",
		"  reject;",
		"}",
		"function 'bgp_test-bgpfilter_exportFilterV4'() {",
		"  if ((net !~ 55.4.0.0/16)&&((defined(source))&&(source ~ [ RTS_BGP ]))&&((defined(ifname))&&(ifname ~ \"vxlan.calico\"))) then { reject; }",
		"  if ((net !~ 88.7.0.0/16)&&((defined(source))&&(source ~ [ RTS_BGP ]))) then { reject; }",
		"  if ((net !~ [ 88.7.0.0/16{16,24} ])&&((defined(source))&&(source ~ [ RTS_BGP ]))) then { reject; }",
		"  if ((net !~ 55.4.0.0/16)&&((defined(ifname))&&(ifname ~ \"eth0\"))) then { accept; }",
		"  if (((defined(source))&&(source ~ [ RTS_BGP ]))&&((defined(ifname))&&(ifname ~ \"eth0\"))) then { reject; }",
		"  if ((net ~ 77.7.0.0/16)) then { accept; }",
		"  if (((defined(source))&&(source ~ [ RTS_BGP ]))) then { accept; }",
		"  if (((defined(ifname))&&(ifname ~ \"extraiface\"))) then { accept; }",
		"  reject;",
		"}",
	}
	expectedBIRDCfgStrV6 := []string{
		"# v6 BGPFilter test-bgpfilter",
		"function 'bgp_test-bgpfilter_importFilterV6'() {",
		"  if ((net !~ 7000:1::0/64)&&((defined(source))&&(source ~ [ RTS_BGP ]))&&((defined(ifname))&&(ifname ~ \"vxlan.calico\"))) then { reject; }",
		"  if ((net != 8000:1::0/64)&&((defined(source))&&(source ~ [ RTS_BGP ]))) then { reject; }",
		"  if ((net !~ 6000:1::0/64)&&((defined(ifname))&&(ifname ~ \"eth0\"))) then { accept; }",
		"  if ((net !~ [ 6000:1::0/64{96,128} ])&&((defined(ifname))&&(ifname ~ \"eth0\"))) then { accept; }",
		"  if (((defined(source))&&(source ~ [ RTS_BGP ]))&&((defined(ifname))&&(ifname ~ \"eth0\"))) then { reject; }",
		"  if ((net != 7000:1::0/64)) then { accept; }",
		"  if ((net != [ 7000:1::0/64{64,96} ])) then { accept; }",
		"  if (((defined(source))&&(source ~ [ RTS_BGP ]))) then { accept; }",
		"  if (((defined(ifname))&&(ifname ~ \"extraiface\"))) then { accept; }",
		"  reject;",
		"}",
		"function 'bgp_test-bgpfilter_exportFilterV6'() {",
		"  if ((net !~ b000:1::0/64)&&((defined(source))&&(source ~ [ RTS_BGP ]))&&((defined(ifname))&&(ifname ~ \"vxlan.calico\"))) then { accept; }",
		"  if ((net !~ a000:1::0/64)&&((defined(source))&&(source ~ [ RTS_BGP ]))) then { reject; }",
		"  if ((net !~ c000:1::0/64)&&((defined(ifname))&&(ifname ~ \"eth0\"))) then { reject; }",
		"  if ((net !~ [ c000:1::0/64{120,128} ])&&((defined(ifname))&&(ifname ~ \"eth0\"))) then { reject; }",
		"  if (((defined(source))&&(source ~ [ RTS_BGP ]))&&((defined(ifname))&&(ifname ~ \"eth0\"))) then { accept; }",
		"  if ((net !~ 9000:1::0/64)) then { accept; }",
		"  if ((net !~ [ 9000:1::0/64{96,120} ])) then { accept; }",
		"  if (((defined(source))&&(source ~ [ RTS_BGP ]))) then { accept; }",
		"  if (((defined(ifname))&&(ifname ~ \"extraiface\"))) then { reject; }",
		"  reject;",
		"}",
	}

	jsonFilter, err := json.Marshal(testFilter)
	if err != nil {
		t.Errorf("Error formatting BGPFilter into JSON: %s", err)
	}
	kvps := []memkv.KVPair{
		{Key: "test-bgpfilter", Value: string(jsonFilter)},
	}

	v4BIRDCfgResult, err := BGPFilterBIRDFuncs(kvps, 4)
	if err != nil {
		t.Errorf("Unexpected error while generating v4 BIRD BGPFilter functions: %s", err)
	}
	if !reflect.DeepEqual(v4BIRDCfgResult, expectedBIRDCfgStrV4) {
		t.Errorf("Generated v4 BIRD config differs from expectation:\n Generated = %s,\n Expected = %s",
			v4BIRDCfgResult, expectedBIRDCfgStrV4)
	}

	v6BIRDCfgResult, err := BGPFilterBIRDFuncs(kvps, 6)
	if err != nil {
		t.Errorf("Unexpected error while generating v6 BIRD BGPFilter functions: %s", err)
	}
	if !reflect.DeepEqual(v6BIRDCfgResult, expectedBIRDCfgStrV6) {
		t.Errorf("Generated v6 BIRD config differs from expectation:\n Generated = %s,\n Expected = %s",
			v6BIRDCfgResult, expectedBIRDCfgStrV6)
	}
}

func Test_ValidateHashToIpv4Method(t *testing.T) {
	expectedRouterId := "207.94.5.27"
	nodeName := "Testrobin123"
	actualRouterId, err := HashToIPv4(nodeName)
	if err != nil {
		t.Fatalf("HashToIPv4(%s) returned unexpected error: %v", nodeName, err)
	}
	if expectedRouterId != actualRouterId {
		t.Errorf("Expected %s to equal %s", expectedRouterId, actualRouterId)
	}

	expectedRouterId = "109.174.215.226"
	nodeName = "nodeTest"
	actualRouterId, err = HashToIPv4(nodeName)
	if err != nil {
		t.Fatalf("HashToIPv4(%s) returned unexpected error: %v", nodeName, err)
	}
	if expectedRouterId != actualRouterId {
		t.Errorf("Expected %s to equal %s", expectedRouterId, actualRouterId)
	}
}

func int32Helper(i int32) *int32 {
	return &i
}

type ippoolTestCase struct {
	cidr           string
	exportDisabled bool
	ipipMode       encap.Mode
	vxlanMode      encap.Mode
}

var (
	poolsTestsV4 []ippoolTestCase = []ippoolTestCase{
		// IPv4 IPIP Encapsulation cases.
		{cidr: "10.10.0.0/16", exportDisabled: false, ipipMode: encap.Always},
		{cidr: "10.11.0.0/16", exportDisabled: true, ipipMode: encap.Always},
		{cidr: "10.12.0.0/16", exportDisabled: false, ipipMode: encap.CrossSubnet},
		{cidr: "10.13.0.0/16", exportDisabled: true, ipipMode: encap.CrossSubnet},
		// IPv4 No-Encapsulation case.
		{cidr: "10.14.0.0/16", exportDisabled: false},
		{cidr: "10.15.0.0/16", exportDisabled: true},
		// IPv4 VXLAN Encapsulation cases.
		{cidr: "10.16.0.0/16", exportDisabled: false, vxlanMode: encap.Always},
		{cidr: "10.17.0.0/16", exportDisabled: true, vxlanMode: encap.Always},
		{cidr: "10.18.0.0/16", exportDisabled: false, vxlanMode: encap.CrossSubnet},
		{cidr: "10.19.0.0/16", exportDisabled: true, vxlanMode: encap.CrossSubnet},
	}

	poolsTestsV6 []ippoolTestCase = []ippoolTestCase{
		// IPv6 IPIP Encapsulation cases.
		{cidr: "dead:beef:1::/64", exportDisabled: false, ipipMode: encap.Always},
		{cidr: "dead:beef:2::/64", exportDisabled: true, ipipMode: encap.Always},
		{cidr: "dead:beef:3::/64", exportDisabled: false, ipipMode: encap.CrossSubnet},
		{cidr: "dead:beef:4::/64", exportDisabled: true, ipipMode: encap.CrossSubnet},
		// IPv6 No-Encapsulation case.
		{cidr: "dead:beef:5::/64", exportDisabled: false},
		{cidr: "dead:beef:6::/64", exportDisabled: true},
		// IPv6 VXLAN Encapsulation cases.
		{cidr: "dead:beef:7::/64", exportDisabled: false, vxlanMode: encap.Always},
		{cidr: "dead:beef:8::/64", exportDisabled: true, vxlanMode: encap.Always},
		{cidr: "dead:beef:9::/64", exportDisabled: false, vxlanMode: encap.CrossSubnet},
		{cidr: "dead:beef:10::/64", exportDisabled: true, vxlanMode: encap.CrossSubnet},
	}
)

func Test_IPPoolsFilterBIRDFunc_KernelProgrammingV4(t *testing.T) {
	expectedStatements := []string{
		// IPv4 IPIP Encapsulation cases.
		`  if (net ~ 10.10.0.0/16) then { krt_tunnel="tunl0"; accept; }`,
		`  if (net ~ 10.11.0.0/16) then { krt_tunnel="tunl0"; accept; }`,
		`  if (net ~ 10.12.0.0/16) then { if (defined(bgp_next_hop)&&(bgp_next_hop ~ 1.1.1.0/24)) then krt_tunnel=""; else krt_tunnel="tunl0"; accept; }`,
		`  if (net ~ 10.13.0.0/16) then { if (defined(bgp_next_hop)&&(bgp_next_hop ~ 1.1.1.0/24)) then krt_tunnel=""; else krt_tunnel="tunl0"; accept; }`,
		// IPv4 No-Encapsulation case.
		`  if (net ~ 10.14.0.0/16) then { krt_tunnel=""; accept; }`,
		`  if (net ~ 10.15.0.0/16) then { krt_tunnel=""; accept; }`,
		// IPv4 VXLAN Encapsulation cases.
		`  if (net ~ 10.16.0.0/16) then { reject; } # VXLAN routes are handled by Felix.`,
		`  if (net ~ 10.17.0.0/16) then { reject; } # VXLAN routes are handled by Felix.`,
		`  if (net ~ 10.18.0.0/16) then { reject; } # VXLAN routes are handled by Felix.`,
		`  if (net ~ 10.19.0.0/16) then { reject; } # VXLAN routes are handled by Felix.`,
	}
	testExpectedIPPoolStatments(t, poolsTestsV4, expectedStatements, true, "1.1.1.0/24", 4)
}

func Test_IPPoolsFilterBIRDFunc_KernelProgrammingV6(t *testing.T) {
	expectedStatements := []string{
		// IPv6 IPIP Encapsulation cases.
		`  if (net ~ dead:beef:1::/64) then { accept; }`,
		`  if (net ~ dead:beef:2::/64) then { accept; }`,
		`  if (net ~ dead:beef:3::/64) then { accept; }`,
		`  if (net ~ dead:beef:4::/64) then { accept; }`,
		// IPv6 No-Encapsulation case.
		`  if (net ~ dead:beef:5::/64) then { accept; }`,
		`  if (net ~ dead:beef:6::/64) then { accept; }`,
		// IPv6 VXLAN Encapsulation cases.
		`  if (net ~ dead:beef:7::/64) then { reject; } # VXLAN routes are handled by Felix.`,
		`  if (net ~ dead:beef:8::/64) then { reject; } # VXLAN routes are handled by Felix.`,
		`  if (net ~ dead:beef:9::/64) then { reject; } # VXLAN routes are handled by Felix.`,
		`  if (net ~ dead:beef:10::/64) then { reject; } # VXLAN routes are handled by Felix.`,
	}
	testExpectedIPPoolStatments(t, poolsTestsV6, expectedStatements, true, "", 6)
}

func Test_IPPoolsFilterBIRDFunc_BGPPeeringV4(t *testing.T) {
	expectedStatements := []string{
		// IPv4 IPIP Encapsulation cases.
		`  if (net ~ 10.10.0.0/16) then { accept; }`,
		`  if (net ~ 10.11.0.0/16) then { reject; } # BGP export is disabled.`,
		`  if (net ~ 10.12.0.0/16) then { accept; }`,
		`  if (net ~ 10.13.0.0/16) then { reject; } # BGP export is disabled.`,
		// IPv4 No-Encapsulation case.
		`  if (net ~ 10.14.0.0/16) then { accept; }`,
		`  if (net ~ 10.15.0.0/16) then { reject; } # BGP export is disabled.`,
		// IPv4 VXLAN Encapsulation cases.
		`  if (net ~ 10.16.0.0/16) then { accept; }`,
		`  if (net ~ 10.17.0.0/16) then { reject; } # BGP export is disabled.`,
		`  if (net ~ 10.18.0.0/16) then { accept; }`,
		`  if (net ~ 10.19.0.0/16) then { reject; } # BGP export is disabled.`,
	}
	testExpectedIPPoolStatments(t, poolsTestsV4, expectedStatements, false, "", 4)
}

func Test_IPPoolsFilterBIRDFunc_BGPPeeringV6(t *testing.T) {
	expectedStatements := []string{
		// IPv6 IPIP Encapsulation cases.
		`  if (net ~ dead:beef:1::/64) then { accept; }`,
		`  if (net ~ dead:beef:2::/64) then { reject; } # BGP export is disabled.`,
		`  if (net ~ dead:beef:3::/64) then { accept; }`,
		`  if (net ~ dead:beef:4::/64) then { reject; } # BGP export is disabled.`,
		// IPv6 No-Encapsulation case.
		`  if (net ~ dead:beef:5::/64) then { accept; }`,
		`  if (net ~ dead:beef:6::/64) then { reject; } # BGP export is disabled.`,
		// IPv6 VXLAN Encapsulation cases.
		`  if (net ~ dead:beef:7::/64) then { accept; }`,
		`  if (net ~ dead:beef:8::/64) then { reject; } # BGP export is disabled.`,
		`  if (net ~ dead:beef:9::/64) then { accept; }`,
		`  if (net ~ dead:beef:10::/64) then { reject; } # BGP export is disabled.`,
	}
	testExpectedIPPoolStatments(t, poolsTestsV6, expectedStatements, false, "", 6)
}

func testExpectedIPPoolStatments(
	t *testing.T,
	tcs []ippoolTestCase,
	expectedStatements []string,
	forProgrammingKernel bool,
	localSubnet string,
	ipVersion int,
) {
	kvps := ippoolTestCasesToKVPairs(t, tcs)
	for _, filterAction := range []string{"", "accept", "reject"} {
		expected := filterExpectedStatements(expectedStatements, filterAction)
		generated, err := IPPoolsFilterBIRDFunc(kvps, filterAction, forProgrammingKernel, localSubnet, ipVersion)
		if err != nil {
			t.Errorf("Unexpected error while generating BIRD IPPool filter: %s", err)
		}
		if !reflect.DeepEqual(generated, expected) {
			t.Errorf("Generated BIRD config differs from expectation:\n Generated=%#v,\n Expected=%#v",
				generated, expected)
		}
	}
}

func ippoolTestCasesToKVPairs(t *testing.T, tcs []ippoolTestCase) memkv.KVPairs {
	kvps := []memkv.KVPair{}
	for _, tc := range tcs {
		ippool := model.IPPool{}
		ippool.CIDR = net.MustParseCIDR(tc.cidr)
		ippool.IPIPMode = tc.ipipMode
		ippool.VXLANMode = tc.vxlanMode
		ippool.DisableBGPExport = tc.exportDisabled

		jsonIPPool, err := json.Marshal(ippool)
		if err != nil {
			t.Errorf("Error formatting IPPool into JSON: %s", err)
		}
		kvps = append(kvps, memkv.KVPair{
			Key:   fmt.Sprintf("ippool-%s", tc.cidr),
			Value: string(jsonIPPool),
		})
	}
	return kvps
}

func filterExpectedStatements(statements []string, filterAction string) (filtered []string) {
	if len(filterAction) == 0 {
		return statements
	}
	for _, s := range statements {
		if strings.Contains(s, fmt.Sprintf("%s; }", filterAction)) {
			filtered = append(filtered, s)
		}
	}
	return
}
