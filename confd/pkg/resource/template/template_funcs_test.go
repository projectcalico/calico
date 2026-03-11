package template

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/kelseyhightower/memkv"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"
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

func Test_filterMatchCommunity(t *testing.T) {
	tests := []struct {
		name     string
		comm     *v3.BGPFilterCommunityMatch
		expected string
		wantErr  bool
	}{
		{
			name:     "standard community",
			comm:     &v3.BGPFilterCommunityMatch{Values: []v3.BGPCommunityValue{"65000:100"}},
			expected: "((65000, 100) ~ bgp_community)",
		},
		{
			name:     "large community",
			comm:     &v3.BGPFilterCommunityMatch{Values: []v3.BGPCommunityValue{"65000:10:20"}},
			expected: "((65000, 10, 20) ~ bgp_large_community)",
		},
		{
			name:    "nil communities",
			comm:    nil,
			wantErr: true,
		},
		{
			name:    "empty values",
			comm:    &v3.BGPFilterCommunityMatch{Values: []v3.BGPCommunityValue{}},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := filterMatchCommunity(tt.comm)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if result != tt.expected {
				t.Errorf("got %q, want %q", result, tt.expected)
			}
		})
	}
}

func Test_filterMatchASPathPrefix(t *testing.T) {
	tests := []struct {
		name     string
		prefix   []numorstring.ASNumber
		expected string
	}{
		{
			name:     "single ASN",
			prefix:   []numorstring.ASNumber{65000},
			expected: "(bgp_path.first = 65000)",
		},
		{
			name:     "multiple ASNs",
			prefix:   []numorstring.ASNumber{65000, 65001},
			expected: "(bgp_path ~ [= 65000 65001 * =])",
		},
		{
			name:     "three ASNs",
			prefix:   []numorstring.ASNumber{65000, 65001, 65002},
			expected: "(bgp_path ~ [= 65000 65001 65002 * =])",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := filterMatchASPathPrefix(tt.prefix)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if result != tt.expected {
				t.Errorf("got %q, want %q", result, tt.expected)
			}
		})
	}
}

func Test_filterMatchPriority(t *testing.T) {
	prio := 512
	result, err := filterMatchPriority(&prio)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
		return
	}
	expected := "(krt_metric = 512)"
	if result != expected {
		t.Errorf("got %q, want %q", result, expected)
	}
}

func Test_filterOperationStatements(t *testing.T) {
	tests := []struct {
		name     string
		ops      []v3.BGPFilterOperation
		expected []string
	}{
		{
			name: "add standard community",
			ops: []v3.BGPFilterOperation{
				{AddCommunity: &v3.BGPFilterAddCommunity{Value: "65000:100"}},
			},
			expected: []string{"bgp_community.add((65000, 100));"},
		},
		{
			name: "add large community",
			ops: []v3.BGPFilterOperation{
				{AddCommunity: &v3.BGPFilterAddCommunity{Value: "65000:10:20"}},
			},
			expected: []string{"bgp_large_community.add((65000, 10, 20));"},
		},
		{
			name: "prepend single ASN",
			ops: []v3.BGPFilterOperation{
				{PrependASPath: &v3.BGPFilterPrependASPath{Prefix: []numorstring.ASNumber{65000}}},
			},
			expected: []string{"bgp_path.prepend(65000);"},
		},
		{
			name: "prepend multiple ASNs - reversed for correct order",
			ops: []v3.BGPFilterOperation{
				{PrependASPath: &v3.BGPFilterPrependASPath{Prefix: []numorstring.ASNumber{65000, 65001}}},
			},
			expected: []string{"bgp_path.prepend(65001);", "bgp_path.prepend(65000);"},
		},
		{
			name: "set priority",
			ops: []v3.BGPFilterOperation{
				{SetPriority: &v3.BGPFilterSetPriority{Value: 512}},
			},
			expected: []string{"krt_metric = 512;"},
		},
		{
			name: "multiple operations",
			ops: []v3.BGPFilterOperation{
				{AddCommunity: &v3.BGPFilterAddCommunity{Value: "65001:200"}},
				{PrependASPath: &v3.BGPFilterPrependASPath{Prefix: []numorstring.ASNumber{65000}}},
				{SetPriority: &v3.BGPFilterSetPriority{Value: 100}},
			},
			expected: []string{
				"bgp_community.add((65001, 200));",
				"bgp_path.prepend(65000);",
				"krt_metric = 100;",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := filterOperationStatements(tt.ops)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("got %v, want %v", result, tt.expected)
			}
		})
	}
}

func Test_filterStatementWithOperations(t *testing.T) {
	prio := 512
	args := filterArgs{
		operator: v3.In,
		cidr:     "10.0.0.0/8",
		priority: &prio,
		action:   v3.Accept,
		operations: []v3.BGPFilterOperation{
			{AddCommunity: &v3.BGPFilterAddCommunity{Value: "65001:200"}},
			{PrependASPath: &v3.BGPFilterPrependASPath{Prefix: []numorstring.ASNumber{65000}}},
		},
	}
	result, err := filterStatement(args)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
		return
	}
	expected := "if ((net ~ 10.0.0.0/8)&&(krt_metric = 512)) then { bgp_community.add((65001, 200)); bgp_path.prepend(65000); accept; }"
	if result != expected {
		t.Errorf("got:\n  %s\nwant:\n  %s", result, expected)
	}
}

func Test_BGPFilterBIRDFuncs_WithCommunitiesASPathPriorityAndOperations(t *testing.T) {
	prio := 512
	testFilter := v3.BGPFilter{}
	testFilter.Name = "kubevirt-filter"
	testFilter.Spec = v3.BGPFilterSpec{
		ImportV4: []v3.BGPFilterRuleV4{
			// Import rule: match community and set priority
			{
				Action:      v3.Accept,
				Communities: &v3.BGPFilterCommunityMatch{Values: []v3.BGPCommunityValue{"65000:100"}},
				Operations: []v3.BGPFilterOperation{
					{SetPriority: &v3.BGPFilterSetPriority{Value: 100}},
				},
			},
			// Import rule: match AS path prefix and set priority
			{
				Action:       v3.Accept,
				ASPathPrefix: []numorstring.ASNumber{65000, 65001},
				Operations: []v3.BGPFilterOperation{
					{SetPriority: &v3.BGPFilterSetPriority{Value: 200}},
				},
			},
		},
		ExportV4: []v3.BGPFilterRuleV4{
			// Export rule: match priority and add community
			{
				Action:   v3.Accept,
				Priority: &prio,
				Operations: []v3.BGPFilterOperation{
					{AddCommunity: &v3.BGPFilterAddCommunity{Value: "65001:200"}},
				},
			},
			// Export rule: match priority and prepend AS path
			{
				Action:   v3.Accept,
				Priority: &prio,
				Operations: []v3.BGPFilterOperation{
					{PrependASPath: &v3.BGPFilterPrependASPath{Prefix: []numorstring.ASNumber{65000}}},
				},
			},
		},
	}

	expectedV4 := []string{
		"# v4 BGPFilter kubevirt-filter",
		"function 'bgp_kubevirt-filter_importFilterV4'() {",
		"  if (((65000, 100) ~ bgp_community)) then { krt_metric = 100; accept; }",
		"  if ((bgp_path ~ [= 65000 65001 * =])) then { krt_metric = 200; accept; }",
		"}",
		"function 'bgp_kubevirt-filter_exportFilterV4'() {",
		"  if ((krt_metric = 512)) then { bgp_community.add((65001, 200)); accept; }",
		"  if ((krt_metric = 512)) then { bgp_path.prepend(65000); accept; }",
		"}",
	}

	jsonFilter, err := json.Marshal(testFilter)
	if err != nil {
		t.Fatalf("Error marshalling BGPFilter: %v", err)
	}
	kvps := []memkv.KVPair{
		{Key: "kubevirt-filter", Value: string(jsonFilter)},
	}

	result, err := BGPFilterBIRDFuncs(kvps, 4)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !reflect.DeepEqual(result, expectedV4) {
		t.Errorf("Generated BIRD config differs:\n  Got:    %v\n  Expect: %v", result, expectedV4)
	}
}

func Test_BGPFilterBIRDFuncs_WithPeerType(t *testing.T) {
	testFilter := v3.BGPFilter{}
	testFilter.Name = "peertype-filter"
	testFilter.Spec = v3.BGPFilterSpec{
		ExportV4: []v3.BGPFilterRuleV4{
			// eBGP-only rule
			{
				Action:        v3.Accept,
				PeerType:      v3.BGPFilterPeerTypeEBGP,
				MatchOperator: v3.In,
				CIDR:          "10.0.0.0/8",
			},
			// iBGP-only rule
			{
				Action:        v3.Reject,
				PeerType:      v3.BGPFilterPeerTypeIBGP,
				MatchOperator: v3.In,
				CIDR:          "10.0.0.0/8",
			},
			// No PeerType - applies to all
			{
				Action: v3.Reject,
			},
		},
	}

	expectedV4 := []string{
		"# v4 BGPFilter peertype-filter",
		"function 'bgp_peertype-filter_exportFilterV4'(bool is_same_as) {",
		"  if (!is_same_as) then { if ((net ~ 10.0.0.0/8)) then { accept; } }",
		"  if (is_same_as) then { if ((net ~ 10.0.0.0/8)) then { reject; } }",
		"  reject;",
		"}",
	}

	jsonFilter, err := json.Marshal(testFilter)
	if err != nil {
		t.Fatalf("Error marshalling BGPFilter: %v", err)
	}
	kvps := []memkv.KVPair{
		{Key: "peertype-filter", Value: string(jsonFilter)},
	}

	result, err := BGPFilterBIRDFuncs(kvps, 4)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !reflect.DeepEqual(result, expectedV4) {
		t.Errorf("Generated BIRD config differs:\n  Got:    %v\n  Expect: %v", result, expectedV4)
	}
}

// Test_BGPFilterBIRDFuncs_FullExample covers Example A from bgpfilter-bird-config-examples.md:
// a filter using ALL match criteria (CIDR+PrefixLength, Interface, Communities, ASPathPrefix,
// Priority, PeerType, Source) and ALL operations (SetPriority, AddCommunity, PrependASPath)
// on both import and export, for both iBGP and eBGP peer types.
func Test_BGPFilterBIRDFuncs_FullExample(t *testing.T) {
	prio512 := 512
	prio100 := 100

	testFilter := v3.BGPFilter{}
	testFilter.Name = "full-example"
	testFilter.Spec = v3.BGPFilterSpec{
		ImportV4: []v3.BGPFilterRuleV4{
			{
				CIDR:          "10.244.0.0/16",
				MatchOperator: v3.In,
				PrefixLength:  &v3.BGPFilterPrefixLengthV4{Min: int32Helper(24), Max: int32Helper(28)},
				PeerType:      v3.BGPFilterPeerTypeIBGP,
				Communities:   &v3.BGPFilterCommunityMatch{Values: []v3.BGPCommunityValue{"65000:100"}},
				ASPathPrefix:  []numorstring.ASNumber{65000},
				Priority:      &prio512,
				Interface:     "eth0",
				Action:        v3.Accept,
				Operations: []v3.BGPFilterOperation{
					{SetPriority: &v3.BGPFilterSetPriority{Value: 256}},
					{AddCommunity: &v3.BGPFilterAddCommunity{Value: "65000:200"}},
					{PrependASPath: &v3.BGPFilterPrependASPath{Prefix: []numorstring.ASNumber{65001, 65002}}},
				},
			},
			{
				CIDR:          "10.244.0.0/16",
				MatchOperator: v3.In,
				PeerType:      v3.BGPFilterPeerTypeEBGP,
				Communities:   &v3.BGPFilterCommunityMatch{Values: []v3.BGPCommunityValue{"65000:100:999"}},
				ASPathPrefix:  []numorstring.ASNumber{65000, 65001},
				Priority:      &prio100,
				Action:        v3.Accept,
				Operations: []v3.BGPFilterOperation{
					{SetPriority: &v3.BGPFilterSetPriority{Value: 1024}},
				},
			},
			{
				Action: v3.Reject,
			},
		},
		ExportV4: []v3.BGPFilterRuleV4{
			{
				CIDR:          "192.168.0.0/16",
				MatchOperator: v3.In,
				Source:        v3.BGPFilterSourceRemotePeers,
				Interface:     "eth1",
				PeerType:      v3.BGPFilterPeerTypeEBGP,
				Communities:   &v3.BGPFilterCommunityMatch{Values: []v3.BGPCommunityValue{"65000:42"}},
				ASPathPrefix:  []numorstring.ASNumber{65000, 65001},
				Priority:      &prio100,
				Action:        v3.Accept,
				Operations: []v3.BGPFilterOperation{
					{AddCommunity: &v3.BGPFilterAddCommunity{Value: "65000:300:400"}},
					{PrependASPath: &v3.BGPFilterPrependASPath{Prefix: []numorstring.ASNumber{64999}}},
				},
			},
			{
				CIDR:          "10.0.0.0/8",
				MatchOperator: v3.Equal,
				PeerType:      v3.BGPFilterPeerTypeIBGP,
				Action:        v3.Accept,
			},
		},
	}

	expectedV4 := []string{
		"# v4 BGPFilter full-example",
		"function 'bgp_full-example_importFilterV4'(bool is_same_as) {",
		`  if (is_same_as) then { if ((net ~ [ 10.244.0.0/16{24,28} ])&&((defined(ifname))&&(ifname ~ "eth0"))&&((65000, 100) ~ bgp_community)&&(bgp_path.first = 65000)&&(krt_metric = 512)) then { krt_metric = 256; bgp_community.add((65000, 200)); bgp_path.prepend(65002); bgp_path.prepend(65001); accept; } }`,
		"  if (!is_same_as) then { if ((net ~ 10.244.0.0/16)&&((65000, 100, 999) ~ bgp_large_community)&&(bgp_path ~ [= 65000 65001 * =])&&(krt_metric = 100)) then { krt_metric = 1024; accept; } }",
		"  reject;",
		"}",
		"function 'bgp_full-example_exportFilterV4'(bool is_same_as) {",
		`  if (!is_same_as) then { if ((net ~ 192.168.0.0/16)&&((defined(source))&&(source ~ [ RTS_BGP ]))&&((defined(ifname))&&(ifname ~ "eth1"))&&((65000, 42) ~ bgp_community)&&(bgp_path ~ [= 65000 65001 * =])&&(krt_metric = 100)) then { bgp_large_community.add((65000, 300, 400)); bgp_path.prepend(64999); accept; } }`,
		"  if (is_same_as) then { if ((net = 10.0.0.0/8)) then { accept; } }",
		"}",
	}

	jsonFilter, err := json.Marshal(testFilter)
	if err != nil {
		t.Fatalf("Error marshalling BGPFilter: %v", err)
	}
	kvps := []memkv.KVPair{
		{Key: "full-example", Value: string(jsonFilter)},
	}

	result, err := BGPFilterBIRDFuncs(kvps, 4)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !reflect.DeepEqual(result, expectedV4) {
		t.Errorf("Generated BIRD config differs from Example A in bgpfilter-bird-config-examples.md")
		for i := 0; i < len(expectedV4) || i < len(result); i++ {
			got := "<missing>"
			want := "<missing>"
			if i < len(result) {
				got = result[i]
			}
			if i < len(expectedV4) {
				want = expectedV4[i]
			}
			if got != want {
				t.Errorf("  line %d:\n    got:  %s\n    want: %s", i, got, want)
			}
		}
	}
}

// Test_BGPFilterBIRDFuncs_SimpleExample covers Example B from bgpfilter-bird-config-examples.md:
// a minimal filter with no PeerType, verifying backward-compatible function signatures.
func Test_BGPFilterBIRDFuncs_SimpleExample(t *testing.T) {
	testFilter := v3.BGPFilter{}
	testFilter.Name = "simple-filter"
	testFilter.Spec = v3.BGPFilterSpec{
		ImportV4: []v3.BGPFilterRuleV4{
			{
				CIDR:          "10.0.0.0/8",
				MatchOperator: v3.In,
				Action:        v3.Reject,
			},
		},
		ExportV4: []v3.BGPFilterRuleV4{
			{
				CIDR:          "192.168.0.0/16",
				MatchOperator: v3.Equal,
				Action:        v3.Accept,
			},
		},
	}

	expectedV4 := []string{
		"# v4 BGPFilter simple-filter",
		"function 'bgp_simple-filter_importFilterV4'() {",
		"  if ((net ~ 10.0.0.0/8)) then { reject; }",
		"}",
		"function 'bgp_simple-filter_exportFilterV4'() {",
		"  if ((net = 192.168.0.0/16)) then { accept; }",
		"}",
	}

	jsonFilter, err := json.Marshal(testFilter)
	if err != nil {
		t.Fatalf("Error marshalling BGPFilter: %v", err)
	}
	kvps := []memkv.KVPair{
		{Key: "simple-filter", Value: string(jsonFilter)},
	}

	result, err := BGPFilterBIRDFuncs(kvps, 4)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !reflect.DeepEqual(result, expectedV4) {
		t.Errorf("Generated BIRD config differs from Example B in bgpfilter-bird-config-examples.md:\n  Got:    %v\n  Expect: %v", result, expectedV4)
	}
}

// Test_BGPFilterBIRDFuncs_CommunityMatchOnExport verifies that community matching
// works on export rules (communities are no longer cleared for export).
func Test_BGPFilterBIRDFuncs_CommunityMatchOnExport(t *testing.T) {
	testFilter := v3.BGPFilter{}
	testFilter.Name = "export-comm"
	testFilter.Spec = v3.BGPFilterSpec{
		ExportV4: []v3.BGPFilterRuleV4{
			{
				Action:      v3.Accept,
				Communities: &v3.BGPFilterCommunityMatch{Values: []v3.BGPCommunityValue{"65000:42"}},
				Operations: []v3.BGPFilterOperation{
					{AddCommunity: &v3.BGPFilterAddCommunity{Value: "65001:100"}},
				},
			},
			{
				Action:      v3.Reject,
				Communities: &v3.BGPFilterCommunityMatch{Values: []v3.BGPCommunityValue{"65000:10:20"}},
			},
		},
	}

	expectedV4 := []string{
		"# v4 BGPFilter export-comm",
		"function 'bgp_export-comm_exportFilterV4'() {",
		"  if (((65000, 42) ~ bgp_community)) then { bgp_community.add((65001, 100)); accept; }",
		"  if (((65000, 10, 20) ~ bgp_large_community)) then { reject; }",
		"}",
	}

	jsonFilter, err := json.Marshal(testFilter)
	if err != nil {
		t.Fatalf("Error marshalling BGPFilter: %v", err)
	}
	kvps := []memkv.KVPair{
		{Key: "export-comm", Value: string(jsonFilter)},
	}

	result, err := BGPFilterBIRDFuncs(kvps, 4)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !reflect.DeepEqual(result, expectedV4) {
		t.Errorf("Community matching on export should be rendered.\n  Got:    %v\n  Expect: %v", result, expectedV4)
	}
}

// Test_BGPFilterBIRDFuncs_MixedPeerTypeAndNonPeerTypeRules verifies that when some rules
// have PeerType and others don't, the function gets the bool parameter and only the
// PeerType rules are wrapped in is_same_as guards.
func Test_BGPFilterBIRDFuncs_MixedPeerTypeAndNonPeerTypeRules(t *testing.T) {
	testFilter := v3.BGPFilter{}
	testFilter.Name = "mixed-peertype"
	testFilter.Spec = v3.BGPFilterSpec{
		ImportV4: []v3.BGPFilterRuleV4{
			{
				Action:        v3.Accept,
				PeerType:      v3.BGPFilterPeerTypeIBGP,
				CIDR:          "10.0.0.0/8",
				MatchOperator: v3.In,
				Operations: []v3.BGPFilterOperation{
					{SetPriority: &v3.BGPFilterSetPriority{Value: 100}},
				},
			},
			{
				Action:        v3.Reject,
				CIDR:          "172.16.0.0/12",
				MatchOperator: v3.In,
			},
			{
				Action:   v3.Accept,
				PeerType: v3.BGPFilterPeerTypeEBGP,
			},
		},
	}

	expectedV4 := []string{
		"# v4 BGPFilter mixed-peertype",
		"function 'bgp_mixed-peertype_importFilterV4'(bool is_same_as) {",
		"  if (is_same_as) then { if ((net ~ 10.0.0.0/8)) then { krt_metric = 100; accept; } }",
		"  if ((net ~ 172.16.0.0/12)) then { reject; }",
		"  if (!is_same_as) then { accept; }",
		"}",
	}

	jsonFilter, err := json.Marshal(testFilter)
	if err != nil {
		t.Fatalf("Error marshalling BGPFilter: %v", err)
	}
	kvps := []memkv.KVPair{
		{Key: "mixed-peertype", Value: string(jsonFilter)},
	}

	result, err := BGPFilterBIRDFuncs(kvps, 4)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !reflect.DeepEqual(result, expectedV4) {
		t.Errorf("Mixed PeerType rules should render correctly.\n  Got:    %v\n  Expect: %v", result, expectedV4)
	}
}

func int32Helper(i int32) *int32 {
	return &i
}
