package template

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/kelseyhightower/memkv"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
)

func Test_hashToIPv4_invalid_range(t *testing.T) {
	expectedRouterId := "207.94.5.27"
	nodeName := "Testrobin123"
	actualRouterId := hashToIPv4(nodeName) //invalid router_id 239.94.5.27
	if expectedRouterId != actualRouterId {
		t.Errorf(`hashToIPv4(%s) = %s, want %s`, nodeName, actualRouterId, expectedRouterId)
	}
}

func Test_hashToIPv4_valid_range(t *testing.T) {
	expectedRouterId := "109.174.215.226"
	nodeName := "nodeTest"
	actualRouterId := hashToIPv4(nodeName) //invalid router_id 239.94.5.27
	if expectedRouterId != actualRouterId {
		t.Errorf(`hashToIPv4(%s) = %s, want %s`, nodeName, actualRouterId, expectedRouterId)
	}
}

func Test_EmitFunctionName(t *testing.T) {
	str := "should-not-be-truncated"
	direction := "import"
	version := "4"
	maxFuncNameLen := 66 //Max BIRD symbol length of 64 + 2 for bookending single quotes
	output, err := EmitFunctionName(str, direction, version)
	if err != nil {
		t.Errorf("Unexpected error calling EmitFunctionName(%s, %s, %s): %s", str, direction, version, err)
	}
	if len(output) > maxFuncNameLen {
		t.Errorf(`EmitFunctionName(%s, %s, %s) has length %d which is greater than the maximum allowed of %d`,
			str, direction, version, len(output), maxFuncNameLen)
	}

	str = "very-long-name-that-should-be-truncated-because-it-is-longer-than-the-max-bird-symbol-length-of-64-chars"
	output, err = EmitFunctionName(str, direction, version)
	if err != nil {
		t.Errorf("Unexpected error calling EmitFunctionName(%s, %s, %s): %s", str, direction, version, err)
	}
	if len(output) > maxFuncNameLen {
		t.Errorf(`EmitFunctionName(%s, %s, %s) has length %d which is greater than the maximum allowed of %d`,
			str, direction, version, len(output), maxFuncNameLen)
	}
}

func Test_EmitBIRDBGPFilterFuncs(t *testing.T) {
	testFilter := v3.BGPFilter{}
	testFilter.ObjectMeta.Name = "test-bgpfilter"
	testFilter.Spec = v3.BGPFilterSpec{
		ImportV4: []v3.BGPFilterRuleV4{
			{Action: "reject", MatchOperator: "Equal", CIDR: "44.4.0.0/16"},
		},
		ExportV4: []v3.BGPFilterRuleV4{
			{Action: "accept", MatchOperator: "In", CIDR: "77.7.0.0/16"},
		},
		ImportV6: []v3.BGPFilterRuleV6{
			{Action: "reject", MatchOperator: "NotEqual", CIDR: "7000:1::0/64"},
		},
		ExportV6: []v3.BGPFilterRuleV6{
			{Action: "accept", MatchOperator: "NotIn", CIDR: "9000:1::0/64"},
		},
	}
	expectedBIRDCfgStrV4 := []string{
		"# v4 BGPFilter test-bgpfilter",
		"function 'bgp_test-bgpfilter_importFilterV4'() {",
		"  if ( net = 44.4.0.0/16 ) then { reject; }",
		"}",
		"function 'bgp_test-bgpfilter_exportFilterV4'() {",
		"  if ( net ~ 77.7.0.0/16 ) then { accept; }",
		"}",
	}
	expectedBIRDCfgStrV6 := []string{
		"# v6 BGPFilter test-bgpfilter",
		"function 'bgp_test-bgpfilter_importFilterV6'() {",
		"  if ( net != 7000:1::0/64 ) then { reject; }",
		"}",
		"function 'bgp_test-bgpfilter_exportFilterV6'() {",
		"  if ( net !~ 9000:1::0/64 ) then { accept; }",
		"}",
	}

	jsonFilter, err := json.Marshal(testFilter)
	if err != nil {
		t.Errorf("Error formatting BGPFilter into JSON: %s", err)
	}
	kvps := []memkv.KVPair{
		{Key: "test-bgpfilter", Value: string(jsonFilter)},
	}

	v4BIRDCfgResult, err := EmitBIRDBGPFilterFuncs(kvps, 4)
	if err != nil {
		t.Errorf("Unexpected error while generating v4 BIRD BGPFilter functions: %s", err)
	}
	if !reflect.DeepEqual(v4BIRDCfgResult, expectedBIRDCfgStrV4) {
		t.Errorf("Generated v4 BIRD config differs from expectation: Generated = %s, Expected = %s",
			v4BIRDCfgResult, expectedBIRDCfgStrV4)
	}

	v6BIRDCfgResult, err := EmitBIRDBGPFilterFuncs(kvps, 6)
	if err != nil {
		t.Errorf("Unexpected error while generating v6 BIRD BGPFilter functions: %s", err)
	}
	if !reflect.DeepEqual(v6BIRDCfgResult, expectedBIRDCfgStrV6) {
		t.Errorf("Generated v6 BIRD config differs from expectation: Generated = %s, Expected = %s",
			v6BIRDCfgResult, expectedBIRDCfgStrV6)
	}
}
