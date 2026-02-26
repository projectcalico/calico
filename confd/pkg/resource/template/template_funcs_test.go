package template

import (
	"testing"
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
