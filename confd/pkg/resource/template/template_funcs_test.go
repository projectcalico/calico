package template

import (
	"testing"
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

func Test_TruncateAndHashName(t *testing.T) {
	str := "This is a string that should not be truncated"
	output := TruncateAndHashName(str, len(str))
	if output != str {
		t.Errorf(`TruncateAndHashName(%s, %d) = %s, want %s`, str, len(str), output, str)
	}

	str = "This is a string that should be truncated"
	expectedLen := len(str) / 2
	output = TruncateAndHashName(str, expectedLen)
	if len(output) != expectedLen {
		t.Errorf(`TruncateAndHashName(%s, %d) has length %d, want length %d`, str, expectedLen, len(output), expectedLen)
	}
}
