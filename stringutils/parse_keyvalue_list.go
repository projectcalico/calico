package stringutils

// https://play.golang.org/p/xSEX1CAcQE

import (
	"fmt"
	"regexp"
	"strings"
)

var rex = regexp.MustCompile("\\s*(\\w+)=(.+)")

// ParseKeyValueList parses a comma-separated key=value list to a map.
// Keys must contain only word characters (leading spaces ignored).
// A valid map is always returned even when the error is != nil.
// Spaces in the value are preserved.
func ParseKeyValueList(param string) (*map[string]string, error) {
	res := make(map[string]string)
	if len(strings.TrimSpace(param)) == 0 {
		return &res, nil
	}
	var invalidItems []string
	for _, item := range strings.Split(param, ",") {
		if item == "" {
			// Accept empty items (e.g tailing ",")
			continue
		}
		kv := rex.FindStringSubmatch(item)
		if kv == nil {
			invalidItems = append(invalidItems, item)
			continue
		}
		res[kv[1]] = kv[2]
	}
	if len(invalidItems) > 0 {
		return &res, fmt.Errorf("Invalid items %v", invalidItems)
	}
	return &res, nil
}
