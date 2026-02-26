package template

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"path"
	"sort"
	"strings"
	"time"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/confd/pkg/backends"
)

func newFuncMap() map[string]any {
	m := make(map[string]any)
	m["base"] = path.Base
	m["split"] = strings.Split
	m["json"] = UnmarshalJsonObject
	m["jsonArray"] = UnmarshalJsonArray
	m["dir"] = path.Dir
	m["map"] = CreateMap
	m["join"] = strings.Join
	m["datetime"] = time.Now
	m["toUpper"] = strings.ToUpper
	m["toLower"] = strings.ToLower
	m["contains"] = strings.Contains
	m["replace"] = strings.Replace
	m["hasSuffix"] = strings.HasSuffix
	m["lookupIP"] = LookupIP
	m["lookupSRV"] = LookupSRV
	m["fileExists"] = isFileExist
	m["base64Encode"] = Base64Encode
	m["base64Decode"] = Base64Decode
	m["conditionJoin"] = ConditionJoin
	return m
}

func addFuncs(out, in map[string]any) {
	maps.Copy(out, in)
}

// addCalicoFuncs adds Calico-specific template functions
func addCalicoFuncs(funcMap map[string]any) {
	// Add getBGPConfig function that takes the ipVersion and client as parameters
	funcMap["getBGPConfig"] = func(ipVersion int, client any) (any, error) {
		if storeClient, ok := client.(backends.StoreClient); ok {
			config, err := storeClient.GetBirdBGPConfig(ipVersion)
			if err != nil {
				// Return error to fail template execution and prevent broken config
				return nil, err
			}
			return config, nil
		}
		return nil, errors.New("client does not support GetBirdBGPConfig")
	}
}

var (
	operatorLUT = map[v3.BGPFilterMatchOperator]string{
		v3.Equal:    "=",
		v3.NotEqual: "!=",
		v3.In:       "~",
		v3.NotIn:    "!~",
	}
)

func FilterMatchPrefixLength(cidr string, prefixMin, prefixMax *int32) (string, error) {
	cidrIP, cidrNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", fmt.Errorf("unexpected error when parsing cidr %s: %s", cidr, err)
	}

	mask, _ := cidrNet.Mask.Size()
	minLength := int32(mask)
	// default for ipv4
	maxLength := int32(32)

	// check for ipv6 IP
	if cidrIP.To4() == nil {
		maxLength = 128
	}

	if prefixMin != nil {
		minLength = max(minLength, *prefixMin)
	}
	if prefixMax != nil {
		maxLength = min(maxLength, *prefixMax)
	}

	return fmt.Sprintf("[ %s{%d,%d} ]", cidr, minLength, maxLength), nil
}

func FilterMatchCIDR(cidr string, prefixLengthV4 *v3.BGPFilterPrefixLengthV4, prefixLengthV6 *v3.BGPFilterPrefixLengthV6, operator v3.BGPFilterMatchOperator) (string, error) {
	op, ok := operatorLUT[operator]
	if !ok {
		return "", fmt.Errorf("unexpected operator found in BGPFilter: %s", operator)
	}

	var err error
	if prefixLengthV4 != nil {
		cidr, err = FilterMatchPrefixLength(cidr, prefixLengthV4.Min, prefixLengthV4.Max)
	} else if prefixLengthV6 != nil {
		cidr, err = FilterMatchPrefixLength(cidr, prefixLengthV6.Min, prefixLengthV6.Max)
	}

	if err != nil {
		return "", err
	}

	return fmt.Sprintf("(net %s %s)", op, cidr), nil
}

func FilterMatchSource(source v3.BGPFilterMatchSource) (string, error) {
	switch source {
	case v3.BGPFilterSourceRemotePeers:
		return "((defined(source))&&(source ~ [ RTS_BGP ]))", nil
	default:
		return "", fmt.Errorf("unexpected source found in BGPFilter: %s", source)
	}
}

func FilterMatchInterface(iface string) (string, error) {
	if iface == "" {
		return "", fmt.Errorf("empty interface found in BGPFilter")
	}
	return fmt.Sprintf("((defined(ifname))&&(ifname ~ \"%s\"))", iface), nil
}

// ConditionJoin joins non-empty condition strings with "&&" for use in BIRD filter expressions.
func ConditionJoin(conditions ...string) string {
	var nonEmpty []string
	for _, c := range conditions {
		if c != "" {
			nonEmpty = append(nonEmpty, c)
		}
	}
	return strings.Join(nonEmpty, "&&")
}

// BGPFilterFunctionName returns a formatted name for use as a BIRD function, truncating and hashing if the provided
// name would result in a function name longer than the max allowable length of 64 chars.
// e.g. input of ("my-bgp-filter", "import", "4") would result in output of "'bgp_my-bpg-filter_importFilterV4'"
func BGPFilterFunctionName(filterName, direction, version string) (string, error) {
	normalizedDirection := strings.ToLower(direction)
	if normalizedDirection != "import" && normalizedDirection != "export" {
		return "", fmt.Errorf("provided direction '%s' does not map to either 'import' or 'export'", direction)
	}
	pieces := []string{"bgp_", "", "_", normalizedDirection, "FilterV", version}
	maxBIRDSymLen := 64
	resizedName, err := TruncateAndHashName(filterName, maxBIRDSymLen-len(strings.Join(pieces, "")))
	if err != nil {
		return "", err
	}
	pieces[1] = resizedName
	fullName := strings.Join(pieces, "")
	return fmt.Sprintf("'%s'", fullName), nil
}

// CreateMap creates a key-value map of string -> interface{}
// The i'th is the key and the i+1 is the value
func CreateMap(values ...any) (map[string]any, error) {
	if len(values)%2 != 0 {
		return nil, errors.New("invalid map call")
	}
	dict := make(map[string]any, len(values)/2)
	for i := 0; i < len(values); i += 2 {
		key, ok := values[i].(string)
		if !ok {
			return nil, errors.New("map keys must be strings")
		}
		dict[key] = values[i+1]
	}
	return dict, nil
}

func UnmarshalJsonObject(data string) (map[string]any, error) {
	var ret map[string]any
	err := json.Unmarshal([]byte(data), &ret)
	return ret, err
}

func UnmarshalJsonArray(data string) ([]any, error) {
	var ret []any
	err := json.Unmarshal([]byte(data), &ret)
	return ret, err
}

func LookupIP(data string) []string {
	ips, err := net.LookupIP(data)
	if err != nil {
		return nil
	}
	// "Cast" IPs into strings and sort the array
	ipStrings := make([]string, len(ips))

	for i, ip := range ips {
		ipStrings[i] = ip.String()
	}
	sort.Strings(ipStrings)
	return ipStrings
}

type sortSRV []*net.SRV

func (s sortSRV) Len() int {
	return len(s)
}

func (s sortSRV) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func (s sortSRV) Less(i, j int) bool {
	str1 := fmt.Sprintf("%s%d%d%d", s[i].Target, s[i].Port, s[i].Priority, s[i].Weight)
	str2 := fmt.Sprintf("%s%d%d%d", s[j].Target, s[j].Port, s[j].Priority, s[j].Weight)
	return str1 < str2
}

func LookupSRV(service, proto, name string) []*net.SRV {
	_, addrs, err := net.LookupSRV(service, proto, name)
	if err != nil {
		return []*net.SRV{}
	}
	sort.Sort(sortSRV(addrs))
	return addrs
}

func Base64Encode(data string) string {
	return base64.StdEncoding.EncodeToString([]byte(data))
}

func Base64Decode(data string) (string, error) {
	s, err := base64.StdEncoding.DecodeString(data)
	return string(s), err
}
