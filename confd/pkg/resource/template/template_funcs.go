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

	"github.com/kelseyhightower/memkv"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"

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
	m["bgpFilterBIRDFuncs"] = BGPFilterBIRDFuncs
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

// filterStatement produces a single comparison expression to be used within a multi-statement BIRD filter
// function.
// e.g input of ("In", "77.0.0.1/16", "accept") produces output of "if ((net ~ 77.0.0.1/16)) then { accept; }"
//
// When operations are present (only valid with Accept action), the output becomes a block:
//
//	if (<conditions>) then { <op1>; <op2>; accept; }
func filterStatement(fields filterArgs) (string, error) {
	actionStatement, err := filterAction(fields.action)
	if err != nil {
		return "", err
	}

	var conditions []string
	if fields.cidr != "" {
		if fields.operator == "" {
			return "", fmt.Errorf("operator not included in BGPFilter")
		}
		cidrCondition, err := filterMatchCIDR(fields.cidr, fields.prefixLengthV4, fields.prefixLengthV6, fields.operator)
		if err != nil {
			return "", err
		}
		conditions = append(conditions, cidrCondition)
	}

	if fields.source != "" {
		sourceCondition, err := filterMatchSource(fields.source)
		if err != nil {
			return "", err
		}
		conditions = append(conditions, sourceCondition)
	}

	if fields.iface != "" {
		ifaceCondition, err := filterMatchInterface(fields.iface)
		if err != nil {
			return "", err
		}
		conditions = append(conditions, ifaceCondition)
	}

	if fields.communities != nil {
		communityCondition, err := filterMatchCommunity(fields.communities)
		if err != nil {
			return "", err
		}
		conditions = append(conditions, communityCondition)
	}

	if len(fields.asPathPrefix) > 0 {
		aspCondition, err := filterMatchASPathPrefix(fields.asPathPrefix)
		if err != nil {
			return "", err
		}
		conditions = append(conditions, aspCondition)
	}

	if fields.priority != nil {
		priorityCondition, err := filterMatchPriority(fields.priority)
		if err != nil {
			return "", err
		}
		conditions = append(conditions, priorityCondition)
	}

	// Build the body: operations (if any) followed by the action.
	var bodyParts []string
	if len(fields.operations) > 0 {
		opStmts, err := filterOperationStatements(fields.operations)
		if err != nil {
			return "", err
		}
		bodyParts = append(bodyParts, opStmts...)
	}
	bodyParts = append(bodyParts, actionStatement)
	body := strings.Join(bodyParts, " ")

	conditionExpr := strings.Join(conditions, "&&")
	if conditionExpr != "" {
		return fmt.Sprintf("if (%s) then { %s }", conditionExpr, body), nil
	}
	return body, nil
}

func filterAction(action v3.BGPFilterAction) (string, error) {
	if action != v3.Accept && action != v3.Reject {
		return "", fmt.Errorf("unexpected action found in BGPFilter: %s", action)
	}
	return fmt.Sprintf("%s;", strings.ToLower(string(action))), nil
}

var (
	operatorLUT = map[v3.BGPFilterMatchOperator]string{
		v3.MatchOperatorEqual:    "=",
		v3.MatchOperatorNotEqual: "!=",
		v3.MatchOperatorIn:       "~",
		v3.MatchOperatorNotIn:    "!~",
	}
)

func filterMatchPrefixLength(cidr string, prefixMin, prefixMax *int32) (string, error) {
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

func filterMatchCIDR(cidr string, prefixLengthV4 *v3.BGPFilterPrefixLengthV4, prefixLengthV6 *v3.BGPFilterPrefixLengthV6, operator v3.BGPFilterMatchOperator) (string, error) {
	op, ok := operatorLUT[operator]
	if !ok {
		return "", fmt.Errorf("unexpected operator found in BGPFilter: %s", operator)
	}

	var err error
	if prefixLengthV4 != nil {
		cidr, err = filterMatchPrefixLength(cidr, prefixLengthV4.Min, prefixLengthV4.Max)
	} else if prefixLengthV6 != nil {
		cidr, err = filterMatchPrefixLength(cidr, prefixLengthV6.Min, prefixLengthV6.Max)
	}

	if err != nil {
		return "", err
	}

	return fmt.Sprintf("(net %s %s)", op, cidr), nil
}

func filterMatchSource(source v3.BGPFilterMatchSource) (string, error) {
	switch source {
	case v3.BGPFilterSourceRemotePeers:
		return "((defined(source))&&(source ~ [ RTS_BGP ]))", nil
	default:
		return "", fmt.Errorf("unexpected source found in BGPFilter: %s", source)
	}
}

func filterMatchInterface(iface string) (string, error) {
	if iface == "" {
		return "", fmt.Errorf("empty interface found in BGPFilter")
	}
	return fmt.Sprintf("((defined(ifname))&&(ifname ~ \"%s\"))", iface), nil
}

// filterMatchCommunity generates a BIRD condition that checks if a route has the specified community.
// Standard communities (aa:nn) use bgp_community, large communities (aa:nn:mm) use bgp_large_community.
func filterMatchCommunity(communities *v3.BGPFilterCommunityMatch) (string, error) {
	if communities == nil || len(communities.Values) == 0 {
		return "", fmt.Errorf("empty communities in BGPFilter")
	}
	// Currently MaxItems=1, so we only handle one value.
	value := string(communities.Values[0])
	parts := strings.Split(value, ":")
	switch len(parts) {
	case 2:
		// Standard community: (aa, nn) ~ bgp_community
		return fmt.Sprintf("((%s, %s) ~ bgp_community)", parts[0], parts[1]), nil
	case 3:
		// Large community: (aa, nn, mm) ~ bgp_large_community
		return fmt.Sprintf("((%s, %s, %s) ~ bgp_large_community)", parts[0], parts[1], parts[2]), nil
	default:
		return "", fmt.Errorf("invalid community value format in BGPFilter: %s", value)
	}
}

// filterMatchASPathPrefix generates a BIRD condition that checks if a route's AS path begins
// with the specified sequence of AS numbers.
func filterMatchASPathPrefix(asPathPrefix []numorstring.ASNumber) (string, error) {
	if len(asPathPrefix) == 0 {
		return "", fmt.Errorf("empty AS path prefix in BGPFilter")
	}
	var asns []string
	for _, asn := range asPathPrefix {
		asns = append(asns, asn.String())
	}
	return fmt.Sprintf("(bgp_path ~ [= %s * =])", strings.Join(asns, " ")), nil
}

// filterMatchPriority generates a BIRD condition that checks if a route has the specified
// priority (krt_metric).
func filterMatchPriority(priority *int) (string, error) {
	if priority == nil {
		return "", fmt.Errorf("nil priority in BGPFilter")
	}
	return fmt.Sprintf("(krt_metric = %d)", *priority), nil
}

// filterOperationStatements generates BIRD statements for the operations in a filter rule.
func filterOperationStatements(operations []v3.BGPFilterOperation) ([]string, error) {
	var stmts []string
	for _, op := range operations {
		if op.AddCommunity != nil {
			if op.AddCommunity.Value == nil {
				return nil, fmt.Errorf("BGPFilter AddCommunity operation has nil value")
			}
			parts := strings.Split(string(*op.AddCommunity.Value), ":")
			switch len(parts) {
			case 2:
				stmts = append(stmts, fmt.Sprintf("bgp_community.add((%s, %s));", parts[0], parts[1]))
			case 3:
				stmts = append(stmts, fmt.Sprintf("bgp_large_community.add((%s, %s, %s));", parts[0], parts[1], parts[2]))
			default:
				return nil, fmt.Errorf("invalid community value format in BGPFilter operation: %s", *op.AddCommunity.Value)
			}
		} else if op.PrependASPath != nil {
			// BIRD prepends one ASN at a time. The last prepend ends up first in the path,
			// so we iterate in reverse to get the desired order.
			for i := len(op.PrependASPath.Prefix) - 1; i >= 0; i-- {
				stmts = append(stmts, fmt.Sprintf("bgp_path.prepend(%s);", op.PrependASPath.Prefix[i].String()))
			}
		} else if op.SetPriority != nil {
			if op.SetPriority.Value == nil {
				return nil, fmt.Errorf("BGPFilter SetPriority operation has nil value")
			}
			stmts = append(stmts, fmt.Sprintf("krt_metric = %d;", *op.SetPriority.Value))
		} else {
			return nil, fmt.Errorf("BGPFilter operation has no field set")
		}
	}
	return stmts, nil
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

type filterArgs struct {
	operator       v3.BGPFilterMatchOperator
	cidr           string
	prefixLengthV4 *v3.BGPFilterPrefixLengthV4
	prefixLengthV6 *v3.BGPFilterPrefixLengthV6
	source         v3.BGPFilterMatchSource
	iface          string
	peerType       v3.BGPFilterPeerType
	communities    *v3.BGPFilterCommunityMatch
	asPathPrefix   []numorstring.ASNumber
	priority       *int
	action         v3.BGPFilterAction
	operations     []v3.BGPFilterOperation
}

// filterArgsFromRuleV4 converts a BGPFilterRuleV4 to filterArgs.
func filterArgsFromRuleV4(rule v3.BGPFilterRuleV4) filterArgs {
	return filterArgs{
		operator:       rule.MatchOperator,
		cidr:           rule.CIDR,
		prefixLengthV4: rule.PrefixLength,
		source:         rule.Source,
		iface:          rule.Interface,
		peerType:       rule.PeerType,
		communities:    rule.Communities,
		asPathPrefix:   rule.ASPathPrefix,
		priority:       rule.Priority,
		action:         rule.Action,
		operations:     rule.Operations,
	}
}

// filterArgsFromRuleV6 converts a BGPFilterRuleV6 to filterArgs.
func filterArgsFromRuleV6(rule v3.BGPFilterRuleV6) filterArgs {
	return filterArgs{
		operator:       rule.MatchOperator,
		cidr:           rule.CIDR,
		prefixLengthV6: rule.PrefixLength,
		source:         rule.Source,
		iface:          rule.Interface,
		peerType:       rule.PeerType,
		communities:    rule.Communities,
		asPathPrefix:   rule.ASPathPrefix,
		priority:       rule.Priority,
		action:         rule.Action,
		operations:     rule.Operations,
	}
}

// hasPeerTypeRules returns true if any of the given filterArgs have a PeerType set.
func hasPeerTypeRules(rules []filterArgs) bool {
	for _, r := range rules {
		if r.peerType != "" {
			return true
		}
	}
	return false
}

// BGPFilterBIRDFuncs generates the definitions of a set of BIRD functions for all configured BGPFilter resources.
//
// For each direction (import/export), if any rule for that direction within a filter uses PeerType,
// the generated function for that direction takes a bool parameter:
//
//	function 'bgp_myfilter_importFilterV4'(bool is_same_as) { ... }
//
// Within such a function, rules with PeerType are wrapped in if (is_same_as) / if (!is_same_as) guards.
func BGPFilterBIRDFuncs(pairs memkv.KVPairs, version int) ([]string, error) {
	var lines []string
	var versionStr string

	if version == 4 || version == 6 {
		versionStr = fmt.Sprintf("%d", version)
	} else {
		return nil, fmt.Errorf("version must be either 4 or 6")
	}

	v4Selected := version == 4

	type directionInput struct {
		dir string
		v4  []v3.BGPFilterRuleV4
		v6  []v3.BGPFilterRuleV6
	}
	type directionRules struct {
		direction string
		rules     []filterArgs
	}

	for _, kvp := range pairs {
		var filter v3.BGPFilter
		err := json.Unmarshal([]byte(kvp.Value), &filter)
		if err != nil {
			return nil, fmt.Errorf("error unmarshalling JSON: %s", err)
		}

		// Build rules for each direction, converting V4/V6 to unified filterArgs.
		var directions []directionRules
		for _, d := range []directionInput{
			{"import", filter.Spec.ImportV4, filter.Spec.ImportV6},
			{"export", filter.Spec.ExportV4, filter.Spec.ExportV6},
		} {
			var ruleFields []filterArgs
			if v4Selected {
				for _, rule := range d.v4 {
					ruleFields = append(ruleFields, filterArgsFromRuleV4(rule))
				}
			} else {
				for _, rule := range d.v6 {
					ruleFields = append(ruleFields, filterArgsFromRuleV6(rule))
				}
			}
			if len(ruleFields) > 0 {
				directions = append(directions, directionRules{d.dir, ruleFields})
			}
		}

		if len(directions) == 0 {
			continue
		}

		filterName := path.Base(kvp.Key)
		lines = append(lines, fmt.Sprintf("# v%s BGPFilter %s", versionStr, filterName))

		for _, dr := range directions {
			filterFuncName, err := BGPFilterFunctionName(filterName, dr.direction, versionStr)
			if err != nil {
				return nil, err
			}

			if hasPeerTypeRules(dr.rules) {
				lines = append(lines, fmt.Sprintf("function %s(bool is_same_as) {", filterFuncName))
			} else {
				lines = append(lines, fmt.Sprintf("function %s() {", filterFuncName))
			}

			// Emit each rule as a BIRD statement, wrapping with PeerType guard if needed.
			for _, fields := range dr.rules {
				filterRule, err := filterStatement(fields)
				if err != nil {
					return nil, err
				}

				switch fields.peerType {
				case v3.BGPFilterPeerTypeIBGP:
					filterRule = fmt.Sprintf("if (is_same_as) then { %s }", filterRule)
				case v3.BGPFilterPeerTypeEBGP:
					filterRule = fmt.Sprintf("if (!is_same_as) then { %s }", filterRule)
				}

				lines = append(lines, fmt.Sprintf("  %s", filterRule))
			}

			lines = append(lines, "}")
		}
	}
	if len(lines) == 0 {
		lines = append(lines, fmt.Sprintf("# No v%s BGPFilters configured", versionStr))
	}
	return lines, nil
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
