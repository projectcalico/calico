// Copyright (c) 2016-2017,2020 Tigera, Inc. All rights reserved.

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

package v1

import (
	"net"
	"reflect"
	"regexp"
	"strings"

	log "github.com/sirupsen/logrus"
	"gopkg.in/go-playground/validator.v9"
	k8svalidation "k8s.io/apimachinery/pkg/util/validation"

	"github.com/projectcalico/api/pkg/lib/numorstring"

	api "github.com/projectcalico/calico/libcalico-go/lib/apis/v1"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/errors"
	calinet "github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/libcalico-go/lib/scope"
	"github.com/projectcalico/calico/libcalico-go/lib/selector"
	"github.com/projectcalico/calico/libcalico-go/lib/selector/tokenizer"
	v3 "github.com/projectcalico/calico/libcalico-go/lib/validator/v3"
)

var validate *validator.Validate

var (
	labelRegex          = regexp.MustCompile(`^` + tokenizer.LabelKeyMatcher + `$`)
	labelValueRegex     = regexp.MustCompile("^[a-zA-Z0-9]?([a-zA-Z0-9_.-]{0,61}[a-zA-Z0-9])?$")
	nameRegex           = regexp.MustCompile("^[a-zA-Z0-9_.-]{1,128}$")
	namespacedNameRegex = regexp.MustCompile(`^[a-zA-Z0-9_./-]{1,128}$`)
	interfaceRegex      = regexp.MustCompile("^[a-zA-Z0-9_.-]{1,15}$")
	actionRegex         = regexp.MustCompile("^(allow|deny|log|pass)$")
	backendActionRegex  = regexp.MustCompile("^(allow|deny|log|next-tier|)$")
	protocolRegex       = regexp.MustCompile("^(tcp|udp|icmp|icmpv6|sctp|udplite)$")
	ipipModeRegex       = regexp.MustCompile("^(always|cross-subnet|)$")
	reasonString        = "Reason: "
	poolSmallIPv4       = "IP pool size is too small (min /26) for use with Calico IPAM"
	poolSmallIPv6       = "IP pool size is too small (min /122) for use with Calico IPAM"
	poolUnstictCIDR     = "IP pool CIDR is not strictly masked"
	overlapsV4LinkLocal = "IP pool range overlaps with IPv4 Link Local range 169.254.0.0/16"
	overlapsV6LinkLocal = "IP pool range overlaps with IPv6 Link Local range fe80::/10"
	protocolPortsMsg    = "rules that specify ports must set protocol to TCP or UDP or SCTP"

	ipv4LinkLocalNet = net.IPNet{
		IP:   net.ParseIP("169.254.0.0"),
		Mask: net.CIDRMask(16, 32),
	}

	ipv6LinkLocalNet = net.IPNet{
		IP:   net.ParseIP("fe80::"),
		Mask: net.CIDRMask(10, 128),
	}
)

// Validate is used to validate the supplied structure according to the
// registered field and structure validators.
func Validate(current interface{}) error {
	err := validate.Struct(current)
	if err == nil {
		return nil
	}

	verr := errors.ErrorValidation{}
	for _, f := range err.(validator.ValidationErrors) {
		verr.ErroredFields = append(verr.ErroredFields,
			errors.ErroredField{
				Name:   f.StructField(),
				Value:  f.Value(),
				Reason: extractReason(f.Tag()),
			})
	}
	return verr
}

func init() {
	// Initialise static data.
	validate = validator.New()

	// Register field validators.
	registerFieldValidator("action", validateAction)
	registerFieldValidator("interface", validateInterface)
	registerFieldValidator("backendAction", validateBackendAction)
	registerFieldValidator("name", validateName)
	registerFieldValidator("namespacedName", validateNamespacedName)
	registerFieldValidator("selector", validateSelector)
	registerFieldValidator("tag", validateTag)
	registerFieldValidator("labels", validateLabels)
	registerFieldValidator("scopeglobalornode", validateScopeGlobalOrNode)
	registerFieldValidator("ipVersion", validateIPVersion)
	registerFieldValidator("ipIpMode", validateIPIPMode)
	registerFieldValidator("policyType", validatePolicyType)
	registerFieldValidator("portName", validatePortName)
	registerFieldValidator("sourceAddress", v3.RegexValidator("SourceAddress", v3.SourceAddressRegex))

	// Register struct validators.
	// Shared types.
	registerStructValidator(validateProtocol, numorstring.Protocol{})
	registerStructValidator(validatePort, numorstring.Port{})

	// Frontend API types.
	registerStructValidator(validateIPNAT, api.IPNAT{})
	registerStructValidator(validateWorkloadEndpointSpec, api.WorkloadEndpointSpec{})
	registerStructValidator(validateHostEndpointSpec, api.HostEndpointSpec{})
	registerStructValidator(validateIPPool, api.IPPool{})
	registerStructValidator(validateICMPFields, api.ICMPFields{})
	registerStructValidator(validateRule, api.Rule{})
	registerStructValidator(validateEndpointPort, api.EndpointPort{})
	registerStructValidator(validateNodeSpec, api.NodeSpec{})
	registerStructValidator(validateBGPPeerMeta, api.BGPPeerMetadata{})
	registerStructValidator(validatePolicySpec, api.PolicySpec{})

	// Backend model types.
	registerStructValidator(validateBackendRule, model.Rule{})
	registerStructValidator(validateBackendEndpointPort, model.EndpointPort{})
}

// reason returns the provided error reason prefixed with an identifier that
// allows the string to be used as the field tag in the validator and then
// re-extracted as the reason when the validator returns a field error.
func reason(r string) string {
	return reasonString + r
}

// extractReason extracts the error reason from the field tag in a validator
// field error (if there is one).
func extractReason(tag string) string {
	if strings.HasPrefix(tag, reasonString) {
		return strings.TrimPrefix(tag, reasonString)
	}
	return ""
}

func registerFieldValidator(key string, fn validator.Func) {
	validate.RegisterValidation(key, fn)
}

func registerStructValidator(fn validator.StructLevelFunc, t ...interface{}) {
	validate.RegisterStructValidation(fn, t...)
}

func validateAction(fl validator.FieldLevel) bool {
	s := fl.Field().String()
	log.Debugf("Validate action: %s", s)
	return actionRegex.MatchString(s)
}

func validateInterface(fl validator.FieldLevel) bool {
	s := fl.Field().String()
	log.Debugf("Validate interface: %s", s)
	return s == "*" || interfaceRegex.MatchString(s)
}

func validateBackendAction(fl validator.FieldLevel) bool {
	s := fl.Field().String()
	log.Debugf("Validate action: %s", s)
	return backendActionRegex.MatchString(s)
}

func validateName(fl validator.FieldLevel) bool {
	s := fl.Field().String()
	log.Debugf("Validate name: %s", s)
	return nameRegex.MatchString(s)
}

func validateNamespacedName(fl validator.FieldLevel) bool {
	s := fl.Field().String()
	log.Debugf("Validate namespacedName: %s", s)
	return namespacedNameRegex.MatchString(s)
}

func validateIPVersion(fl validator.FieldLevel) bool {
	ver := fl.Field().Int()
	log.Debugf("Validate ip version: %d", ver)
	return ver == 4 || ver == 6
}

func validateIPIPMode(fl validator.FieldLevel) bool {
	s := fl.Field().String()
	log.Debugf("Validate name: %s", s)
	return ipipModeRegex.MatchString(s)
}

func validatePortName(fl validator.FieldLevel) bool {
	s := fl.Field().String()
	log.Debugf("Validate port name: %s", s)
	return len(s) != 0 && len(k8svalidation.IsValidPortName(s)) == 0
}

func validateSelector(fl validator.FieldLevel) bool {
	s := fl.Field().String()
	log.Debugf("Validate selector: %s", s)

	// We use the selector parser to validate a selector string.
	_, err := selector.Parse(s)
	if err != nil {
		log.Debugf("Selector %#v was invalid: %v", s, err)
		return false
	}
	return true
}

func validateTag(fl validator.FieldLevel) bool {
	s := fl.Field().String()
	log.Debugf("Validate tag: %s", s)
	return nameRegex.MatchString(s)
}

func validateLabels(fl validator.FieldLevel) bool {
	l := fl.Field().Interface().(map[string]string)
	log.Debugf("Validate labels: %s", l)
	for k, v := range l {
		if !labelRegex.MatchString(k) || !labelValueRegex.MatchString(v) {
			return false
		}
	}
	return true
}

func validateScopeGlobalOrNode(fl validator.FieldLevel) bool {
	f := fl.Field().Interface().(scope.Scope)
	log.Debugf("Validate scope: %v", f)
	return f == scope.Global || f == scope.Node
}

func validatePolicyType(fl validator.FieldLevel) bool {
	s := fl.Field().String()
	log.Debugf("Validate policy type: %s", s)
	if s == string(api.PolicyTypeIngress) {
		return true
	}
	if s == string(api.PolicyTypeEgress) {
		return true
	}
	return false
}

func validateProtocol(structLevel validator.StructLevel) {
	p := structLevel.Current().Interface().(numorstring.Protocol)
	log.Debugf("Validate protocol: %v %s %d", p.Type, p.StrVal, p.NumVal)

	// The protocol field may be an integer 1-255 (i.e. not 0), or one of the valid protocol
	// names.
	if num, err := p.NumValue(); err == nil {
		if num == 0 {
			structLevel.ReportError(reflect.ValueOf(p.NumVal),
				"Protocol", "", reason("protocol number invalid"), "")
		}
	} else if !protocolRegex.MatchString(p.String()) {
		structLevel.ReportError(reflect.ValueOf(p.String()),
			"Protocol", "", reason("protocol name invalid"), "")
	}
}

func validatePort(structLevel validator.StructLevel) {
	p := structLevel.Current().Interface().(numorstring.Port)

	// Check that the port range is in the correct order.  The YAML parsing also checks this,
	// but this protects against misuse of the programmatic API.
	log.Debugf("Validate port: %v", p)
	if p.MinPort > p.MaxPort {
		structLevel.ReportError(reflect.ValueOf(p.MaxPort),
			"Port", "", reason("port range invalid"), "")
	}

	if p.PortName != "" {
		if p.MinPort != 0 || p.MaxPort != 0 {
			structLevel.ReportError(reflect.ValueOf(p.PortName),
				"Port", "", reason("named port invalid, if name is specified, min and max should be 0"), "")
		}
	} else if p.MinPort < 1 || p.MaxPort < 1 {
		structLevel.ReportError(reflect.ValueOf(p.MaxPort),
			"Port", "", reason("port range invalid, port number must be between 0 and 65536"), "")
	}
}

func validateIPNAT(structLevel validator.StructLevel) {
	i := structLevel.Current().Interface().(api.IPNAT)
	log.Debugf("Internal IP: %s; External IP: %s", i.InternalIP, i.ExternalIP)

	// An IPNAT must have both the internal and external IP versions the same.
	if i.InternalIP.Version() != i.ExternalIP.Version() {
		structLevel.ReportError(reflect.ValueOf(i.ExternalIP),
			"ExternalIP", "", reason("mismatched IP versions"), "")
	}
}

func validateWorkloadEndpointSpec(structLevel validator.StructLevel) {
	w := structLevel.Current().Interface().(api.WorkloadEndpointSpec)

	// The configured networks only support /32 (for IPv4) and /128 (for IPv6) at present.
	for _, netw := range w.IPNetworks {
		ones, bits := netw.Mask.Size()
		if bits != ones {
			structLevel.ReportError(reflect.ValueOf(w.IPNetworks),
				"IPNetworks", "", reason("IP network contains multiple addresses"), "")
		}
	}

	if w.IPv4Gateway != nil && w.IPv4Gateway.Version() != 4 {
		structLevel.ReportError(reflect.ValueOf(w.IPv4Gateway),
			"IPv4Gateway", "", reason("invalid IPv4 gateway address specified"), "")
	}

	if w.IPv6Gateway != nil && w.IPv6Gateway.Version() != 6 {
		structLevel.ReportError(reflect.ValueOf(w.IPv6Gateway),
			"IPv6Gateway", "", reason("invalid IPv6 gateway address specified"), "")
	}

	// If NATs have been specified, then they should each be within the configured networks of
	// the endpoint.
	if len(w.IPNATs) > 0 {
		valid := false
		for _, nat := range w.IPNATs {
			// Check each NAT to ensure it is within the configured networks.  If any
			// are not then exit without further checks.
			valid = false
			for _, nw := range w.IPNetworks {
				if nw.Contains(nat.InternalIP.IP) {
					valid = true
					break
				}
			}
			if !valid {
				break
			}
		}

		if !valid {
			structLevel.ReportError(reflect.ValueOf(w.IPNATs),
				"IPNATs", "", reason("NAT is not in the endpoint networks"), "")
		}
	}
}

func validateHostEndpointSpec(structLevel validator.StructLevel) {
	h := structLevel.Current().Interface().(api.HostEndpointSpec)

	// A host endpoint must have an interface name and/or some expected IPs specified.
	if h.InterfaceName == "" && len(h.ExpectedIPs) == 0 {
		structLevel.ReportError(reflect.ValueOf(h.InterfaceName),
			"InterfaceName", "", reason("no interface or expected IPs have been specified"), "")
	}
}

func validateIPPool(structLevel validator.StructLevel) {
	pool := structLevel.Current().Interface().(api.IPPool)

	// Validation of the data occurs before checking whether Metadata
	// fields are complete, so need to check whether CIDR is assigned before
	// performing cross-checks.  If CIDR is not assigned this will be
	// picked up during Metadata->Key conversion.
	if pool.Metadata.CIDR.IP != nil {
		// IPIP cannot be enabled for IPv6.
		if pool.Metadata.CIDR.Version() == 6 && pool.Spec.IPIP != nil && pool.Spec.IPIP.Enabled {
			structLevel.ReportError(reflect.ValueOf(pool.Spec.IPIP.Enabled),
				"IPIP.Enabled", "", reason("IPIP is not supported on an IPv6 IP pool"), "")
		}

		// The Calico IPAM places restrictions on the minimum IP pool size.  If
		// the pool is enabled, check that the pool is at least the minimum size.
		if !pool.Spec.Disabled {
			ones, bits := pool.Metadata.CIDR.Mask.Size()
			log.Debugf("Pool CIDR: %s, num bits: %d", pool.Metadata.CIDR, bits-ones)
			if bits-ones < 6 {
				if pool.Metadata.CIDR.Version() == 4 {
					structLevel.ReportError(reflect.ValueOf(pool.Metadata.CIDR),
						"CIDR", "", reason(poolSmallIPv4), "")
				} else {
					structLevel.ReportError(reflect.ValueOf(pool.Metadata.CIDR),
						"CIDR", "", reason(poolSmallIPv6), "")
				}
			}
		}

		// The Calico CIDR should be strictly masked
		ip, ipNet, _ := net.ParseCIDR(pool.Metadata.CIDR.String())
		log.Debugf("Pool CIDR: %s, Masked IP: %d", pool.Metadata.CIDR, ipNet.IP)
		if ipNet.IP.String() != ip.String() {
			structLevel.ReportError(reflect.ValueOf(pool.Metadata.CIDR),
				"CIDR", "", reason(poolUnstictCIDR), "")
		}

		// IP Pool CIDR cannot overlap with IPv4 or IPv6 link local address range.
		if pool.Metadata.CIDR.Version() == 4 && pool.Metadata.CIDR.IsNetOverlap(ipv4LinkLocalNet) {
			structLevel.ReportError(reflect.ValueOf(pool.Metadata.CIDR),
				"CIDR", "", reason(overlapsV4LinkLocal), "")
		}

		if pool.Metadata.CIDR.Version() == 6 && pool.Metadata.CIDR.IsNetOverlap(ipv6LinkLocalNet) {
			structLevel.ReportError(reflect.ValueOf(pool.Metadata.CIDR),
				"CIDR", "", reason(overlapsV6LinkLocal), "")
		}
	}
}

func validateICMPFields(structLevel validator.StructLevel) {
	icmp := structLevel.Current().Interface().(api.ICMPFields)

	// Due to Kernel limitations, ICMP code must always be specified with a type.
	if icmp.Code != nil && icmp.Type == nil {
		structLevel.ReportError(reflect.ValueOf(icmp.Code),
			"Code", "", reason("ICMP code specified without an ICMP type"), "")
	}
}

func validateRule(structLevel validator.StructLevel) {
	rule := structLevel.Current().Interface().(api.Rule)

	// If the protocol does not support ports, check that the port values have not
	// been specified.
	if rule.Protocol == nil || !rule.Protocol.SupportsPorts() {
		if len(rule.Source.Ports) > 0 {
			structLevel.ReportError(reflect.ValueOf(rule.Source.Ports),
				"Source.Ports", "", reason(protocolPortsMsg), "")
		}
		if len(rule.Source.NotPorts) > 0 {
			structLevel.ReportError(reflect.ValueOf(rule.Source.NotPorts),
				"Source.NotPorts", "", reason(protocolPortsMsg), "")
		}

		if len(rule.Destination.Ports) > 0 {
			structLevel.ReportError(reflect.ValueOf(rule.Destination.Ports),
				"Destination.Ports", "", reason(protocolPortsMsg), "")
		}
		if len(rule.Destination.NotPorts) > 0 {
			structLevel.ReportError(reflect.ValueOf(rule.Destination.NotPorts),
				"Destination.NotPorts", "", reason(protocolPortsMsg), "")
		}
	}

	// Check that only one of the net or nets fields is specified.
	hasNetField := rule.Source.Net != nil ||
		rule.Destination.Net != nil ||
		rule.Source.NotNet != nil ||
		rule.Destination.NotNet != nil
	hasNetsField := len(rule.Source.Nets) != 0 ||
		len(rule.Destination.Nets) != 0 ||
		len(rule.Source.NotNets) != 0 ||
		len(rule.Destination.NotNets) != 0
	if hasNetField && hasNetsField {
		structLevel.ReportError(reflect.ValueOf(rule.Source.Nets),
			"Source/Destination.Net/Nets",
			"Source/Destination.Net/Nets",
			reason("only one of Net and Nets fields allowed"),
			"")
	}

	var seenV4, seenV6 bool

	scanNets := func(nets []*calinet.IPNet, fieldName string) {
		var v4, v6 bool
		for _, n := range nets {
			v4 = v4 || n.Version() == 4
			v6 = v6 || n.Version() == 6
		}
		if rule.IPVersion != nil && ((v4 && *rule.IPVersion != 4) || (v6 && *rule.IPVersion != 6)) {
			structLevel.ReportError(reflect.ValueOf(rule.Source.Net), fieldName,
				"", reason("rule IP version doesn't match CIDR version"), "")
		}
		if v4 && seenV6 || v6 && seenV4 || v4 && v6 {
			// This field makes the rule inconsistent.
			structLevel.ReportError(reflect.ValueOf(nets), fieldName,
				"", reason("rule contains both IPv4 and IPv6 CIDRs"), "")
		}
		seenV4 = seenV4 || v4
		seenV6 = seenV6 || v6
	}

	scanNets(rule.Source.GetNets(), "Source.Net(s)")
	scanNets(rule.Source.GetNotNets(), "Source.NotNet(s)")
	scanNets(rule.Destination.GetNets(), "Destination.Net(s)")
	scanNets(rule.Destination.GetNotNets(), "Destination.NotNet(s)")
}

func validateBackendRule(structLevel validator.StructLevel) {
	rule := structLevel.Current().Interface().(model.Rule)

	// If the protocol does not support ports check that the port values have not
	// been specified.
	if rule.Protocol == nil || !rule.Protocol.SupportsPorts() {
		if len(rule.SrcPorts) > 0 {
			structLevel.ReportError(reflect.ValueOf(rule.SrcPorts),
				"SrcPorts", "", reason(protocolPortsMsg), "")
		}
		if len(rule.NotSrcPorts) > 0 {
			structLevel.ReportError(reflect.ValueOf(rule.NotSrcPorts),
				"NotSrcPorts", "", reason(protocolPortsMsg), "")
		}

		if len(rule.DstPorts) > 0 {
			structLevel.ReportError(reflect.ValueOf(rule.DstPorts),
				"DstPorts", "", reason(protocolPortsMsg), "")
		}
		if len(rule.NotDstPorts) > 0 {
			structLevel.ReportError(reflect.ValueOf(rule.NotDstPorts),
				"NotDstPorts", "", reason(protocolPortsMsg), "")
		}
	}
}

func validateNodeSpec(structLevel validator.StructLevel) {
	ns := structLevel.Current().Interface().(api.NodeSpec)

	if ns.BGP != nil {
		if ns.BGP.IPv4Address == nil && ns.BGP.IPv6Address == nil {
			structLevel.ReportError(reflect.ValueOf(ns.BGP.IPv4Address),
				"BGP.IPv4Address", "", reason("no BGP IP address and subnet specified"), "")
		}

		if ns.BGP.IPv4Address != nil && ns.BGP.IPv4Address.Version() != 4 {
			structLevel.ReportError(reflect.ValueOf(ns.BGP.IPv4Address),
				"BGP.IPv4Address", "", reason("invalid IPv4 address and subnet specified"), "")
		}

		if ns.BGP.IPv6Address != nil && ns.BGP.IPv6Address.Version() != 6 {
			structLevel.ReportError(reflect.ValueOf(ns.BGP.IPv6Address),
				"BGP.IPv6Address", "", reason("invalid IPv6 address and subnet specified"), "")
		}
	}
}

func validateBGPPeerMeta(structLevel validator.StructLevel) {
	m := structLevel.Current().Interface().(api.BGPPeerMetadata)

	if m.Scope == scope.Global && m.Node != "" {
		structLevel.ReportError(reflect.ValueOf(m.Node),
			"Metadata.Node", "", reason("no BGP Peer node name should be specified when scope is global"), "")
	}
}

func validateBackendEndpointPort(structLevel validator.StructLevel) {
	port := structLevel.Current().Interface().(model.EndpointPort)

	if port.Protocol.String() != "tcp" && port.Protocol.String() != "udp" && port.Protocol.String() != "sctp" {
		structLevel.ReportError(
			reflect.ValueOf(port.Protocol),
			"EndpointPort.Protocol",
			"",
			reason("EndpointPort protocol must be 'tcp' or 'udp' or 'sctp'."),
			"",
		)
	}
}

func validateEndpointPort(structLevel validator.StructLevel) {
	port := structLevel.Current().Interface().(api.EndpointPort)

	if port.Protocol.String() != "tcp" && port.Protocol.String() != "udp" && port.Protocol.String() != "sctp" {
		structLevel.ReportError(
			reflect.ValueOf(port.Protocol),
			"EndpointPort.Protocol",
			"",
			reason("EndpointPort protocol must be 'tcp' or 'udp' or 'sctp'."),
			"",
		)
	}
}

func validatePolicySpec(structLevel validator.StructLevel) {
	m := structLevel.Current().Interface().(api.PolicySpec)

	if m.DoNotTrack && m.PreDNAT {
		structLevel.ReportError(reflect.ValueOf(m.PreDNAT),
			"PolicySpec.PreDNAT", "", reason("PreDNAT and DoNotTrack cannot both be true, for a given PolicySpec"), "")
	}

	if m.PreDNAT && len(m.EgressRules) > 0 {
		structLevel.ReportError(reflect.ValueOf(m.EgressRules),
			"PolicySpec.EgressRules", "", reason("PreDNAT PolicySpec cannot have any EgressRules"), "")
	}

	if m.PreDNAT && len(m.Types) > 0 {
		for _, t := range m.Types {
			if t == api.PolicyTypeEgress {
				structLevel.ReportError(reflect.ValueOf(m.Types),
					"PolicySpec.Types", "", reason("PreDNAT PolicySpec cannot have 'egress' Type"), "")
			}
		}
	}

	// Check (and disallow) any repeats in Types field.
	mp := map[api.PolicyType]bool{}
	for _, t := range m.Types {
		if _, exists := mp[t]; exists {
			structLevel.ReportError(reflect.ValueOf(m.Types),
				"PolicySpec.Types", "", reason("'"+string(t)+"' type specified more than once"), "")
		} else {
			mp[t] = true
		}
	}
}
