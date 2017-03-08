// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.

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

package validator

import (
	"reflect"
	"regexp"
	"strings"

	log "github.com/Sirupsen/logrus"
	"github.com/projectcalico/libcalico-go/lib/api"
	"github.com/projectcalico/libcalico-go/lib/errors"
	"github.com/projectcalico/libcalico-go/lib/numorstring"
	"github.com/projectcalico/libcalico-go/lib/scope"
	"github.com/projectcalico/libcalico-go/lib/selector"
	"github.com/projectcalico/libcalico-go/lib/selector/tokenizer"

	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"gopkg.in/go-playground/validator.v8"
)

var validate *validator.Validate

var (
	labelRegex         = regexp.MustCompile(`^` + tokenizer.LabelKeyMatcher + `$`)
	labelValueRegex    = regexp.MustCompile("^[a-zA-Z0-9]?([a-zA-Z0-9_.-]{0,61}[a-zA-Z0-9])?$")
	nameRegex          = regexp.MustCompile("^[a-zA-Z0-9_.-]{1,128}$")
	interfaceRegex     = regexp.MustCompile("^[a-zA-Z0-9_-]{1,15}$")
	actionRegex        = regexp.MustCompile("^(allow|deny|log|pass)$")
	backendActionRegex = regexp.MustCompile("^(allow|deny|log|next-tier|)$")
	protocolRegex      = regexp.MustCompile("^(tcp|udp|icmp|icmpv6|sctp|udplite)$")
	ipipModeRegex      = regexp.MustCompile("^(always|cross-subnet|)$")
	reasonString       = "Reason: "
	poolSmallIPv4      = "IP pool size is too small (min /26) for use with Calico IPAM"
	poolSmallIPv6      = "IP pool size is too small (min /122) for use with Calico IPAM"
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
				Name:   f.Name,
				Value:  f.Value,
				Reason: extractReason(f.Tag),
			})
	}
	return verr
}

func init() {
	// Initialise static data.
	config := &validator.Config{TagName: "validate", FieldNameTag: "json"}
	validate = validator.New(config)

	// Register field validators.
	registerFieldValidator("action", validateAction)
	registerFieldValidator("interface", validateInterface)
	registerFieldValidator("backendaction", validateBackendAction)
	registerFieldValidator("name", validateName)
	registerFieldValidator("selector", validateSelector)
	registerFieldValidator("tag", validateTag)
	registerFieldValidator("labels", validateLabels)
	registerFieldValidator("scopeglobalornode", validateScopeGlobalOrNode)
	registerFieldValidator("ipversion", validateIPVersion)
	registerFieldValidator("ipipmode", validateIPIPMode)

	// Register struct validators.
	registerStructValidator(validateProtocol, numorstring.Protocol{})
	registerStructValidator(validatePort, numorstring.Port{})
	registerStructValidator(validateIPNAT, api.IPNAT{})
	registerStructValidator(validateWorkloadEndpointSpec, api.WorkloadEndpointSpec{})
	registerStructValidator(validateHostEndpointSpec, api.HostEndpointSpec{})
	registerStructValidator(validateIPPool, api.IPPool{})
	registerStructValidator(validateICMPFields, api.ICMPFields{})
	registerStructValidator(validateRule, api.Rule{})
	registerStructValidator(validateBackendRule, model.Rule{})
	registerStructValidator(validateNodeSpec, api.NodeSpec{})
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

func validateAction(v *validator.Validate, topStruct reflect.Value, currentStructOrField reflect.Value, field reflect.Value, fieldType reflect.Type, fieldKind reflect.Kind, param string) bool {
	s := field.String()
	log.Debugf("Validate action: %s", s)
	return actionRegex.MatchString(s)
}

func validateInterface(v *validator.Validate, topStruct reflect.Value, currentStructOrField reflect.Value, field reflect.Value, fieldType reflect.Type, fieldKind reflect.Kind, param string) bool {
	s := field.String()
	log.Debugf("Validate interface: %s", s)
	return interfaceRegex.MatchString(s)
}

func validateBackendAction(v *validator.Validate, topStruct reflect.Value, currentStructOrField reflect.Value, field reflect.Value, fieldType reflect.Type, fieldKind reflect.Kind, param string) bool {
	s := field.String()
	log.Debugf("Validate action: %s", s)
	return backendActionRegex.MatchString(s)
}

func validateName(v *validator.Validate, topStruct reflect.Value, currentStructOrField reflect.Value, field reflect.Value, fieldType reflect.Type, fieldKind reflect.Kind, param string) bool {
	s := field.String()
	log.Debugf("Validate name: %s", s)
	return nameRegex.MatchString(s)
}

func validateIPVersion(v *validator.Validate, topStruct reflect.Value, currentStructOrField reflect.Value, field reflect.Value, fieldType reflect.Type, fieldKind reflect.Kind, param string) bool {
	ver := field.Int()
	log.Debugf("Validate ip version: %d", ver)
	return ver == 4 || ver == 6
}

func validateIPIPMode(v *validator.Validate, topStruct reflect.Value, currentStructOrField reflect.Value, field reflect.Value, fieldType reflect.Type, fieldKind reflect.Kind, param string) bool {
	s := field.String()
	log.Debugf("Validate name: %s", s)
	return ipipModeRegex.MatchString(s)
}

func validateSelector(v *validator.Validate, topStruct reflect.Value, currentStructOrField reflect.Value, field reflect.Value, fieldType reflect.Type, fieldKind reflect.Kind, param string) bool {
	s := field.String()
	log.Debugf("Validate selector: %s", s)

	// We use the selector parser to validate a selector string.
	_, err := selector.Parse(s)
	if err != nil {
		log.Debugf("Selector %#v was invalid: %v", s, err)
		return false
	}
	return true
}

func validateTag(v *validator.Validate, topStruct reflect.Value, currentStructOrField reflect.Value, field reflect.Value, fieldType reflect.Type, fieldKind reflect.Kind, param string) bool {
	s := field.String()
	log.Debugf("Validate tag: %s", s)
	return nameRegex.MatchString(s)
}

func validateLabels(v *validator.Validate, topStruct reflect.Value, currentStructOrField reflect.Value, field reflect.Value, fieldType reflect.Type, fieldKind reflect.Kind, param string) bool {
	l := field.Interface().(map[string]string)
	log.Debugf("Validate labels: %s", l)
	for k, v := range l {
		if !labelRegex.MatchString(k) || !labelValueRegex.MatchString(v) {
			return false
		}
	}
	return true
}

func validateScopeGlobalOrNode(v *validator.Validate, topStruct reflect.Value, currentStructOrField reflect.Value, field reflect.Value, fieldType reflect.Type, fieldKind reflect.Kind, param string) bool {
	f := field.Interface().(scope.Scope)
	log.Debugf("Validate scope: %v", f)
	return f == scope.Global || f == scope.Node
}

func validateProtocol(v *validator.Validate, structLevel *validator.StructLevel) {
	p := structLevel.CurrentStruct.Interface().(numorstring.Protocol)
	log.Debugf("Validate protocol: %v %s %d", p.Type, p.StrVal, p.NumVal)

	// The protocol field may be an integer 1-255 (i.e. not 0), or one of the valid protocol
	// names.
	if num, err := p.NumValue(); err == nil {
		if num == 0 {
			structLevel.ReportError(reflect.ValueOf(p.NumVal),
				"Protocol", "", reason("protocol number invalid"))
		}
	} else if !protocolRegex.MatchString(p.String()) {
		structLevel.ReportError(reflect.ValueOf(p.String()),
			"Protocol", "", reason("protocol name invalid"))
	}
}

func validatePort(v *validator.Validate, structLevel *validator.StructLevel) {
	p := structLevel.CurrentStruct.Interface().(numorstring.Port)

	// Check that the port range is in the correct order.  The YAML parsing also checks this,
	// but this protects against misuse of the programmatic API.
	log.Debugf("Validate port: %s")
	if p.MinPort > p.MaxPort {
		structLevel.ReportError(reflect.ValueOf(p.MaxPort),
			"Port", "", reason("port range invalid"))
	}

	// No need to check for the upperbound (65536) because we use uint16.
	if p.MinPort < 1 || p.MaxPort < 1 {
		structLevel.ReportError(reflect.ValueOf(p.MaxPort),
			"Port", "", reason("port range invalid, port number must be between 0 and 65536"))
	}
}

func validateIPNAT(v *validator.Validate, structLevel *validator.StructLevel) {
	i := structLevel.CurrentStruct.Interface().(api.IPNAT)
	log.Debugf("Internal IP: %s; External IP: %s", i.InternalIP, i.ExternalIP)

	// An IPNAT must have both the internal and external IP versions the same.
	if i.InternalIP.Version() != i.ExternalIP.Version() {
		structLevel.ReportError(reflect.ValueOf(i.ExternalIP),
			"ExternalIP", "", reason("mismatched IP versions"))
	}
}

func validateWorkloadEndpointSpec(v *validator.Validate, structLevel *validator.StructLevel) {
	w := structLevel.CurrentStruct.Interface().(api.WorkloadEndpointSpec)

	// The configured networks only support /32 (for IPv4) and /128 (for IPv6) at present.
	for _, netw := range w.IPNetworks {
		ones, bits := netw.Mask.Size()
		if bits != ones {
			structLevel.ReportError(reflect.ValueOf(w.IPNetworks),
				"IPNetworks", "", reason("IP network contains multiple addresses"))
		}
	}

	if w.IPv4Gateway != nil && w.IPv4Gateway.Version() != 4 {
		structLevel.ReportError(reflect.ValueOf(w.IPv4Gateway),
			"IPv4Gateway", "", reason("invalid IPv4 gateway address specified"))
	}

	if w.IPv6Gateway != nil && w.IPv6Gateway.Version() != 6 {
		structLevel.ReportError(reflect.ValueOf(w.IPv6Gateway),
			"IPv6Gateway", "", reason("invalid IPv6 gateway address specified"))
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
				"IPNATs", "", reason("NAT is not in the endpoint networks"))
		}
	}
}

func validateHostEndpointSpec(v *validator.Validate, structLevel *validator.StructLevel) {
	h := structLevel.CurrentStruct.Interface().(api.HostEndpointSpec)

	// A host endpoint must have an interface name and/or some expected IPs specified.
	if h.InterfaceName == "" && len(h.ExpectedIPs) == 0 {
		structLevel.ReportError(reflect.ValueOf(h.InterfaceName),
			"InterfaceName", "", reason("no interface or expected IPs have been specified"))
	}
}

func validateIPPool(v *validator.Validate, structLevel *validator.StructLevel) {
	pool := structLevel.CurrentStruct.Interface().(api.IPPool)

	// Validation of the data occurs before checking whether Metadata
	// fields are complete, so need to check whether CIDR is assigned before
	// performing cross-checks.  If CIDR is not assigned this will be
	// picked up during Metadata->Key conversion.
	if pool.Metadata.CIDR.IP != nil {
		// IPIP cannot be enabled for IPv6.
		if pool.Metadata.CIDR.Version() == 6 && pool.Spec.IPIP != nil && pool.Spec.IPIP.Enabled {
			structLevel.ReportError(reflect.ValueOf(pool.Spec.IPIP.Enabled),
				"IPIP.Enabled", "", reason("IPIP is not supported on an IPv6 IP pool"))
		}

		// The Calico IPAM places restrictions on the minimum IP pool size.  If
		// the pool is enabled, check that the pool is at least the minimum size.
		if !pool.Spec.Disabled {
			ones, bits := pool.Metadata.CIDR.Mask.Size()
			log.Debugf("Pool CIDR: %s, num bits: %d", pool.Metadata.CIDR, bits-ones)
			if bits-ones < 6 {
				if pool.Metadata.CIDR.Version() == 4 {
					structLevel.ReportError(reflect.ValueOf(pool.Metadata.CIDR),
						"CIDR", "", reason(poolSmallIPv4))
				} else {
					structLevel.ReportError(reflect.ValueOf(pool.Metadata.CIDR),
						"CIDR", "", reason(poolSmallIPv6))
				}
			}
		}
	}

}

func validateICMPFields(v *validator.Validate, structLevel *validator.StructLevel) {
	icmp := structLevel.CurrentStruct.Interface().(api.ICMPFields)

	// Due to Kernel limitations, ICMP code must always be specified with a type.
	if icmp.Code != nil && icmp.Type == nil {
		structLevel.ReportError(reflect.ValueOf(icmp.Code),
			"Code", "", reason("ICMP code specified without an ICMP type"))
	}
}

func validateRule(v *validator.Validate, structLevel *validator.StructLevel) {
	rule := structLevel.CurrentStruct.Interface().(api.Rule)

	// If the protocol is neither tcp (6) nor udp (17) check that the port values have not
	// been specified.
	if rule.Protocol == nil || !rule.Protocol.SupportsPorts() {
		if len(rule.Source.Ports) > 0 {
			structLevel.ReportError(reflect.ValueOf(rule.Source.Ports),
				"Source.Ports", "", reason("protocol does not support ports"))
		}
		if len(rule.Source.NotPorts) > 0 {
			structLevel.ReportError(reflect.ValueOf(rule.Source.NotPorts),
				"Source.NotPorts", "", reason("protocol does not support ports"))
		}

		if len(rule.Destination.Ports) > 0 {
			structLevel.ReportError(reflect.ValueOf(rule.Destination.Ports),
				"Destination.Ports", "", reason("protocol does not support ports"))
		}
		if len(rule.Destination.NotPorts) > 0 {
			structLevel.ReportError(reflect.ValueOf(rule.Destination.NotPorts),
				"Destination.NotPorts", "", reason("protocol does not support ports"))
		}
	}
}

func validateBackendRule(v *validator.Validate, structLevel *validator.StructLevel) {
	rule := structLevel.CurrentStruct.Interface().(model.Rule)

	// If the protocol is neither tcp (6) nor udp (17) check that the port values have not
	// been specified.
	if rule.Protocol == nil || !rule.Protocol.SupportsPorts() {
		if len(rule.SrcPorts) > 0 {
			structLevel.ReportError(reflect.ValueOf(rule.SrcPorts),
				"SrcPorts", "", reason("protocol does not support ports"))
		}
		if len(rule.NotSrcPorts) > 0 {
			structLevel.ReportError(reflect.ValueOf(rule.NotSrcPorts),
				"NotSrcPorts", "", reason("protocol does not support ports"))
		}

		if len(rule.DstPorts) > 0 {
			structLevel.ReportError(reflect.ValueOf(rule.DstPorts),
				"DstPorts", "", reason("protocol does not support ports"))
		}
		if len(rule.NotDstPorts) > 0 {
			structLevel.ReportError(reflect.ValueOf(rule.NotDstPorts),
				"NotDstPorts", "", reason("protocol does not support ports"))
		}
	}
}

func validateNodeSpec(v *validator.Validate, structLevel *validator.StructLevel) {
	ns := structLevel.CurrentStruct.Interface().(api.NodeSpec)

	if ns.BGP != nil {
		if ns.BGP.IPv4Address == nil && ns.BGP.IPv6Address == nil {
			structLevel.ReportError(reflect.ValueOf(ns.BGP.IPv4Address),
				"BGP.IPv4Address", "", reason("no BGP IP address and subnet specified"))
		}

		if ns.BGP.IPv4Address != nil && ns.BGP.IPv4Address.Version() != 4 {
			structLevel.ReportError(reflect.ValueOf(ns.BGP.IPv4Address),
				"BGP.IPv4Address", "", reason("invalid IPv4 address and subnet specified"))
		}

		if ns.BGP.IPv6Address != nil && ns.BGP.IPv6Address.Version() != 6 {
			structLevel.ReportError(reflect.ValueOf(ns.BGP.IPv6Address),
				"BGP.IPv6Address", "", reason("invalid IPv6 address and subnet specified"))
		}
	}
}
