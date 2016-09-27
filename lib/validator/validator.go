// Copyright (c) 2016 Tigera, Inc. All rights reserved.

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
	"strconv"
	"strings"

	log "github.com/Sirupsen/logrus"
	"github.com/tigera/libcalico-go/lib/api"
	"github.com/tigera/libcalico-go/lib/errors"
	"github.com/tigera/libcalico-go/lib/numorstring"
	"github.com/tigera/libcalico-go/lib/scope"
	"github.com/tigera/libcalico-go/lib/selector"
	"gopkg.in/go-playground/validator.v8"
)

var validate *validator.Validate

var (
	nameRegex          = regexp.MustCompile("^[a-zA-Z0-9_.-]+$")
	labelRegex         = regexp.MustCompile("^[a-zA-Z_./-][a-zA-Z0-9_./-]*$")
	actionRegex        = regexp.MustCompile("^(allow|deny|log)$")
	backendActionRegex = regexp.MustCompile("^(allow|deny|log|)$")
	protocolRegex      = regexp.MustCompile("^(tcp|udp|icmp|icmpv6|sctp|udplite)$")
)

func init() {
	// Initialise static data.
	config := &validator.Config{TagName: "validate", FieldNameTag: "json"}
	validate = validator.New(config)

	// Register field validators.
	registerFieldValidator("action", validateAction)
	registerFieldValidator("backendaction", validateBackendAction)
	registerFieldValidator("name", validateName)
	registerFieldValidator("selector", validateSelector)
	registerFieldValidator("tag", validateTag)
	registerFieldValidator("labels", validateLabels)
	registerFieldValidator("interface", validateInterface)
	registerFieldValidator("asn", validateASNum)
	registerFieldValidator("scopeglobalornode", validateScopeGlobalOrNode)
	registerFieldValidator("ipversion", validateIPVersion)

	// Register struct validators.
	registerStructValidator(validateProtocol, numorstring.Protocol{})
	registerStructValidator(validatePort, numorstring.Port{})
	registerStructValidator(validateIPNAT, api.IPNAT{})
	registerStructValidator(validateWorkloadEndpointSpec, api.WorkloadEndpointSpec{})
	registerStructValidator(validateHostEndpointSpec, api.HostEndpointSpec{})
	registerStructValidator(validatePoolMetadata, api.PoolMetadata{})
	registerStructValidator(validateICMPFields, api.ICMPFields{})
	registerStructValidator(validateRule, api.Rule{})
}

func registerFieldValidator(key string, fn validator.Func) {
	validate.RegisterValidation(key, fn)
}

func registerStructValidator(fn validator.StructLevelFunc, t ...interface{}) {
	validate.RegisterStructValidation(fn, t...)
}

func Validate(current interface{}) error {
	err := validate.Struct(current)
	if err == nil {
		return nil
	}

	verr := errors.ErrorValidation{}
	for _, f := range err.(validator.ValidationErrors) {
		verr.ErrFields = append(verr.ErrFields,
			errors.ErroredField{Name: f.Name, Value: f.Value})
	}
	return verr
}

func validateAction(v *validator.Validate, topStruct reflect.Value, currentStructOrField reflect.Value, field reflect.Value, fieldType reflect.Type, fieldKind reflect.Kind, param string) bool {
	s := field.String()
	log.Debugf("Validate action: %s", s)
	return actionRegex.MatchString(s)
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
		if !labelRegex.MatchString(k) || !labelRegex.MatchString(v) {
			return false
		}
	}
	return true
}

func validateInterface(v *validator.Validate, topStruct reflect.Value, currentStructOrField reflect.Value, field reflect.Value, fieldType reflect.Type, fieldKind reflect.Kind, param string) bool {
	b := []byte(field.String())
	log.Debugf("Validate interface: %s", b)
	return nameRegex.Match(b)
}

func validateASNum(v *validator.Validate, topStruct reflect.Value, currentStructOrField reflect.Value, field reflect.Value, fieldType reflect.Type, fieldKind reflect.Kind, param string) bool {
	f := field.Interface().(int)
	log.Debugf("Validate AS number: %v", f)
	return f >= 0 && f <= 4294967295
}

func validateScopeGlobalOrNode(v *validator.Validate, topStruct reflect.Value, currentStructOrField reflect.Value, field reflect.Value, fieldType reflect.Type, fieldKind reflect.Kind, param string) bool {
	f := field.Interface().(scope.Scope)
	log.Debugf("Validate scope: %v", f)
	return f == scope.Global || f == scope.Node
}

func validateProtocol(v *validator.Validate, structLevel *validator.StructLevel) {
	p := structLevel.CurrentStruct.Interface().(numorstring.Protocol)
	log.Debugf("Validate protocol: %v %s %d", p.Type, p.StrVal, p.NumVal)

	// The protocol field may be an integer 1-254, or one of the valid protocol names.
	if num, err := p.NumValue(); err == nil {
		if (num < 1) || (num > 255) {
			structLevel.ReportError(reflect.ValueOf(p.NumVal), "Protocol", "protocol", "protocol number invalid")
		}
	} else if !protocolRegex.MatchString(p.String()) {
		structLevel.ReportError(reflect.ValueOf(p.String()), "Protocol", "protocol", "protocol name invalid")
	}
}

func validatePort(v *validator.Validate, structLevel *validator.StructLevel) {
	p := structLevel.CurrentStruct.Interface().(numorstring.Port)

	// A port may be specified either as a single port or a range of ports.  Port values are
	// integers 0-65535.  A range of ports is specified as a string X:Y where X,Y are valid
	// port values and X <= Y.
	log.Debugf("Validate port: %v %s %v", p.Type, p.StrVal, p.NumVal)
	if p.Type == numorstring.NumOrStringNum && ((p.NumVal < 0) || (p.NumVal > 65535)) {
		structLevel.ReportError(reflect.ValueOf(p.NumVal), "Port", "port", "port number invalid")
		return
	} else if p.Type == numorstring.NumOrStringString {
		ports := strings.Split(p.StrVal, ":")
		if len(ports) > 2 {
			structLevel.ReportError(reflect.ValueOf(p.StrVal), "Port", "port", "port range invalid")
			return
		}
		first := 0
		for _, port := range ports {
			log.Debugf("Validate range, checking port %s", port)
			num, err := strconv.Atoi(port)
			if err != nil {
				structLevel.ReportError(reflect.ValueOf(p.StrVal), "Port", "port", "port range invalid")
				return
			}

			if num < 0 || num > 65535 {
				structLevel.ReportError(reflect.ValueOf(p.StrVal), "Port", "port", "port number invalid")
				return
			}

			if num < first {
				structLevel.ReportError(reflect.ValueOf(p.StrVal), "Port", "port", "port range invalid")
				return
			}
			first = num
		}
	}
}

func validateIPNAT(v *validator.Validate, structLevel *validator.StructLevel) {
	i := structLevel.CurrentStruct.Interface().(api.IPNAT)
	log.Debugf("Internal IP: %s; External IP: %s", i.InternalIP, i.ExternalIP)

	// An IPNAT must have both the internal and external IP versions the same.
	if i.InternalIP.Version() != i.ExternalIP.Version() {
		structLevel.ReportError(reflect.ValueOf(i.ExternalIP), "ExternalIP", "externalIP", "mismatched IP versions")
	}
}

func validateWorkloadEndpointSpec(v *validator.Validate, structLevel *validator.StructLevel) {
	w := structLevel.CurrentStruct.Interface().(api.WorkloadEndpointSpec)

	// The configured networks only support /32 (for IPv4) and /128 (for IPv6) at present.
	if w.IPNetworks != nil {
		for _, netw := range w.IPNetworks {
			ones, bits := netw.Mask.Size()
			if bits != ones {
				structLevel.ReportError(reflect.ValueOf(w.IPNetworks), "IPNetworks", "ipNetworks", "IP network contains multiple addresses")
			}
		}
	}

	// If NATs have been specified, then they should each be within the configured networks of
	// the endpoint.
	if w.IPNATs != nil {
		valid := false
		if w.IPNetworks != nil {
			// Check each NAT to ensure it is within the configured networks.  If any
			// are not then exit without further checks.
			for _, nat := range w.IPNATs {
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
		}

		if !valid {
			structLevel.ReportError(reflect.ValueOf(w.IPNATs), "IPNATs", "ipNATs", "NAT is not in the endpoint networks")
		}
	}
}

func validateHostEndpointSpec(v *validator.Validate, structLevel *validator.StructLevel) {
	h := structLevel.CurrentStruct.Interface().(api.HostEndpointSpec)

	// A host endpoint must have an interface name and/or some expected IPs specified.
	if h.InterfaceName == "" && (h.ExpectedIPs == nil || len(h.ExpectedIPs) == 0) {
		structLevel.ReportError(reflect.ValueOf(h.InterfaceName), "InterfaceName", "InterfaceName", "no interface or expected IPs have been specified")
	}
}

func validatePoolMetadata(v *validator.Validate, structLevel *validator.StructLevel) {
	pool := structLevel.CurrentStruct.Interface().(api.PoolMetadata)

	// The Calico IPAM places restrictions on the minimum IP pool size, check that the
	// pool is at least the minimum size.
	if pool.CIDR.IP != nil {
		ones, bits := pool.CIDR.Mask.Size()
		log.Debugf("Pool CIDR: %s, num bits: %d", pool.CIDR, bits-ones)
		if bits-ones < 6 {
			structLevel.ReportError(reflect.ValueOf(pool.CIDR), "CIDR", "cidr", "IP pool is too small")
		}
	}
}

func validateICMPFields(v *validator.Validate, structLevel *validator.StructLevel) {
	icmp := structLevel.CurrentStruct.Interface().(api.ICMPFields)

	// Due to Kernel limitations, ICMP code must always be specified with a type.
	if icmp.Code != nil && icmp.Type == nil {
		structLevel.ReportError(reflect.ValueOf(icmp.Code), "Code", "icmp code", "ICMP code specified without an ICMP type")
	}
}

func validateRule(v *validator.Validate, structLevel *validator.StructLevel) {
	rule := structLevel.CurrentStruct.Interface().(api.Rule)

	// If the protocol is neither tcp (6) nor udp (17) check that the port values have not
	// been specified.
	if rule.Protocol == nil || !rule.Protocol.SupportsPorts() {
		if rule.Source.Ports != nil && len(rule.Source.Ports) > 0 {
			structLevel.ReportError(reflect.ValueOf(rule.Source.Ports), "source.Ports", "source ports", "port is not valid for protocol")
		}
		if rule.Source.NotPorts != nil && len(rule.Source.NotPorts) > 0 {
			structLevel.ReportError(reflect.ValueOf(rule.Source.NotPorts), "Source.NotPorts", "source !ports", "port is not valid for protocol")
		}

		if rule.Destination.Ports != nil && len(rule.Destination.Ports) > 0 {
			structLevel.ReportError(reflect.ValueOf(rule.Destination.Ports), "Destination.Ports", "destination ports", "port is not valid for protocol")
		}
		if rule.Destination.NotPorts != nil && len(rule.Destination.NotPorts) > 0 {
			structLevel.ReportError(reflect.ValueOf(rule.Destination.NotPorts), "Destination.NotPorts", "destination !ports", "port is not valid for protocol")
		}
	}
}
