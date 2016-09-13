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
	actionRegex        = regexp.MustCompile("^(allow|deny)$")
	backendActionRegex = regexp.MustCompile("^(allow|deny)$")
	protocolRegex      = regexp.MustCompile("^(tcp|udp|icmp|icmpv6|sctp|udplite)$")
)

func init() {
	// Initialise static data.
	config := &validator.Config{TagName: "validate", FieldNameTag: "json"}
	validate = validator.New(config)

	// Register some common validators.
	RegisterFieldValidator("action", validateAction)
	RegisterFieldValidator("backendaction", validateBackendAction)
	RegisterFieldValidator("name", validateName)
	RegisterFieldValidator("selector", validateSelector)
	RegisterFieldValidator("tag", validateTag)
	RegisterFieldValidator("labels", validateLabels)
	RegisterFieldValidator("interface", validateInterface)
	RegisterFieldValidator("order", validateOrder)
	RegisterFieldValidator("asn", validateASNum)
	RegisterFieldValidator("scopeglobalornode", validateScopeGlobalOrNode)

	RegisterStructValidator(validateProtocol, numorstring.Protocol{})
	RegisterStructValidator(validatePort, numorstring.Port{})
}

func RegisterFieldValidator(key string, fn validator.Func) {
	validate.RegisterValidation(key, fn)
}

func RegisterStructValidator(fn validator.StructLevelFunc, t ...interface{}) {
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
	log.Infof("Validate action: %s", s)
	return actionRegex.MatchString(s)
}

func validateBackendAction(v *validator.Validate, topStruct reflect.Value, currentStructOrField reflect.Value, field reflect.Value, fieldType reflect.Type, fieldKind reflect.Kind, param string) bool {
	s := field.String()
	log.Infof("Validate action: %s", s)
	return backendActionRegex.MatchString(s)
}

func validateName(v *validator.Validate, topStruct reflect.Value, currentStructOrField reflect.Value, field reflect.Value, fieldType reflect.Type, fieldKind reflect.Kind, param string) bool {
	s := field.String()
	log.Infof("Validate name: %s", s)
	return nameRegex.MatchString(s)
}

func validateSelector(v *validator.Validate, topStruct reflect.Value, currentStructOrField reflect.Value, field reflect.Value, fieldType reflect.Type, fieldKind reflect.Kind, param string) bool {
	s := field.String()
	log.Infof("Validate selector: %s", s)
	_, err := selector.Parse(s)
	if err != nil {
		log.Infof("Selector %#v was invalid: %v", s, err)
		return false
	}
	return true
}

func validateTag(v *validator.Validate, topStruct reflect.Value, currentStructOrField reflect.Value, field reflect.Value, fieldType reflect.Type, fieldKind reflect.Kind, param string) bool {
	s := field.String()
	log.Infof("Validate tag: %s", s)
	return nameRegex.MatchString(s)
}

func validateLabels(v *validator.Validate, topStruct reflect.Value, currentStructOrField reflect.Value, field reflect.Value, fieldType reflect.Type, fieldKind reflect.Kind, param string) bool {
	l := field.Interface().(map[string]string)
	log.Infof("Validate labels: %s", l)
	for k, v := range l {
		if !labelRegex.MatchString(k) || !labelRegex.MatchString(v) {
			return false
		}
	}
	return true
}

func validateInterface(v *validator.Validate, topStruct reflect.Value, currentStructOrField reflect.Value, field reflect.Value, fieldType reflect.Type, fieldKind reflect.Kind, param string) bool {
	b := []byte(field.String())
	log.Infof("Validate interface: %s", b)
	return nameRegex.Match(b)
}

func validateOrder(v *validator.Validate, topStruct reflect.Value, currentStructOrField reflect.Value, field reflect.Value, fieldType reflect.Type, fieldKind reflect.Kind, param string) bool {
	f := field.Interface()
	log.Infof("Validate order: %v", f)
	return f != nil
}

func validateASNum(v *validator.Validate, topStruct reflect.Value, currentStructOrField reflect.Value, field reflect.Value, fieldType reflect.Type, fieldKind reflect.Kind, param string) bool {
	f := field.Interface().(int)
	log.Infof("Validate AS number: %v", f)
	return f >= 0 && f <= 4294967295
}

func validateScopeGlobalOrNode(v *validator.Validate, topStruct reflect.Value, currentStructOrField reflect.Value, field reflect.Value, fieldType reflect.Type, fieldKind reflect.Kind, param string) bool {
	f := field.Interface().(scope.Scope)
	log.Infof("Validate scope: %v", f)
	return f == scope.Global || f == scope.Node
}

func validateProtocol(v *validator.Validate, structLevel *validator.StructLevel) {
	log.Infof("Validate protocol")
	p := structLevel.CurrentStruct.Interface().(numorstring.Protocol)
	log.Infof("Validate protocol: %v %s %v", p.Type, p.StrVal, p.NumVal)
	if p.Type == numorstring.NumOrStringNum && ((p.NumVal < 1) || (p.NumVal > 255)) {
		structLevel.ReportError(reflect.ValueOf(p.NumVal), "Protocol", "protocol", "protocol number invalid")
	} else if p.Type == numorstring.NumOrStringString && !protocolRegex.MatchString(p.StrVal) {
		structLevel.ReportError(reflect.ValueOf(p.StrVal), "Protocol", "protocol", "protocol name invalid")
	}
}

func validatePort(v *validator.Validate, structLevel *validator.StructLevel) {
	log.Infof("Validate port")
	p := structLevel.CurrentStruct.Interface().(numorstring.Port)
	log.Infof("Validate port: %v %s %v", p.Type, p.StrVal, p.NumVal)
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
			log.Infof("Validate range, checking port %s", port)
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
