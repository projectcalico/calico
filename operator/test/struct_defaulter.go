// Copyright (c) 2020-2024,2026 Tigera, Inc. All rights reserved.

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

package test

import (
	"fmt"
	"reflect"
)

// The code here is for testing purposes and can be used to populate all fields of a struct
// with a value. This can be useful for writing unit tests to check that all fields are processed
// by a function.

const (
	DefaultNonZeroInt64   int64   = 1
	DefaultNonZeroUint64  uint64  = 1
	DefaultNonZeroFloat64 float64 = 1
	DefaultNonZeroString  string  = "not-zero"
	DefaultNonZeroBool    bool    = true
)

type NonZeroDefaultOption func(defaulter *nonZeroValueDefaulter)

func WithInterfaceImplementations(ifaceImpls map[string]interface{}) NonZeroDefaultOption {
	return func(defaulter *nonZeroValueDefaulter) {
		defaulter.ifaceImpls = ifaceImpls
	}
}

type ValueDefaulter interface {
	SetDefault(interface{}) error
}

type nonZeroValueDefaulter struct {
	ifaceImpls map[string]interface{}
}

// NewNonZeroStructDefaulter creates an implementation of the ValueDefaulter that
func NewNonZeroStructDefaulter(options ...NonZeroDefaultOption) ValueDefaulter {
	defaulter := &nonZeroValueDefaulter{}
	for _, option := range options {
		option(defaulter)
	}
	return defaulter
}

func (defaulter *nonZeroValueDefaulter) SetDefault(strct interface{}) error {
	return defaulter.setDefaultValue(reflect.ValueOf(strct).Elem())
}

func (defaulter *nonZeroValueDefaulter) setDefaultValue(value reflect.Value) error {
	if !value.CanSet() {
		return nil
	}

	switch value.Kind() {
	case reflect.Pointer:
		p := reflect.New(value.Type().Elem())
		if err := defaulter.setDefaultValue(p.Elem()); err != nil {
			return err
		}

		value.Set(p)
	case reflect.Struct:
		for i := 0; i < value.NumField(); i++ {
			f := value.Field(i)
			if err := defaulter.setDefaultValue(f); err != nil {
				return err
			}
		}
	case reflect.Interface:
		ifaceName := value.Type().Name()
		if impl, exists := defaulter.ifaceImpls[ifaceName]; exists {
			implValue := reflect.New(reflect.TypeOf(impl))
			if err := defaulter.setDefaultValue(implValue.Elem()); err != nil {
				return err
			}
			value.Set(implValue)
		} else {
			return fmt.Errorf("no implementation for interface '%s'", value.Type().Name())
		}
	case reflect.Slice:
		v2 := reflect.New(value.Type().Elem())
		if err := defaulter.setDefaultValue(v2.Elem()); err != nil {
			return err
		}

		value.Set(reflect.Append(value, v2.Elem()))
	case reflect.Map:
		mapKey := reflect.New(value.Type().Key())
		mapValue := reflect.New(value.Type().Elem())
		if err := defaulter.setDefaultValue(mapKey.Elem()); err != nil {
			return err
		}

		if err := defaulter.setDefaultValue(mapValue.Elem()); err != nil {
			return err
		}

		m := reflect.MakeMap(value.Type())
		m.SetMapIndex(mapKey.Elem(), mapValue.Elem())

		value.Set(m)
	case reflect.Chan:
		value.Set(reflect.MakeChan(value.Type(), 1))
	default:
		if err := setPrimitive(value); err != nil {
			return err
		}
	}

	return nil
}

func setPrimitive(v reflect.Value) error {
	switch v.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v.SetInt(DefaultNonZeroInt64)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v.SetUint(DefaultNonZeroUint64)
	case reflect.Float32, reflect.Float64:
		v.SetFloat(DefaultNonZeroFloat64)
	case reflect.String:
		v.SetString(DefaultNonZeroString)
	case reflect.Bool:
		v.SetBool(DefaultNonZeroBool)
	default:
		return fmt.Errorf("unknown type %s", v.Kind())
	}

	return nil
}
