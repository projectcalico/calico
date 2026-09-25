// Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.
//
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

package codec

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/go-playground/validator/v10"
)

var validate *validator.Validate

var (
	// validationMessageFunctions are the functions that are called when validation fails for a particular validation tag.
	// The validation tag that failed is used to look up the function that outputs a descriptive message for why the validation
	// may have failed.
	validationMessageFunctions = map[string]func(fieldError validator.FieldError) string{
		"required": func(fieldError validator.FieldError) string {
			return fmt.Sprintf("%s is required", fieldName(fieldError))
		},
		"oneof": func(fieldError validator.FieldError) string {
			return fmt.Sprintf("invalid %s %q, expected one of %s",
				fieldName(fieldError), fieldError.Value(), strings.Join(strings.Fields(fieldError.Param()), ", "))
		},
	}
)

func init() {
	validate = validator.New()

	// Registering the tag name function allows us to report the field name that failed validation back to the API
	// user. This could either be a json field or a schema field.
	validate.RegisterTagNameFunc(func(fld reflect.StructField) string {
		name := fld.Name

		for _, tagName := range []string{tagJSON, tagURLPath, tagURLQuery, tagHeader} {
			if _, ok := fld.Tag.Lookup(tagName); ok {
				name = strings.SplitN(fld.Tag.Get(tagName), ",", 2)[0]
				if name == "-" {
					name = ""
				}
				return name
			}
		}

		return name
	})
}

// fieldName drops the index a "dive" failure adds, so kind[0] reads as kind.
func fieldName(fieldError validator.FieldError) string {
	name, _, _ := strings.Cut(fieldError.Field(), "[")
	return name
}

// RegisterValidation wraps the validate.RegisterValidation function so that a messageFunc can also be registered with
// the validation function.
func RegisterValidation(tag string, validatorFunc validator.Func, callValidationEvenIfNull bool, messageFunc func(fieldError validator.FieldError) string) {
	err := validate.RegisterValidation(tag, validatorFunc, callValidationEvenIfNull)
	if err != nil {
		panic(err)
	}

	validationMessageFunctions[tag] = messageFunc
}

// TODO Actually use this an make it better.
func TranslateValidationErrors(errors validator.ValidationErrors) []string {
	translations := make([]string, 0)
	for _, fieldError := range errors {
		if f, exists := validationMessageFunctions[fieldError.Tag()]; exists {
			translations = append(translations, f(fieldError))
		} else {
			translations = append(translations, fmt.Sprintf("field \"%s\" is invalid", fieldError.Field()))
		}
	}

	return translations
}
