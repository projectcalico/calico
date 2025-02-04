// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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

package encoding

import (
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"net/http"
	"reflect"
	"strings"

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"

	"github.com/go-playground/form"
	"github.com/go-playground/validator/v10"

	"github.com/projectcalico/calico/lib/httpapimachinery/pkg/header"
)

const (
	tagURLPath  = "urlPath"
	tagURLQuery = "urlQuery"
	tagHeader   = "header"
	tagJSON     = "json"
)

var (
	validate *validator.Validate

	urlPathDecoder  *form.Decoder
	urlPathEncoder  *form.Encoder
	urlQueryDecoder *form.Decoder
	urlQueryEncoder *form.Encoder
	headerDecoder   *form.Decoder
	headerEncoder   *form.Encoder
)

var (
	// validationMessageFunctions are the functions that are called when validation fails for a particular validation tag.
	// The validation tag that failed is used to look up the function that outputs a descriptive message for why the validation
	// may have failed.
	validationMessageFunctions = map[string]func(fieldError validator.FieldError) string{
		"required": func(fieldError validator.FieldError) string {
			translated := fmt.Sprintf("Missing required field (%s).", fieldError.Field())
			return translated
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

	urlPathDecoder = form.NewDecoder()
	urlPathEncoder = form.NewEncoder()

	urlPathDecoder.SetTagName(tagURLPath)
	urlPathEncoder.SetTagName(tagURLPath)

	// ModeExplicit ensures that we don't try to parse structs that don't have the tag.
	urlPathDecoder.SetMode(form.ModeExplicit)
	urlPathEncoder.SetMode(form.ModeExplicit)

	urlQueryDecoder = form.NewDecoder()
	urlQueryEncoder = form.NewEncoder()
	urlQueryDecoder.SetTagName(tagURLQuery)
	urlQueryEncoder.SetTagName(tagURLQuery)
	urlQueryDecoder.SetMode(form.ModeExplicit)
	urlQueryEncoder.SetMode(form.ModeExplicit)

	RegisterCustomDecodeTypeFunc(decodeUUID, uuid.UUID{})
	RegisterCustomEncodeTypeFunc(encodeUUID, uuid.UUID{})

	headerDecoder = form.NewDecoder()
	headerEncoder = form.NewEncoder()
	headerDecoder.SetTagName(tagHeader)
	headerEncoder.SetTagName(tagHeader)
	headerDecoder.SetMode(form.ModeExplicit)
	headerEncoder.SetMode(form.ModeExplicit)
}

func RegisterCustomDecodeTypeFunc(fn form.DecodeCustomTypeFunc, types ...interface{}) {
	urlPathDecoder.RegisterCustomTypeFunc(fn, types...)
	urlQueryDecoder.RegisterCustomTypeFunc(fn, types...)
}

func RegisterCustomEncodeTypeFunc(fn form.EncodeCustomTypeFunc, types ...interface{}) {
	urlPathEncoder.RegisterCustomTypeFunc(fn, types...)
	urlQueryEncoder.RegisterCustomTypeFunc(fn, types...)
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

// RegisterValidation wraps the validate.RegisterValidation function so that a messageFunc can also be registered with
// the validation function.
func RegisterValidation(tag string, validatorFunc validator.Func, callValidationEvenIfNull bool, messageFunc func(fieldError validator.FieldError) string) {
	err := validate.RegisterValidation(tag, validatorFunc, callValidationEvenIfNull)
	if err != nil {
		panic(err)
	}

	validationMessageFunctions[tag] = messageFunc
}

// decodeUUID is a form.Decoder decoding function that converts a string into a UUID.
func decodeUUID(vals []string) (interface{}, error) {
	if len(vals) >= 1 {
		return uuid.Parse(vals[0])
	}
	return nil, nil
}

// decodeUUID is a form.Decoder decoding function that converts a string into a UUID.
func encodeUUID(obj interface{}) ([]string, error) {
	uid, ok := obj.(uuid.UUID)
	if !ok {
		return nil, fmt.Errorf("object is not a uuid.UUID")
	}

	return []string{uid.String()}, nil
}

// DecodeAndValidateReqParams decodes the request in the specific RequestParam type, and validates the fields based on
// the validation tags. The request body and query params are decoded into the RequestParam type, depending on if there
// is a body / are query / url params and what the content type is.
func DecodeAndValidateReqParams[RequestParam any](req *http.Request) (*RequestParam, error) {
	reqParams := new(RequestParam)

	// Don't assume the body is json (or even available) if the json header content type isn't set.
	content := strings.ToLower(strings.TrimSpace(req.Header.Get(header.ContentType)))
	if content == header.ApplicationJSON {
		// TODO Consider a different pattern than decoding the entire body at once, it might be more prudent to return
		// TODO some sort of decoding structure so caller isn't forced to load everything in memory at once while reading
		// TODO the request. It may be able to process the request items and discard them from memory as it reads them,
		// TODO and if we do have streaming APIs this would be required.
		jsonDec := json.NewDecoder(req.Body)
		jsonDec.DisallowUnknownFields()

		if err := jsonDec.Decode(reqParams); err != nil {
			log.WithError(err).Debug("Failed to decode request body.")
			return nil, fmt.Errorf("malformed request body")
		}
	}

	// TODO Consider other content types for body parsing?? Not sure if we have any.
	if err := DecodeAndValidateURLParameters(reqParams, req.Header, mux.Vars(req), req.URL.Query()); err != nil {
		return nil, err
	}

	return reqParams, nil
}

func DecodeAndValidateURLParameters[T any](obj *T, header map[string][]string, path map[string]string, query map[string][]string) error {
	pathParams := map[string][]string{}
	for key, v := range path {
		pathParams[key] = []string{v}
	}

	// Decode the path params.
	if err := decodeParameters(urlPathDecoder, obj, pathParams); err != nil {
		return err
	}

	// Decode the query params.
	if err := decodeParameters(urlQueryDecoder, obj, query); err != nil {
		return err
	}

	// Decode the headers.
	if err := decodeParameters(headerDecoder, obj, header); err != nil {
		return err
	}

	// Validate parameters.
	if err := validate.Struct(obj); err != nil {
		return err
	}

	return nil
}

// decoderParameters uses the given form.Decoder to decode the given values into the given reqParams. It returns an error
// if there was an issue decoding the values, which signifies a validation error.
func decodeParameters[RequestParams any](decoder *form.Decoder, reqParams RequestParams, values map[string][]string) error {
	if err := decoder.Decode(reqParams, values); err != nil {
		if decodeErrs, ok := err.(form.DecodeErrors); ok {
			var msgs []string
			for key, fieldErr := range decodeErrs {
				msgs = append(msgs, fmt.Sprintf("failed to decode %s: %s", key, fieldErr.Error()))
			}

			return fmt.Errorf(strings.Join(msgs, "; "))
		}
		return err
	}

	return nil
}
