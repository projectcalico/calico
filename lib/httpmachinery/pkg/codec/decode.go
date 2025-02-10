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

package codec

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-playground/form"
	"github.com/google/uuid"

	apicontext "github.com/projectcalico/calico/lib/httpmachinery/pkg/context"
	"github.com/projectcalico/calico/lib/httpmachinery/pkg/header"
)

var (
	urlPathDecoder  *form.Decoder
	urlQueryDecoder *form.Decoder
	headerDecoder   *form.Decoder
)

type URLVarsFunc func(r *http.Request) map[string]string

func init() {
	urlPathDecoder = form.NewDecoder()
	urlQueryDecoder = form.NewDecoder()
	headerDecoder = form.NewDecoder()

	urlPathDecoder.SetTagName(tagURLPath)
	urlQueryDecoder.SetTagName(tagURLQuery)
	headerDecoder.SetTagName(tagHeader)

	// ModeExplicit ensures that we don't try to parse structs that don't have the tag.
	urlPathDecoder.SetMode(form.ModeExplicit)
	urlQueryDecoder.SetMode(form.ModeExplicit)
	headerDecoder.SetMode(form.ModeExplicit)

	RegisterCustomDecodeTypeFunc(decodeUUID)
}

func RegisterCustomDecodeTypeFunc[E any](fn func(vals []string) (E, error)) {
	f := func(vals []string) (interface{}, error) {
		return fn(vals)
	}

	var typ E
	urlPathDecoder.RegisterCustomTypeFunc(f, typ)
	urlQueryDecoder.RegisterCustomTypeFunc(f, typ)
	headerDecoder.RegisterCustomTypeFunc(f, typ)
}

// DecodeAndValidateRequestParams decodes the request in the specific RequestParam type, and validates the fields based on
// the validation tags. The request body and query params are decoded into the RequestParam type, depending on if there
// is a body / are query / url params and what the content type is.
func DecodeAndValidateRequestParams[RequestParam any](ctx apicontext.Context, urlVars URLVarsFunc, req *http.Request) (*RequestParam, error) {
	reqParams := new(RequestParam)

	// Don't assume the body is json (or even available) if the json header content type isn't set.
	content := strings.ToLower(strings.TrimSpace(req.Header.Get(header.ContentType)))
	if content == header.ApplicationJSON {
		jsonDec := json.NewDecoder(req.Body)
		jsonDec.DisallowUnknownFields()

		if err := jsonDec.Decode(reqParams); err != nil {
			ctx.Logger().WithError(err).Debug("Failed to decode request body.")
			return nil, fmt.Errorf("malformed request body")
		}
	}

	if err := DecodeAndValidateURLParameters(reqParams, req.Header, urlVars(req), req.URL.Query()); err != nil {
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

// decodeUUID is a form.Decoder decoding function that converts a string into a UUID.
func decodeUUID(vals []string) (uuid.UUID, error) {
	if len(vals) >= 1 {
		return uuid.Parse(vals[0])
	}
	return uuid.Nil, nil
}
