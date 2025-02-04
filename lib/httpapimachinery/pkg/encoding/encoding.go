// Copyright (c) 2024 Tigera, Inc. All rights reserved.

package encoding

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"unicode"

	"github.com/google/uuid"

	// TODO I don't think we want to import these utilities and instead leave it up to the user of the library
	// TODO what muxer / logger they use. We'll need to provide some sort of interfacing for this though.
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"

	"github.com/go-playground/form"
	"github.com/go-playground/validator/v10"
)

const (
	// TODO Probably want header constants in some other package or file and just have this package or file deal with
	// TODO encoding / decoding (import the header values if needed).
	HeaderContentType          = "Content-Type"
	ContentTypeApplicationJson = "application/json"
	ContentTypeTextCSV         = "text/csv"
)

var (
	//schemaDecoder *schema.Decoder
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
		"min": func(fieldError validator.FieldError) string {
			var translated string
			switch fieldError.Type().Kind() {
			case reflect.Slice, reflect.Array, reflect.Map:
				translated = fmt.Sprintf("Number of elements is less than %s (%s).", fieldError.Param(), fieldError.Field())
			case reflect.String:
				translated = fmt.Sprintf("Length is less than %s (%s).", fieldError.Param(), fieldError.Field())
			default:
				translated = fmt.Sprintf("Value is less than %s (%s).", fieldError.Param(), fieldError.Field())
			}
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

		for _, tagName := range []string{"json", "urlPath", "urlQuery"} {
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

	// TODO Probably just want to remove this from the default validation.
	RegisterValidation("sha256digest", validateSHA256Digest, false, func(fieldError validator.FieldError) string {
		translated := fmt.Sprintf("field \"%s\" is not a sha256 digest (must start with sha256:)", fieldError.Field())
		return translated
	})

	// TODO Should we remove this from the default validation?
	RegisterValidation("nouppercase", validateNoUpperCase, false, func(fieldError validator.FieldError) string {
		translated := fmt.Sprintf("Cannot contain upper case letter (%s).", fieldError.Value())
		return translated
	})

	urlPathDecoder = form.NewDecoder()
	urlPathEncoder = form.NewEncoder()
	// TODO obviously should be using constants or a variable for these tag names.
	urlPathDecoder.SetTagName("urlPath")
	urlPathEncoder.SetTagName("urlPath")

	// ModeExplicit ensures that we don't try to parse structs that don't have the tag.
	urlPathDecoder.SetMode(form.ModeExplicit)
	urlPathEncoder.SetMode(form.ModeExplicit)

	urlQueryDecoder = form.NewDecoder()
	urlQueryEncoder = form.NewEncoder()
	urlQueryDecoder.SetTagName("urlQuery")
	urlQueryEncoder.SetTagName("urlQuery")
	urlQueryDecoder.SetMode(form.ModeExplicit)
	urlQueryEncoder.SetMode(form.ModeExplicit)

	RegisterCustomDecodeTypeFunc(decodeUUID, uuid.UUID{})
	RegisterCustomEncodeTypeFunc(encodeUUI, uuid.UUID{})

	headerDecoder = form.NewDecoder()
	headerEncoder = form.NewEncoder()
	headerDecoder.SetTagName("header")
	headerEncoder.SetTagName("header")
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

// RegisterValidation wraps the validate.RegisterValidation function so that a messageFunc can also be registered with
// the validation function.
func RegisterValidation(tag string, validatorFunc validator.Func, callValidationEvenIfNull bool, messageFunc func(fieldError validator.FieldError) string) {
	err := validate.RegisterValidation(tag, validatorFunc, callValidationEvenIfNull)
	if err != nil {
		panic(err)
	}

	validationMessageFunctions[tag] = messageFunc
}

// TODO not sure if this should be kept here, possible it could be made better? It's used to get an nicer error message
// TODO to respond with when validation fails.
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

// TODO Probably want to keep this as a default.
// decodeUUID is a form.Decoder decoding function that converts a string into a UUID.
func decodeUUID(vals []string) (interface{}, error) {
	if len(vals) >= 1 {
		return uuid.Parse(vals[0])
	}
	return nil, nil
}

// decodeUUID is a form.Decoder decoding function that converts a string into a UUID.
func encodeUUI(obj interface{}) ([]string, error) {
	uid, ok := obj.(uuid.UUID)
	if !ok {
		return nil, fmt.Errorf("object is not a uuid.UUID")
	}

	return []string{uid.String()}, nil
}

// validateNoUpperCase is a validator.Validate validator function that checks that the string field isn't uppercase.
func validateNoUpperCase(fl validator.FieldLevel) bool {
	v := fl.Field()
	var stringValue string
	if v.Kind() == reflect.Ptr {
		if v.IsNil() {
			return true
		}
		stringValue = *(v.Interface().(*string))
	} else {
		stringValue = v.Interface().(string)
	}
	for _, r := range stringValue {
		if unicode.IsLetter(r) && unicode.IsUpper(r) {
			return false
		}
	}
	return true
}

// validateSHA256Digest is a validator.Validate validator function that checks that the string field is in a sha256
// digest format.
func validateSHA256Digest(fl validator.FieldLevel) bool {
	v := fl.Field()
	var digest string
	if v.Kind() == reflect.Ptr {
		if v.IsNil() {
			return true
		}
		digest = *(v.Interface().(*string))
	} else {
		digest = v.Interface().(string)
	}

	// It's possible that the digest is in the format of "registry.com/repo@sha256:digest" so we need to remove the
	// registry and repo path if it exists and validate the rest.
	repoPathAndDigest := strings.SplitN(digest, "@", 2)
	if len(repoPathAndDigest) >= 2 {
		digest = repoPathAndDigest[1]
	}

	return strings.HasPrefix(digest, "sha256:")
}

// DecodeAndValidateReqParams decodes the request in the specific RequestParam type, and validates the fields based on
// the validation tags. The request body and query params are decoded into the RequestParam type, depending on if there
// is a body / are query / url params and what the content type is.
func DecodeAndValidateReqParams[RequestParam any](req *http.Request) (*RequestParam, error) {
	reqParams := new(RequestParam)

	// Don't assume the body is json (or even available) if the json header content type isn't set.
	content := strings.ToLower(strings.TrimSpace(req.Header.Get(HeaderContentType)))
	if content == ContentTypeApplicationJson {
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

// TODO this all need to be evaluated based on the current use cases. Image assurance uses them for various applications,
// TODO such as encoding requests in the bast API client. I suspect there's some better patterns here.

func EncodeToPathParameters(obj interface{}) (map[string]string, error) {
	pathParams := map[string]string{}
	values, err := urlPathEncoder.Encode(obj)
	if err != nil {
		return nil, err
	}

	for key, value := range values {
		var val string
		if len(value) > 0 {
			val = value[0]
		}
		pathParams[key] = val
	}

	return pathParams, nil
}

func EncodeToPathParameterPairList(obj interface{}) ([]string, error) {
	var list []string
	values, err := urlPathEncoder.Encode(obj)
	if err != nil {
		return nil, err
	}

	for key, value := range values {
		var val string
		if len(value) > 0 {
			val = value[0]
		}
		list = append(list, key, val)
	}

	return list, nil
}

func EncodeToQueryParameters(obj interface{}) (url.Values, error) {
	return urlQueryEncoder.Encode(obj)
}

func EncodeToHeaders(obj interface{}) (url.Values, error) {
	return headerEncoder.Encode(obj)
}

func DecodeURLQueryParameters(v interface{}, values url.Values) error {
	return urlQueryDecoder.Decode(v, values)
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
