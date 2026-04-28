// Package calico extends sigs.k8s.io/controller-tools with two CRD markers:
//
//   - +calico:numOrString    on a struct type (e.g. numorstring.Port) — emits
//     an x-kubernetes-int-or-string union schema, equivalent to apimachinery's
//     intstr.IntOrString.
//   - +calico:nullableItems  on a slice field with pointer elements (e.g.
//     []*int) — marks items as nullable, which upstream does not auto-detect.
package calico

import (
	"fmt"

	apiext "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	crdmarkers "sigs.k8s.io/controller-tools/pkg/crd/markers"
	"sigs.k8s.io/controller-tools/pkg/markers"
)

// NumOrStringMarker is the marker name placed on Go type or field declarations
// to request an int-or-string union schema.
const NumOrStringMarker = "calico:numOrString"

// NumOrString implements the +calico:numOrString marker.
type NumOrString struct{}

// ApplyToSchema replaces the schema with the int-or-string union.
// Replacement (not merge) is required: by the time this runs, controller-gen
// has already walked the underlying struct and populated Properties/Required,
// which would otherwise leak into the output.
func (NumOrString) ApplyToSchema(schema *apiext.JSONSchemaProps) error {
	*schema = apiext.JSONSchemaProps{
		XIntOrString: true,
		AnyOf: []apiext.JSONSchemaProps{
			{Type: "integer"},
			{Type: "string"},
		},
		Pattern: "^.*",
	}
	return nil
}

// ApplyPriority matches upstream XIntOrString's priority so it runs before
// other validation markers.
func (NumOrString) ApplyPriority() crdmarkers.ApplyPriority {
	return crdmarkers.ApplyPriorityDefault - 1
}

// NullableItemsMarker is the marker name placed on slice fields to mark their
// items as nullable in the generated schema.
const NullableItemsMarker = "calico:nullableItems"

// NullableItems implements the +calico:nullableItems marker.
type NullableItems struct{}

// ApplyToSchema sets schema.Items.Schema.Nullable on an array schema.
// Errors on non-array fields so misuse fails at gen time, not silently.
func (NullableItems) ApplyToSchema(schema *apiext.JSONSchemaProps) error {
	if schema.Type != "array" || schema.Items == nil || schema.Items.Schema == nil {
		return fmt.Errorf("+%s applies to slice fields only (got type=%q)", NullableItemsMarker, schema.Type)
	}
	schema.Items.Schema.Nullable = true
	return nil
}

// RegisterMarkers adds the +calico:numOrString and +calico:nullableItems
// markers to reg.
func RegisterMarkers(reg *markers.Registry) error {
	for _, target := range []markers.TargetType{markers.DescribesType, markers.DescribesField} {
		def, err := markers.MakeDefinition(NumOrStringMarker, target, NumOrString{})
		if err != nil {
			return err
		}
		if err := reg.Register(def); err != nil {
			return err
		}
	}
	nullableItemsDef, err := markers.MakeDefinition(NullableItemsMarker, markers.DescribesField, NullableItems{})
	if err != nil {
		return err
	}
	if err := reg.Register(nullableItemsDef); err != nil {
		return err
	}
	return nil
}

