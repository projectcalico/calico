package calico

import (
	"testing"

	apiext "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"sigs.k8s.io/controller-tools/pkg/markers"
)

// TestNumOrStringApplyToSchema verifies the marker rewrites schemas to the
// int-or-string union shape used by Calico's existing CRDs.
func TestNumOrStringApplyToSchema(t *testing.T) {
	schema := apiext.JSONSchemaProps{Type: "object"}
	if err := (NumOrString{}).ApplyToSchema(&schema); err != nil {
		t.Fatalf("ApplyToSchema: %v", err)
	}
	if schema.Type != "" {
		t.Errorf("Type: want empty, got %q", schema.Type)
	}
	if !schema.XIntOrString {
		t.Errorf("XIntOrString: want true")
	}
	if got := len(schema.AnyOf); got != 2 {
		t.Fatalf("AnyOf: want 2 entries, got %d", got)
	}
	if schema.AnyOf[0].Type != "integer" || schema.AnyOf[1].Type != "string" {
		t.Errorf("AnyOf: want [integer,string], got [%s,%s]", schema.AnyOf[0].Type, schema.AnyOf[1].Type)
	}
	if schema.Pattern != "^.*" {
		t.Errorf("Pattern: want %q, got %q", "^.*", schema.Pattern)
	}
}

// TestNumOrStringWipesStructWalk verifies the marker wholesale-replaces the
// schema, since when applied to a struct-shaped Go type controller-gen has
// already populated Properties/Required/Type from the struct walk; merging
// onto that would leak the struct shape into the CRD.
func TestNumOrStringWipesStructWalk(t *testing.T) {
	schema := apiext.JSONSchemaProps{
		Type:       "object",
		Properties: map[string]apiext.JSONSchemaProps{"numVal": {Type: "integer"}},
		Required:   []string{"numVal"},
	}
	if err := (NumOrString{}).ApplyToSchema(&schema); err != nil {
		t.Fatalf("ApplyToSchema: %v", err)
	}
	if schema.Type != "" {
		t.Errorf("Type: want empty, got %q", schema.Type)
	}
	if len(schema.Properties) != 0 {
		t.Errorf("Properties: want empty, got %v", schema.Properties)
	}
	if len(schema.Required) != 0 {
		t.Errorf("Required: want empty, got %v", schema.Required)
	}
	if !schema.XIntOrString {
		t.Errorf("XIntOrString: want true")
	}
}

// TestRegisterMarkers verifies the marker can be registered on both type and
// field targets without conflict.
func TestRegisterMarkers(t *testing.T) {
	reg := &markers.Registry{}
	if err := RegisterMarkers(reg); err != nil {
		t.Fatalf("RegisterMarkers: %v", err)
	}
	if def := reg.Lookup("+"+NumOrStringMarker, markers.DescribesType); def == nil {
		t.Errorf("type marker %q not registered", NumOrStringMarker)
	}
	if def := reg.Lookup("+"+NumOrStringMarker, markers.DescribesField); def == nil {
		t.Errorf("field marker %q not registered", NumOrStringMarker)
	}
	if def := reg.Lookup("+"+NullableItemsMarker, markers.DescribesField); def == nil {
		t.Errorf("field marker %q not registered", NullableItemsMarker)
	}
}

// TestNullableItemsApplyToSchema verifies the marker sets nullable on the
// items schema of an array.
func TestNullableItemsApplyToSchema(t *testing.T) {
	schema := apiext.JSONSchemaProps{
		Type: "array",
		Items: &apiext.JSONSchemaPropsOrArray{
			Schema: &apiext.JSONSchemaProps{Type: "integer"},
		},
	}
	if err := (NullableItems{}).ApplyToSchema(&schema); err != nil {
		t.Fatalf("ApplyToSchema: %v", err)
	}
	if !schema.Items.Schema.Nullable {
		t.Errorf("Items.Schema.Nullable: want true")
	}
	if schema.Nullable {
		t.Errorf("Nullable: want false on outer schema")
	}
}

// TestNullableItemsRejectsNonArray verifies the marker errors out on
// non-array schemas instead of silently no-oping.
func TestNullableItemsRejectsNonArray(t *testing.T) {
	schema := apiext.JSONSchemaProps{Type: "string"}
	if err := (NullableItems{}).ApplyToSchema(&schema); err == nil {
		t.Errorf("expected error for non-array schema")
	}
}

