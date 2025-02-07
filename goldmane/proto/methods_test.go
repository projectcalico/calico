package proto

import "testing"

func TestConversion(t *testing.T) {
	// Take a bunch of policy strings and convert them to PolicyHit structs, then back.
	// Ensure that the strings are the same before and after the conversion.
	tests := []string{
		// GNP
		"0|tier|tier.name|allow|0",
		"1|tier|staged:tier.name|deny|2",
		"1|tier|staged:tier.name.with.dots|deny|2",

		// Namespaced Calico NP
		"0|tier|namespace/tier.name|allow|1",
		"1|tier|namespace/staged:tier.name|deny|0",
		"1|tier|namespace/staged:tier.name.with.dots|deny|0",

		// Namespaced KNP
		"0|tier|namespace/knp.default.name|allow|2",
		"1|tier|namespace/staged:knp.default.name|deny|3",
		"1|tier|namespace/staged:knp.default.name.with.dots|deny|3",

		// AdminNetworkPolicy
		"3|adminnetworkpolicy|anp.adminnetworkpolicy.name|pass|4",
		"3|adminnetworkpolicy|anp.adminnetworkpolicy.name.with.dots|pass|4",

		// Profile rules.
		"1|__PROFILE__|__PROFILE__.kns.default|allow|0",
		"1|__PROFILE__|__PROFILE__.ksa.svcacct|allow|0",
	}

	for _, strVal := range tests {
		t.Run(strVal, func(t *testing.T) {
			hit, err := HitFromString(strVal)
			if err != nil {
				t.Fatalf("Failed to convert string to PolicyHit: %v", err)
			}

			converted := hit.ToString()
			if converted != strVal {
				t.Fatalf("Conversion failed: expected %s, got %s", strVal, converted)
			}
		})
	}
}
