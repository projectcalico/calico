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

		// GNP in baseline / anp namespaces.
		"0|adminnetworkpolicy|adminnetworkpolicy.name|deny|1",
		"1|baselineadminnetworkpolicy|baselineadminnetworkpolicy.name|deny|2",

		// Namespaced Calico NP
		"0|tier|namespace/tier.name|allow|1",
		"1|tier|namespace/staged:tier.name|deny|0",
		"1|tier|namespace/staged:tier.name.with.dots|deny|0",
		"0|tier1|default/tier1.np1-1|pass|0",

		// Namespaced KNP
		"0|tier|namespace/knp.default.name|allow|2",
		"1|tier|namespace/staged:knp.default.name|deny|3",
		"1|tier|namespace/staged:knp.default.name.with.dots|deny|3",

		// AdminNetworkPolicy
		"3|adminnetworkpolicy|kanp.adminnetworkpolicy.name|pass|4",
		"3|adminnetworkpolicy|kanp.adminnetworkpolicy.name.with.dots|pass|4",
		"2|adminnetworkpolicy|kanp.adminnetworkpolicy.name.with.dots|pass|1",

		// BaslineAdminNetworkPolicy
		"0|baselineadminnetworkpolicy|kbanp.baselineadminnetworkpolicy.name|pass|4",
		"3|baselineadminnetworkpolicy|kbanp.baselineadminnetworkpolicy.name.with.dots|pass|4",
		"2|baselineadminnetworkpolicy|kbanp.baselineadminnetworkpolicy.name.with.dots|pass|1",

		// Profile rules.
		"1|__PROFILE__|__PROFILE__.kns.default|allow|0",
		"2|__PROFILE__|__PROFILE__.kns.default|allow|1",
		"1|__PROFILE__|__PROFILE__.ksa.svcacct|allow|0",

		// End of tier rules - indicated by -1.
		"0|tier1|ns1/tier1.policy1|deny|-1",
		"1|tier1|ns1/tier1.policy1|allow|-1",
		"0|adminnetworkpolicy|kanp.adminnetworkpolicy.policy1|allow|-1",
		"2|adminnetworkpolicy|adminnetworkpolicy.policy1|allow|-1",
		"0|tier2|default/tier2.staged:np2-1|deny|-1",
		"1|tier2|default/tier2.staged:np2-1|deny|-1",
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
