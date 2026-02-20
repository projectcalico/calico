package proto

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConversion(t *testing.T) {
	// Take a bunch of policy strings and convert them to PolicyHit structs, then back.
	// Ensure that the strings are the same before and after the conversion.
	tests := []string{
		// GNP
		"0|tier|gnp:name|allow|0",

		// Staged GNP
		"1|tier|sgnp:name|deny|2",
		"1|tier|sgnp:name.with.dots|deny|2",

		// GNP in ClusterNetworkPolicy namespaces.
		"0|kube-admin|kcnp:name|deny|1",
		"1|kube-baseline|kcnp:name|deny|2",

		// Namespaced Calico NP
		"0|tier|np:namespace/name|allow|1",
		"0|tier|np:namespace/tier.name|allow|1",
		"0|tier1|np:default/tier1.np1-1|pass|0",

		// Namespaced KNP
		"0|default|knp:namespace/name|allow|2",

		// Staged poliicies have a different format depending on the Kind.
		// For Calico policies:     <tier>|<namespace>/<tier>.staged:<name>
		// For kubernetes policies: default|<namespace>/staged:knp.default.<name>
		//
		// Calico Namespaced StagedNetworkPolicy.
		"1|tier|snp:namespace/name|deny|0",
		"1|tier|snp:namespace/name.with.dots|deny|0",

		// StagedKubernetesNetworkPolicy.
		"1|default|sknp:namespace/name|deny|3",
		"1|default|sknp:namespace/name.with.dots|deny|3",

		// ClusterNetworkPolicy - Admin Tier
		"3|kube-admin|kcnp:name|pass|4",
		"3|kube-admin|kcnp:name.with.dots|pass|4",
		"2|kube-admin|kcnp:name.with.dots|pass|1",

		// ClusterNetworkPolicy - Baseline Tier
		"3|kube-baseline|kcnp:name|pass|4",
		"3|kube-baseline|kcnp:name.with.dots|pass|4",
		"2|kube-baseline|kcnp:name.with.dots|pass|1",

		// Profile rules.
		"1|__PROFILE__|pro:kns.default|allow|0",
		"2|__PROFILE__|pro:kns.default|allow|1",
		"1|__PROFILE__|pro:ksa.svcacct|allow|0",

		// End of tier rules - indicated by -1.
		"0|tier1|np:ns1/tier1.policy1|deny|-1",
		"1|tier1|np:ns1/tier1.policy1|allow|-1",
		"0|kube-admin|kcnp:policy1|allow|-1",
		"2|kube-admin|gnp:kube-admin.policy1|allow|-1",
		"0|tier2|snp:default/np2-1|deny|-1",
		"1|tier2|snp:default/np2-1|deny|-1",
	}

	for _, strVal := range tests {
		t.Run(strVal, func(t *testing.T) {
			hit, err := HitFromString(strVal)
			if err != nil {
				t.Fatalf("Failed to convert string to PolicyHit: %v", err)
			}

			converted, err := hit.ToString()
			require.NoError(t, err)
			if converted != strVal {
				t.Fatalf("Conversion failed: expected %s, got %s", strVal, converted)
			}
		})
	}
}

func TestInvalidStrings(t *testing.T) {
	tests := []string{
		// Invalid integer values.
		"1|tier|sgnp:tier.name|deny|notInt",
		"notint|kube-baseline|kcnp:name|deny|2",
		"notint|kube-baseline|kcnp:name|pass|4",
		"notint|tier1|np:ns1/tier1.policy1|deny|-1",

		// An extra section.
		"0|tier|gnp:tier.name|allow|0|extra",

		// Invalid characters.
		"1|tier|gnp:invalid-ch@aracter|deny|2",
		"1|_|snp:namespace/tier.name|deny|0",
		"0|@kube-baseline|kcnp:policy1|allow|-1",

		// Bad action field.
		"0|kube-admin|kcnp:name|badaction|1",

		// Tier field is missing.
		"0||np:namespace/name|allow|1",

		// Missing a name section.
		"0|tier1|np:namespace/|pass|0",

		// Profile rules.
		"1|___PROFILE__|pro:kns.default|allow|0",
		"1|__PROFILE__|pro:PSA.svcacct|allow|0",
	}

	for _, strVal := range tests {
		t.Run(strVal, func(t *testing.T) {
			_, err := HitFromString(strVal)
			require.Error(t, err)
		})
	}
}

func TestToString(t *testing.T) {
	type testCase struct {
		name   string
		hit    *PolicyHit
		err    string
		strVal string
	}
	tests := []testCase{
		{
			name:   "Valid base case",
			strVal: "0|tier|gnp:name|allow|0",
			hit: &PolicyHit{
				Kind:        PolicyKind_GlobalNetworkPolicy,
				Tier:        "tier",
				Name:        "name",
				Namespace:   "",
				Action:      Action_Allow,
				RuleIndex:   0,
				PolicyIndex: 0,
			},
		},
		{
			name: "Invalid action",
			err:  "unexpected action",
			hit: &PolicyHit{
				Kind:        PolicyKind_GlobalNetworkPolicy,
				Tier:        "tier",
				Name:        "name",
				Namespace:   "",
				Action:      Action(500),
				RuleIndex:   0,
				PolicyIndex: 0,
			},
		},
		{
			name: "Invalid kind",
			err:  "unexpected policy kind",
			hit: &PolicyHit{
				Kind:        PolicyKind(500),
				Tier:        "tier",
				Name:        "name",
				Namespace:   "namespace",
				Action:      Action_Allow,
				RuleIndex:   0,
				PolicyIndex: 0,
			},
		},
		{
			name: "GNP with a Namespace specified",
			err:  "unexpected namespace",
			hit: &PolicyHit{
				Kind:        PolicyKind_GlobalNetworkPolicy,
				Tier:        "tier",
				Name:        "name",
				Namespace:   "namespace",
				Action:      Action_Allow,
				RuleIndex:   0,
				PolicyIndex: 0,
			},
		},
		{
			name: "Missing trigger for EndOfTier",
			err:  "missing trigger",
			hit: &PolicyHit{
				Kind:        PolicyKind_EndOfTier,
				Tier:        "tier",
				Name:        "name",
				Namespace:   "namespace",
				Action:      Action_Allow,
				RuleIndex:   0,
				PolicyIndex: 0,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			val, err := tc.hit.ToString()
			if tc.err != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.err)
			} else {
				require.NoError(t, err)
			}

			if tc.strVal != "" {
				require.Equal(t, tc.strVal, val)
			}
		})
	}
}
