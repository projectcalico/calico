// Copyright (c) 2016-2025 Tigera, Inc. All rights reserved.
package rules

import (
	"fmt"

	"github.com/projectcalico/calico/felix/types"
	"github.com/projectcalico/calico/libcalico-go/lib/hash"
)

const (
	// From testing, it appears the max prefix length is 63 chars (so final char is likely a NULL terminator).
	NFLOGPrefixMaxLengthWoTerm = NFLOGPrefixMaxLength - 1
	// The number of chars of the unhashed prefix to keep as a prefix (of the prefix)
	hashedPrefixPrefixLen = 10
	// The number of chars of the unhashed prefix to keep as a suffix (of the prefix)
	hashedPrefixSuffixLen = 10
	// The number of chars for the hash
	hashLen = NFLOGPrefixMaxLengthWoTerm - hashedPrefixPrefixLen - hashedPrefixSuffixLen - 1
)

// CalculateNFLOGPrefixStr calculates NFLOG prefix string to use, limiting the length to 64 chars.
// The default format is:
// AODIII|Name ; with A:    the action: (A)llow, (D)eny, (N)ext-tier
//
//	O:    the owner type: (P)olicy or p(R)ofile
//	D:    the rule direction: (I)ngress or (E)gress
//	III:  the rule index (not a fixed number of digits)
//	Name: the policy or profile ID string, including one or more of name, namespace, and kind.
//
// If the total length of the prefix is greater than NFLOGPrefixMaxLength, then the first 10 chars
// and the last 10 chars are left unchanged and the remainder is filled in with a hash of the original prefix
// up to the max length. This allows for a reasonable stab at matching a hashed prefix with the profile or policy.
func CalculateNFLOGPrefixStr(action RuleAction, owner RuleOwnerType, dir RuleDir, idx int, id types.IDMaker) string {
	return maybeHash(fmt.Sprintf("%c%c%c%d|%s", action, owner, dir, idx, id.ID()))
}

// CalculateEndOfTierDropNFLOGPrefixStr calculates NFLOG prefix string to use for the no-policy-match
// drop action in a tier.
// The format is:
// AOD|Tier ; with A:    the action: Always (D)eny
//
//	O:    the owner type: Always (P)olicy
//	D:    the rule direction: (I)ngress or (E)gress
//	Tier: the tier name
//
// If the total length of the prefix is greater than NFLOGPrefixMaxLength, then the first 10 chars
// and the last 10 chars are left unchanged and the remainder is filled in with a hash of the original prefix
// up to the max length. This allows for a reasonable stab at matching a hashed prefix with the tier.
func CalculateEndOfTierDropNFLOGPrefixStr(dir RuleDir, tier string) string {
	return maybeHash(fmt.Sprintf("%c%c%c|%s", RuleActionDeny, RuleOwnerTypePolicy, dir, tier))
}

// CalculateEndOfTierPassNFLOGPrefixStr calculates NFLOG prefix string to use for the no-policy-match
// pass action in a tier. This is in replacement of the end-of-tier drop when all of the policies within the
// tier are staged.
// The format is:
// AOD|Tier ; with A:    the action: Always (P)ass
//
//	O:    the owner type: Always (P)olicy
//	D:    the rule direction: (I)ngress or (E)gress
//	Tier: the tier name
//
// If the total length of the prefix is greater than NFLOGPrefixMaxLength, then the first 10 chars
// and the last 10 chars are left unchanged and the remainder is filled in with a hash of the original prefix
// up to the max length. This allows for a reasonable stab at matching a hashed prefix with the tier.
func CalculateEndOfTierPassNFLOGPrefixStr(dir RuleDir, tier string) string {
	return maybeHash(fmt.Sprintf("%c%c%c|%s", RuleActionPass, RuleOwnerTypePolicy, dir, tier))
}

// CalculateNoMatchProfileNFLOGPrefixStr calculates NFLOG prefix string to use for the no-match profile
// drop action.
// The format is:
// AOD ; with A: the action: Always (D)eny
//
//	O: the owner type: Always p(R)rofile
//	D: the rule direction: (I)ngress or (E)gress
func CalculateNoMatchProfileNFLOGPrefixStr(dir RuleDir) string {
	// This is a fix length, it never needs hashing.
	return fmt.Sprintf("%c%c%c", RuleActionDeny, RuleOwnerTypeProfile, dir)
}

// CalculateNoMatchPolicyNFLOGPrefixStr calculates NFLOG prefix string to use for the no-match profile
// drop action.
// The format is:
// AOD|Policy ; with A:      the action: Always (D)eny
//
//	O:      the owner type: Always (P)olicy
//	D:      the rule direction: (I)ngress or (E)gress
//	Policy: the policy ID, consisting of the policy name, namespace, and kind.
func CalculateNoMatchPolicyNFLOGPrefixStr(dir RuleDir, id types.IDMaker) string {
	return maybeHash(fmt.Sprintf("%c%c%c|%s", RuleActionDeny, RuleOwnerTypePolicy, dir, id.ID()))
}

func maybeHash(prefix string) string {
	// Construct a hashed prefix if the prefix is too long. Note that we hash the prefix if length
	// ==NFLOGPrefixMaxLengthWoTerm rather than >NFLOGPrefixMaxLengthWoTerm - this prevents a user
	// from spoofing a hashed entry.
	if len(prefix) >= NFLOGPrefixMaxLengthWoTerm {
		fixedPrefix := prefix[:hashedPrefixPrefixLen]
		fixedSuffix := prefix[len(prefix)-hashedPrefixSuffixLen:]
		hash := hash.GetLengthLimitedID("", prefix, hashLen)
		prefix = fixedPrefix + hash + "_" + fixedSuffix
	}
	return prefix
}
