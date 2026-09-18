// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package math

import (
	"math"
	"math/big"
)

// Ratio is used over total, or 0 when either is nil or total is not positive.
// Both are big.Ints because an IPv6 pool's address count overflows an int.
func Ratio(used, total *big.Int) float64 {
	if used == nil || total == nil || total.Sign() <= 0 {
		return 0
	}
	f, _ := new(big.Float).Quo(
		new(big.Float).SetInt(used),
		new(big.Float).SetInt(total),
	).Float64()
	return f
}

// RatioOf is Ratio for a count that is known to fit an int.
func RatioOf(used int, total *big.Int) float64 {
	return Ratio(big.NewInt(int64(used)), total)
}

// ClampToInt saturates rather than wrapping, for a count that has to reach a
// response field an int holds. A pool larger than an int is reported as the
// largest int rather than as a negative number.
func ClampToInt(n *big.Int) int {
	if n == nil {
		return 0
	}
	if !n.IsInt64() || n.Int64() > math.MaxInt {
		return math.MaxInt
	}
	return int(n.Int64())
}
