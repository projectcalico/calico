package bitset

import "testing"

func TestBitset(t *testing.T) {
	bitset := NewBitSet()
	bitset.Add(1)
	bitset.Add(2)
	bitset.Add(3)

	if !bitset.Contains(1) {
		t.Errorf("Expected bitset to contain 1")
	}
	if !bitset.Contains(2) {
		t.Errorf("Expected bitset to contain 2")
	}
	if !bitset.Contains(3) {
		t.Errorf("Expected bitset to contain 3")
	}
	if bitset.Len() != 3 {
		t.Errorf("Expected bitset length to be 3, got %d", bitset.Len())
	}

	bitset.Discard(2)
	if bitset.Contains(2) {
		t.Errorf("Expected bitset to not contain 2 after discard")
	}
	if bitset.Len() != 2 {
		t.Errorf("Expected bitset length to be 2, got %d", bitset.Len())
	}
}
