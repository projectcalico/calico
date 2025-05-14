package matchmap

import (
	"testing"
)

func TestMatchMap(t *testing.T) {
	mm := NewMatchMap[int, int, uint16]()
	mm.MustPut(1, 2)
	mm.MustPut(1, 3)
	mm.MustPut(1, 4)
	mm.MustPut(2, 3)
	mm.MustPut(5, 6)
	mm.MustPut(5, 7)
	if !mm.Get(1, 2) {
		t.Errorf("Expected to find match for (1, 2)")
	}
	if !mm.Get(1, 3) {
		t.Errorf("Expected to find match for (1, 3)")
	}
	if !mm.Get(1, 4) {
		t.Errorf("Expected to find match for (1, 4)")
	}
	if mm.Get(2, 1) {
		t.Errorf("Expected not to find match for (2, 1)")
	}
	if mm.Get(300, 2) {
		t.Errorf("Expected not to find match for (300, 2)")
	}
	for i := 0; i < 100; i++ {
		mm.MustPut(i, i)
	}
	for i := 0; i < 100; i++ {
		if !mm.Get(i, i) {
			t.Errorf("Expected to find match for (%d, %d)", i, i)
		}
	}

	mm.Delete(1, 4)
	if mm.Get(1, 4) {
		t.Errorf("Expected not to find match for (1, 4) after deletion")
	}
	mm.Delete(2, 3)
	if mm.Get(2, 3) {
		t.Errorf("Expected not to find match for (2, 3) after deletion")
	}
	mm.Delete(2, 2)
	if mm.Get(2, 2) {
		t.Errorf("Expected not to find match for (2, 3) after deletion")
	}
}

func TestAllBsForA(t *testing.T) {
	mm := NewMatchMap[int, int, uint16]()
	mm.MustPut(1, 2)
	mm.MustPut(1, 3)
	mm.MustPut(1, 4)
	mm.MustPut(2, 3)
	mm.MustPut(2, 4)
	mm.MustPut(3, 4)

	seenItems := make(map[int]bool)
	for b := range mm.AllBsForA(1) {
		if _, ok := seenItems[b]; ok {
			t.Errorf("Expected to see each item only once, but saw %d again", b)
		}
		seenItems[b] = true
	}
	if len(seenItems) != 3 || !seenItems[2] || !seenItems[3] || !seenItems[4] {
		t.Errorf("Expected to see 2, 3, and 4, but didn't see all of them")
	}

	seenItems = make(map[int]bool)
	for b := range mm.AllBsForA(2) {
		if _, ok := seenItems[b]; ok {
			t.Errorf("Expected to see each item only once, but saw %d again", b)
		}
		seenItems[b] = true
	}
	if len(seenItems) != 2 || !seenItems[3] || !seenItems[4] {
		t.Errorf("Expected to see 3, and 4, but didn't see all of them")
	}
}

func TestAllAsForB(t *testing.T) {
	mm := NewMatchMap[int, int, uint16]()
	mm.MustPut(2, 1)
	mm.MustPut(3, 1)
	mm.MustPut(4, 1)
	mm.MustPut(3, 2)
	mm.MustPut(4, 2)
	mm.MustPut(4, 3)

	seenItems := make(map[int]bool)
	for b := range mm.AllAsForB(1) {
		if _, ok := seenItems[b]; ok {
			t.Errorf("Expected to see each item only once, but saw %d again", b)
		}
		seenItems[b] = true
	}
	if len(seenItems) != 3 || !seenItems[2] || !seenItems[3] || !seenItems[4] {
		t.Errorf("Expected to see 2, 3, and 4, but didn't see all of them")
	}

	seenItems = make(map[int]bool)
	for b := range mm.AllAsForB(2) {
		if _, ok := seenItems[b]; ok {
			t.Errorf("Expected to see each item only once, but saw %d again", b)
		}
		seenItems[b] = true
	}
	if len(seenItems) != 2 || !seenItems[3] || !seenItems[4] {
		t.Errorf("Expected to see 3, and 4, but didn't see all of them")
	}
}
