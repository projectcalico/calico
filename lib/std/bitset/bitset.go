package bitset

import (
	"iter"
	"math/bits"
	"slices"
)

type BitSet struct {
	count int
	words []uint64
}

func NewBitSet() *BitSet {
	return &BitSet{}
}

func (b *BitSet) Add(i int) {
	wordIdx := i / 64
	bitIdx := i % 64
	if wordIdx >= len(b.words) {
		newWords := slices.Grow(b.words, wordIdx+1)
		for len(newWords) < wordIdx+1 {
			newWords = append(newWords, 0)
		}
		b.words = newWords
	}
	if b.words[wordIdx]&(1<<bitIdx) != 0 {
		return
	}
	b.words[wordIdx] |= 1 << bitIdx
	b.count++
}

func (b *BitSet) Discard(i int) {
	wordIdx := i / 64
	bitIdx := i % 64
	if wordIdx >= len(b.words) {
		return
	}
	if b.words[wordIdx]&(1<<bitIdx) == 0 {
		return
	}
	b.words[wordIdx] &^= 1 << bitIdx
	b.count--
}

func (b *BitSet) Contains(i int) bool {
	wordIdx := i / 64
	bitIdx := i % 64
	if wordIdx >= len(b.words) {
		return false
	}
	return b.words[wordIdx]&(1<<bitIdx) != 0
}

func (b *BitSet) Len() int {
	return b.count
}

func (b *BitSet) Clear() {
	b.words = nil
	b.count = 0
}

func (b *BitSet) All() iter.Seq[int] {
	return func(yield func(int) bool) {
		for i := 0; i < len(b.words); i++ {
			word := b.words[i]
			base := i * 64
			for {
				tz := bits.TrailingZeros64(word)
				if tz == 64 {
					break
				}
				yield(tz + base)
				word &^= 1 << tz
			}
		}
	}
}
