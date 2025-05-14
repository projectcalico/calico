package maglev

import (
	"hash/fnv"

	"github.com/sirupsen/logrus"
)

// LookupTable stores preference-lists (permutations) for each backend
// and uses them to generate a backend lookuptable.
type LookupTable struct {
	ch                           *ConsistentHash
	permutations                 [][]int
	backendNameToPermutationsIdx map[string]int
	lut                          []int

	log logrus.Entry
}

// NewLookupTable returns a lookup table.
func NewLookupTable() *LookupTable {
	lut := new(LookupTable)
	lut.ch = NewConsistentHash(WithHash(fnv.New32(), fnv.New32()))
	lut.backendNameToPermutationsIdx = make(map[string]int)
	return lut
}

// AddBackend generates and stores a permutation for the given backend name,
// to be factored into the LUT generation.
func (l *LookupTable) AddBackend(name string) {
	if name == "" {
		l.log.Warn("Ignoring new backend with empty name")
		return
	}

	if _, exists := l.backendNameToPermutationsIdx[name]; exists {
		l.log.WithField("backend", name).Info("Will not regenerate permutation for pre-existing backend")
		return
	}

	permutation, err := l.ch.Permutation(name)
	if err != nil {
		l.log.WithError(err).WithField("backend", name).Error("Failed to generate permutation for backend")
		return
	}

	l.permutations = append(l.permutations, permutation)
	l.backendNameToPermutationsIdx[name] = len(l.permutations) - 1
	return
}

func (l *LookupTable) regenerate() {
	// Next-preference for each backend.
	next := make([]int, len(l.permutations))
	// The final lookup-table to hash against.
	lut := make([]int, M)
	for i := range M {
		lut[i] = -1
	}

	// In total, we go to M iterations of the inner loop.
	// Can't rely on the outer-loop condition to break at the right time,
	// so we're counting manually.
	n := 0
populate:
	for {
		for i, prefs := range l.permutations {
			choice := prefs[next[i]]
			for lut[choice] != -1 {
				next[i]++
				choice = prefs[next[i]]
			}

			lut[choice] = i
			// Its *next* preference (after this one). Not sure if necessary to remember this.
			// Maybe it makes something easier later on if this info is to-hand?
			// If its safe to discard, we can probably rewrite this whole func to be more Go-ful.
			next[i]++
			n++
			if n == M {
				break populate
			}
		}
	}
	l.lut = lut
}
