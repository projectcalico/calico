package consistenthash

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash"
	"slices"

	"github.com/sirupsen/logrus"
	k8sp "k8s.io/kubernetes/pkg/proxy"
)

// ConsistentHash implements ConsistentHash consistent hashing:
//   - For each configured backend, generates a preference-list
//     of LUT positions it would like to occupy.
//   - Constructs a ConsistentHash backend LUT to be hashed-into with packet 5-tuples.
type ConsistentHash struct {
	// m is a prime number.
	// Defaults to ConsistentHash.M
	m      int
	h1, h2 hash.Hash

	// Lexicographically orders the backends by name.
	backendNames   []string
	backendsByName map[string]backend
}

type backend struct {
	permutation []int
	endpoint    k8sp.Endpoint
}

// New returns a backend-hashing module.
func New(lutSize int, hash1, hash2 hash.Hash) *ConsistentHash {
	c := &ConsistentHash{m: lutSize}
	c.backendNames = make([]string, 0)
	c.backendsByName = make(map[string]backend)

	if hash1 == nil || hash2 == nil {
		panic("nil hashing function for ConsistentHash")
	}
	c.h1 = hash1
	c.h2 = hash2

	return c
}

// AddBackend generates and stores a permutation for the given backend name,
// to be factored into the LUT generation.
func (ch *ConsistentHash) AddBackend(kep k8sp.Endpoint) {
	var b backend

	if kep == nil {
		logrus.Warn("Ignoring AddBackend for nil endpoint")
		return
	}

	name := kep.String()
	if _, exists := ch.backendsByName[name]; exists {
		logrus.WithField("backend", name).Info("Will not regenerate permutation for pre-existing backend")
		return
	}

	permutation, err := ch.permutation(name)
	if err != nil {
		logrus.WithError(err).WithField("backend", name).Error("Failed to generate permutation for backend")
		return
	}

	b.endpoint = kep
	b.permutation = permutation

	ch.backendsByName[name] = b
	ch.backendNames = append(ch.backendNames, name)
}

// Generate sorts the list of backends and then generates a ConsistentHash LUT.
func (ch *ConsistentHash) Generate() []k8sp.Endpoint {
	if len(ch.backendNames) == 0 {
		return nil
	}

	slices.Sort(ch.backendNames)
	logrus.WithField("backends", ch.backendNames).Info("sorted backend names")

	// Next-preference for each backend.
	next := make([]int, len(ch.backendNames))
	// The final lookup-table to hash against.
	lut := make([]k8sp.Endpoint, ch.m)

	// In total, we go to M iterations of the inner loop.
	// Can't rely on the outer-loop condition to break at the right time,
	// so we're counting manually.
	n := 0
	for {
		for i, backend := range ch.backendNames {
			prefs := ch.backendsByName[backend].permutation
			choice := prefs[next[i]]
			for lut[choice] != nil {
				next[i]++
				choice = prefs[next[i]]
			}

			lut[choice] = ch.backendsByName[backend].endpoint

			// Its *next* preference (after this one). Not sure if necessary to remember this.
			// Maybe it makes something easier later on if this info is to-hand?
			// If its safe to discard, we can probably rewrite this whole func to be more Go-ful.
			next[i]++
			n++
			if n == ch.m {
				return lut
			}
		}
	}
}

// Permutation implements Permutator interface.
func (ch *ConsistentHash) permutation(backendName string) ([]int, error) {
	offset, skip, err := ch.offsetAndSKip(backendName)
	if err != nil {
		return nil, fmt.Errorf("couldn't generate permutation skip/offset for backend '%s': %w", backendName, err)
	}

	permutation := make([]int, ch.m)
	for j := range ch.m {
		permutation[j] = (offset + (j * skip)) % ch.m
	}

	return permutation, nil
}

func (ch *ConsistentHash) offsetAndSKip(s string) (int, int, error) {
	offset, err := hashFromString(s, ch.h1, []byte{0})
	if err != nil {
		return 0, 0, err
	}

	skip, err := hashFromString(s, ch.h2, []byte{0xa})
	if err != nil {
		return 0, 0, err
	}
	return (offset % ch.m), (skip % (ch.m - 1)) + 1, nil
}

func hashFromString(s string, h hash.Hash, seed []byte) (int, error) {
	reinitHash(h, seed)

	h.Write([]byte(s))
	sum := h.Sum(nil)
	reader := bytes.NewReader(sum)
	var result uint32
	err := binary.Read(reader, binary.NativeEndian, &result)
	if err != nil {
		return 0, err
	}

	return int(result), nil
}

func reinitHash(h hash.Hash, seed []byte) {
	h.Reset()
	h.Write(seed)
}
