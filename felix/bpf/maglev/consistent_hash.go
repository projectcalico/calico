package maglev

import (
	"github.com/sirupsen/logrus"
	"golang.org/x/exp/slices"
	k8sp "k8s.io/kubernetes/pkg/proxy"

	"bytes"
	"encoding/binary"
	"fmt"
	"hash"
)

// M is a prime number much larger than any backend set we expect to have.
const M = 1009

type ConsistentHashOpt func(*ConsistentHash)

// WithHash returns an option that sets the maglev hash function.
func WithHash(hash1, hash2 hash.Hash) func(*ConsistentHash) {
	return func(c *ConsistentHash) {
		c.h1 = hash1
		c.h2 = hash2
	}
}

// WithLUTLength configures the LUT-size and subsequently,
// the preference-list length for each backend.
// Should be a prime number.
func WithPreferenceLength(m int) func(*ConsistentHash) {
	return func(c *ConsistentHash) {
		c.m = m
	}
}

// ConsistentHash implements Maglev consistent hashing:
//   - For each configured backend, generates a preference-list
//     of LUT positions it would like to occupy.
//   - Constructs a Maglev backend LUT to be hashed-into with packet 5-tuples.
type ConsistentHash struct {
	// m is a prime number.
	// Defaults to maglev.M
	m      int
	h1, h2 hash.Hash

	// Lexicographically orders the backends by name.
	backendNames []string

	backendsByName map[string]backend
}

type backend struct {
	permutation []int
	endpoint    k8sp.Endpoint
}

// NewConsistentHash returns a maglev hashing module.
func NewConsistentHash(o ...ConsistentHashOpt) *ConsistentHash {
	c := &ConsistentHash{m: M}
	c.backendNames = make([]string, 0)
	c.backendsByName = make(map[string]backend)

	for _, option := range o {
		option(c)
	}

	if c.h1 == nil || c.h2 == nil {
		panic("nil hashing function for maglev")
	}

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

func (ch *ConsistentHash) RemoveBackend(kep k8sp.Endpoint) {
	name := kep.String()
	if kep == nil {
		logrus.Warn("Ignoring RemoveBackend for nil endpoint")
		return
	}

	b, exists := ch.backendsByName[name]
	if !exists {
		logrus.WithField("backend", name).Info("Aborting RemoveBackend for non-existent backend")
		return
	}

	b.endpoint = nil
	delete(ch.backendsByName, name)

	for i, b := range ch.backendNames {
		if b == name {
			slices.Delete(ch.backendNames, i, i)
		}
	}
}

// Generate sorts the list of backends and then generates a Maglev LUT.
func (ch *ConsistentHash) Generate() []k8sp.Endpoint {
	slices.Sort(ch.backendNames)
	logrus.WithField("backends", ch.backendNames).Info("sorted backend names")

	// Next-preference for each backend.
	next := make([]int, len(ch.backendNames))
	// The final lookup-table to hash against.
	lut := make([]k8sp.Endpoint, ch.m)
	defer func() {
		logrus.WithField("lut", lut).Info("Halting generation")
	}()

	// In total, we go to M iterations of the inner loop.
	// Can't rely on the outer-loop condition to break at the right time,
	// so we're counting manually.
	n := 0
populate:
	for {
		for i, backend := range ch.backendNames {
			prefs := ch.backendsByName[backend].permutation
			logrus.WithFields(logrus.Fields{"permutation": prefs, "backend": backend}).Info("Got preference list for backend")
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
				break populate
			}
		}
	}

	return lut
}

// Permutation implements Permutator interface.
func (c *ConsistentHash) permutation(backendName string) ([]int, error) {
	offset, skip, err := c.offsetAndSKip(backendName)
	if err != nil {
		return nil, fmt.Errorf("couldn't generate permutation skip/offset for backend '%s': %w", backendName, err)
	}

	permutation := make([]int, c.m)
	for j := range c.m {
		permutation[j] = (offset + (j * skip)) % c.m
	}

	return permutation, nil
}

func (c *ConsistentHash) offsetAndSKip(s string) (int, int, error) {
	offset, err := hashFromString(s, c.h1, []byte{0})
	if err != nil {
		return 0, 0, err
	}

	skip, err := hashFromString(s, c.h2, []byte{0xa})
	if err != nil {
		return 0, 0, err
	}
	return (offset % c.m), (skip % (c.m - 1)) + 1, nil
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
