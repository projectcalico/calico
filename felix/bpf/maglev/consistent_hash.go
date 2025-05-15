package maglev

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash"
)

// Permutator is something than can generate a unique permutation of a sequence, given a backend name.
type Permutator interface {
	// Permutation makes a permutation of the sequence 0..M.
	// backendName is hashed to ensure each endpoint creates a unique permutation.
	// M must be a prime number.
	Permutation(backendName string, M int) (permutation []int)
}

// ConsistentHash implements Maglev consistent hashing, per-backend.
type ConsistentHash struct {
	h1, h2 hash.Hash
}

// M is a prime number much larger than any backend set we expect to have.
const M = 65537

type consistentHashOpt func(*ConsistentHash)

// WithHash returns an option that sets the maglev hash function.
func WithHash(hash1, hash2 hash.Hash) func(*ConsistentHash) {
	return func(m *ConsistentHash) {
		m.h1 = hash1
		m.h2 = hash2
	}
}

// NewConsistentHash returns a maglev hashing module.
func NewConsistentHash(o ...consistentHashOpt) *ConsistentHash {
	m := &ConsistentHash{}
	for _, option := range o {
		option(m)
	}

	if m.h1 == nil || m.h2 == nil {
		panic("nil hashing function for maglev")
	}

	return m
}

// Permutation implements Permutator interface.
func (c *ConsistentHash) Permutation(backendName string) ([]int, error) {
	offset, skip, err := c.offsetAndSKip(backendName)
	if err != nil {
		return nil, fmt.Errorf("Couldn't generate permutation skip/offset for backend '%s': %w", backendName, err)
	}

	permutation := make([]int, M)
	for j := range M {
		permutation[j] = (offset + (j * skip)) % M
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
	return (offset % M), (skip % (M - 1)) + 1, nil
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
