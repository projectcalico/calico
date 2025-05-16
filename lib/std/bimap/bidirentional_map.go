package bimap

import (
	"iter"
	"maps"
)

type BiMap[A, B comparable] struct {
	aToB map[A]B
	bToA map[B]A
}

func NewBiMap[A, B comparable]() *BiMap[A, B] {
	return &BiMap[A, B]{
		aToB: make(map[A]B),
		bToA: make(map[B]A),
	}
}

func (m *BiMap[A, B]) Put(a A, b B) {
	m.aToB[a] = b
	m.bToA[b] = a
}

func (m *BiMap[A, B]) GetA(b B) (A, bool) {
	a, ok := m.bToA[b]
	return a, ok
}

func (m *BiMap[A, B]) GetB(a A) (B, bool) {
	b, ok := m.aToB[a]
	return b, ok
}

func (m *BiMap[A, B]) All() iter.Seq2[A, B] {
	return maps.All(m.aToB)
}

func (m *BiMap[A, B]) DeleteA(a A) {
	b, ok := m.aToB[a]
	if !ok {
		return
	}
	delete(m.aToB, a)
	delete(m.bToA, b)
}

func (m *BiMap[A, B]) Len() int {
	return len(m.aToB)
}
