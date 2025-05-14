package maglev

import (
	"hash/fnv"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("BPF maglev UTs", func() {

	Context("Consistent hashing", func() {
		It("generate valid permutations", func() {
			maglev := NewConsistentHash(
				WithHash(fnv.New32(), fnv.New32()))

			for _, b := range []string{"backend1", "backend2", "backend3", "sdfskjnksdnf", "sdfkjsdnfksjndf", "i am a backend with a very very very long nameeeeeeeeeeeeeeeeeeeeee"} {
				p, err := maglev.Permutation(b)
				Expect(err).NotTo(HaveOccurred())
				dupMap := make(map[int]bool)
				for _, idx := range p {
					Expect(dupMap).NotTo(HaveKey(idx))
					dupMap[idx] = true
				}
			}
		})

		It("should create a lookup table", func() {
			table := NewLookupTable()
			for _, b := range []string{"backend0", "backend1", "backend2", "backend3", "backend4", "backend5", "backend6", "backend7", "backend8", "backend9"} {
				table.AddBackend(b)
			}
			table.regenerate()
			Expect(table.lut).NotTo(ContainElement(-1))
		})
	})
})
