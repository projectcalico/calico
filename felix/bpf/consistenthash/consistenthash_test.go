package consistenthash

import (
	"fmt"
	"hash/fnv"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"

	types "github.com/projectcalico/calico/felix/bpf/consistenthash/test"
)

var testM = 71

var _ = Describe("BPF ConsistentHash UTs", func() {
	newDefaultConsistentHash := func() *ConsistentHash {
		return New(
			// A big prime would cause this test's execution time to balloon.
			testM,
			fnv.New32(), fnv.New32(),
		)
	}

	addBackend := func(mag *ConsistentHash, ip string, port uint16) types.MockEndpoint {
		e := types.MockEndpoint{
			Ip:  ip,
			Prt: port,
		}
		permutation, err := mag.permutation(e.String())
		Expect(err).NotTo(HaveOccurred())

		mag.backendsByName[e.String()] = backend{permutation: permutation, endpoint: e}
		mag.backendNames = append(mag.backendNames, e.String())

		logrus.Infof("Appending backend name %s to backends. Num backends: %d", e.String(), len(mag.backendNames))
		return e
	}

	Context("Consistent hashing", func() {
		var mag *ConsistentHash

		BeforeEach(func() {
			mag = newDefaultConsistentHash()
		})

		It("generate valid permutations", func() {
			for _, b := range []string{"backend1", "backend2", "backend3", "sdfskjnksdnf", "sdfkjsdnfksjndf", "i am a backend with a very very very long nameeeeeeeeeeeeeeeeeeeeee"} {
				p, err := mag.permutation(b)
				Expect(err).NotTo(HaveOccurred())
				dupMap := make(map[int]bool)
				for _, idx := range p {
					Expect(dupMap).NotTo(HaveKey(idx))
					dupMap[idx] = true
				}
			}
		})

		It("should create a lookup table", func() {
			for _, b := range []string{"backend0", "backend1", "backend2", "backend3", "backend4", "backend5", "backend6", "backend7", "backend8", "backend9"} {
				addBackend(mag, b, uint16(8080))
			}

			lut := mag.Generate()
			Expect(lut).NotTo(ContainElement(""))
			Expect(lut).To(HaveLen(testM))
		})

		It("should generate the same permutations for the same backend", func() {
			otherMag := newDefaultConsistentHash()
			for _, b := range []string{"backend1", "backend2"} {
				e0 := addBackend(mag, b, uint16(8080))
				e1 := addBackend(otherMag, b, uint16(8080))
				Expect(mag.backendsByName[e0.String()]).To(Equal(otherMag.backendsByName[e1.String()]))
			}
		})

		It("evenly distribute LUT spaces for every backend", func() {
			backends := []string{"backend0", "backend1", "backend2", "backend3", "backend4", "backend5", "backend6", "backend7", "backend8", "backend9"}
			for _, b := range backends {
				addBackend(mag, b, uint16(8080))
			}

			lut := mag.Generate()
			Expect(lut).NotTo(ContainElement(""))
			Expect(lut).To(HaveLen(testM))

			By("gathering all IPs in the LUT, validating each one, and counting occurrences")
			foundBackends := make(map[string]int)
			for _, ep := range lut {
				be := ep.IP()
				foundBackends[be] = foundBackends[be] + 1

				Expect(backends).To(ContainElement(be))
			}

			By("Checking every backend is present")
			for _, b := range backends {
				Expect(foundBackends).To(HaveKey(b))
			}

			By("confirming the number of occurrences of each key does not differ by more than 1")
			lowest := -1
			highest := -1
			for _, v := range foundBackends {
				if lowest == -1 {
					lowest = v
				}
				if v > highest {
					highest = v
				}
				if v < lowest {
					lowest = v
				}
			}

			greaterThanOne := (highest - lowest) > 1
			Expect(greaterThanOne).To(BeFalse(), fmt.Sprintf("Highest backends occurrences: %d, lowest: %d", highest, lowest))
		})
	})
})
