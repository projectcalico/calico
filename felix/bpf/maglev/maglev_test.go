package maglev

import (
	"hash/fnv"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"

	types "github.com/projectcalico/calico/felix/bpf/maglev/test"
)

var testM = 71

var _ = Describe("BPF maglev UTs", func() {
	newDefaultMaglevmaglev := func() *ConsistentHash {
		return NewConsistentHash(
			WithHash(fnv.New32(), fnv.New32()),
			// A big prime would cause this test's duration to balloon.
			WithPreferenceLength(testM))
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
			mag = newDefaultMaglevmaglev()
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

			time.Sleep(4 * time.Second)
			lut := mag.Generate()
			Expect(lut).NotTo(ContainElement(""))
			Expect(lut).To(HaveLen(testM))
		})

		It("should generate the same permutations for the same backend", func() {
			otherMag := newDefaultMaglevmaglev()
			for _, b := range []string{"backend1", "backend2"} {
				e0 := addBackend(mag, b, uint16(8080))
				e1 := addBackend(otherMag, b, uint16(8080))
				Expect(mag.backendsByName[e0.String()]).To(Equal(otherMag.backendsByName[e1.String()]))
			}
		})
	})
})
