// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package calico

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
)

var _ = Describe("Secret watcher delete events", func() {
	var (
		sw     *secretWatcher
		secret *v1.Secret
		stopCh chan struct{}
	)

	BeforeEach(func() {
		secret = &v1.Secret{
			ObjectMeta: metav1.ObjectMeta{Namespace: "kube-system", Name: "bgp-password"},
			Data:       map[string][]byte{"password": []byte("s3cret")},
		}
		stopCh = make(chan struct{})
		sw = &secretWatcher{
			client:    &client{recheckC: make(chan struct{}, 1)},
			namespace: "kube-system",
			watches: map[string]*secretWatchData{
				secret.Name: {stopCh: stopCh, secret: secret},
			},
		}
	})

	// The informer substitutes a cache.DeletedFinalStateUnknown tombstone for
	// the secret whenever it loses track of the secret's final state, and the
	// tombstone may carry only a key.
	DescribeTable("clears the cached secret and keeps its watch",
		func(deleted func() any) {
			sw.OnDelete(deleted())

			Expect(sw.watches).To(HaveKey(secret.Name))
			Expect(sw.watches[secret.Name].secret).To(BeNil())
			// The watch goroutine outlives the secret: only SweepStale, which
			// needs this entry to find the channel, may stop it.
			Expect(sw.watches[secret.Name].stopCh).To(Equal(stopCh))
			Expect(stopCh).NotTo(BeClosed())
			Expect(sw.client.recheckC).To(Receive())
		},
		Entry("the secret itself", func() any { return secret }),
		Entry("a tombstone wrapping the secret", func() any {
			return cache.DeletedFinalStateUnknown{Key: "kube-system/bgp-password", Obj: secret}
		}),
		Entry("a tombstone carrying only the key", func() any {
			return cache.DeletedFinalStateUnknown{Key: "kube-system/bgp-password", Obj: nil}
		}),
	)

	It("ignores a delete event that yields no name", func() {
		Expect(func() { sw.OnDelete("not a secret") }).NotTo(Panic())
		Expect(func() { sw.OnDelete(nil) }).NotTo(Panic())

		Expect(sw.watches[secret.Name].secret).To(Equal(secret))
		Expect(sw.client.recheckC).NotTo(Receive())
	})

	It("reports no data for a deleted secret, and still serves it once recreated", func() {
		sw.OnDelete(secret)

		_, err := sw.GetSecret(secret.Name, "password")
		Expect(err).To(MatchError(ContainSubstring("no data available")))

		// The surviving watch is what delivers this.
		sw.OnAdd(secret, false)
		Expect(sw.GetSecret(secret.Name, "password")).To(Equal("s3cret"))
	})
})
