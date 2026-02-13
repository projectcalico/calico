package intdataplane

import (
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/projectcalico/calico/felix/proto"
)

type fakeResettableTimer struct {
	C chan time.Time
}

func newFakeResettableTimer() *fakeResettableTimer {
	t := &fakeResettableTimer{
		C: make(chan time.Time),
	}

	return t
}

func (t *fakeResettableTimer) Chan() <-chan time.Time {
	return t.C
}

func (t *fakeResettableTimer) Reset(time.Duration) bool {
	// Maybe drain a pending alarm.
	select {
	case <-t.C:
		return false
	default:
		return true
	}
}

// Pretend the given duration has passed and pop the timer.
func (t *fakeResettableTimer) Fire() {
	t.C <- time.Now()
}

var _ = Describe("HostMetadataCache UTs", func() {
	It("should flush the first set of updates without waiting for the throttling timer, and then wait for the timer for subsequent flushes", func() {
		Expect(0)
		// Run the metadata cache with a fake timer.
		timer := newFakeResettableTimer()
		newFakeTimerFn := func(t time.Duration) ResettableTimer {
			_ = timer.Reset(t)
			return timer
		}

		// Updates will be sent to us from another goroutine.
		// We need thread-safety to receive them back on this thread.
		updatesC := make(chan map[string]*proto.HostMetadataV4V6Update, 1)
		checkForUpdates := func() map[string]*proto.HostMetadataV4V6Update {
			select {
			case u := <-updatesC:
				return u
			default:
				return nil
			}
		}

		// The updates callback will write the running total of dropped
		// updates since the channel was last consumed.
		// I.e. if an old update was never consumed, it would be overwritten
		// (dropped) by a fresher update, and the dropped counter would go up.
		// If we receive droppedC to read the number of drops, the total resets to 0.
		// droppedC will block any receives when updates haven't been sent on updatesC.
		droppedC := make(chan int, 1)
		// This callback is written with the assumption that only one goroutine call call it
		// at any given time.
		updatesCallback := func(u map[string]*proto.HostMetadataV4V6Update) {
			droppedUpdate := false
			select {
			// Drain/drop old update if necessary.
			case <-updatesC:
				droppedUpdate = true
			// Otherwise, send new update.
			case updatesC <- u:
			}

			// Update the number of dropped updates.
			numDropped := 0
			if droppedUpdate {
				numDropped = 1
			}
			select {
			case droppedC <- numDropped:
			case lastNumDropped := <-droppedC:
				droppedC <- lastNumDropped + numDropped
			}
		}

		cacheT := NewHostMetadataCache(OptWithThrottleInterval(1*time.Second), OptWithNewTimerFn(newFakeTimerFn))
		cacheT.SetOnHostUpdateCB(updatesCallback)
		cacheT.Start()

		update := &proto.HostMetadataV4V6Update{
			Hostname: "hn1",
			Ipv4Addr: "1.2.3.4",
			Labels:   map[string]string{"label1": "label1val"},
		}

		// Fill the cache with updates.
		cacheT.OnUpdate(update)

		// Ensure it *doesn't* flush the updates.
		Consistently(checkForUpdates).Should(BeNil(), "Cache prematurely fired updates")

		// Call CompleteDeferredWork.
		err := cacheT.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		// Ensure it *does* flush the updates.
		Eventually(checkForUpdates).Should(Equal(map[string]*proto.HostMetadataV4V6Update{update.Hostname: update}))

		// Fill up cache with more updates - remove existing update and add new ones.
		cacheT.OnUpdate(&proto.HostMetadataV4V6Remove{Hostname: update.Hostname})
		update.Hostname = "hn2"
		update.Ipv4Addr = "5.6.7.8"
		update.Labels = map[string]string{"label2": "label2val"}
		cacheT.OnUpdate(update)

		// Ensure it *doesn't* flush the updates.
		Consistently(checkForUpdates).Should(BeNil(), "Cache did not wait for timer before flushing")

		// Pop the fake timer.
		timer.Fire()

		// Ensure it *does* flush the updates.
		Eventually(checkForUpdates).Should(Equal(map[string]*proto.HostMetadataV4V6Update{update.Hostname: update}))
		Expect(droppedC).Should(Receive(Equal(0)))
	})
})
