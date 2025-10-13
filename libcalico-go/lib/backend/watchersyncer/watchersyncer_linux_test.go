package watchersyncer

import (
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"golang.org/x/sys/unix"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/watchersyncer"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
)

var _ = Describe("Test the backend datastore multi-watch syncer, Linux-only tests", func() {

	r1 := watchersyncer.ResourceType{
		ListInterface: model.ResourceListOptions{Kind: apiv3.KindNetworkPolicy},
	}

	It("Should retry the same revision on connection refused", func() {
		// Temporarily reduce the watch and list poll interval to make the tests faster.
		// Since we are timing the processing, we still need the interval to be sufficiently
		// large to make the measurements more accurate.
		defer setWatchIntervals(watchersyncer.MinResyncInterval, watchersyncer.ListRetryInterval, watchersyncer.WatchPollInterval)
		setWatchIntervals(100*time.Millisecond, 500*time.Millisecond, 2000*time.Millisecond)

		rs := newStartedWatcherSyncerTester([]watchersyncer.ResourceType{r1})
		rs.ExpectStatusUpdate(api.WaitForDatastore)

		rs.clientListResponse(r1, emptyList)
		rs.ExpectStatusUpdate(api.ResyncInProgress)
		rs.ExpectStatusUpdate(api.InSync)
		rs.clientWatchResponse(r1, nil)

		By("Sending a bookmark.")
		rs.sendEvent(r1, api.WatchEvent{
			Type: api.WatchBookmark,
			New: &model.KVPair{
				Revision: "bookmarkRevision",
			},
		})
		By("Sending a watch terminated error.")
		rs.sendEvent(r1, api.WatchEvent{
			Type:  api.WatchError,
			Error: dsError,
		})

		for range watchersyncer.MaxErrorsPerRevision * 2 {
			rs.clientWatchResponse(r1, cerrors.ErrorDatastoreError{
				Err: unix.ECONNREFUSED,
			})
			Eventually(rs.allEventsHandled, watchersyncer.MinResyncInterval*2, time.Millisecond).Should(BeTrue())
		}
		rs.clientWatchResponse(r1, nil)
		rs.ExpectStatusUnchanged()
		Eventually(rs.allEventsHandled, watchersyncer.MinResyncInterval*2, time.Millisecond).Should(BeTrue())

		Expect(rs.fc.getLatestWatchRevision()).To(Equal("bookmarkRevision"))
	})

})
