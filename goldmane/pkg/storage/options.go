// Copyright (c) 2025 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package storage

import (
	"time"

	"github.com/projectcalico/calico/lib/std/log"
)

type BucketRingOption func(*BucketRing)

func WithPushAfter(n int) BucketRingOption {
	return func(r *BucketRing) {
		r.pushAfter = n
	}
}

func WithBucketsToAggregate(n int) BucketRingOption {
	return func(r *BucketRing) {
		log.WithField("bucketsToAggregate", n).Debug("Setting buckets to aggregate")
		r.bucketsToAggregate = n
	}
}

func WithStreamReceiver(sm Receiver) BucketRingOption {
	return func(r *BucketRing) {
		log.WithField("streamReceiver", sm).Debug("Setting stream receiver")
		r.streams = sm
	}
}

func WithNowFunc(nowFunc func() time.Time) BucketRingOption {
	return func(r *BucketRing) {
		log.WithField("nowFunc", nowFunc).Debug("Setting now function")
		r.nowFunc = nowFunc
	}
}
