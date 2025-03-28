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

package bucketing

type BucketRingOption func(*BucketRing)

func WithPushAfter(n int) BucketRingOption {
	return func(r *BucketRing) {
		r.pushAfter = n
	}
}

func WithBucketsToAggregate(n int) BucketRingOption {
	return func(r *BucketRing) {
		r.bucketsToAggregate = n
	}
}

func WithLookup(lookup lookupFn) BucketRingOption {
	return func(r *BucketRing) {
		r.lookupFlow = lookup
	}
}

func WithStreamReceiver(sm StreamReceiver) BucketRingOption {
	return func(r *BucketRing) {
		r.streams = sm
	}
}
