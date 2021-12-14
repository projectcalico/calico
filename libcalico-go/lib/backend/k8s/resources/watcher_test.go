// Copyright (c) 2020 Tigera, Inc. All rights reserved.

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

package resources

import (
	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
	kwatch "k8s.io/apimachinery/pkg/watch"
)

var _ = Describe("Resources watcher ", func() {
	Describe("convertEvent tests", func() {
		var kwc k8sWatcherConverter

		BeforeEach(func() {
			kwc = k8sWatcherConverter{
				logCxt: log.WithField("test", "test"),
			}
			kwc.converter = func(r Resource) ([]*model.KVPair, error) {
				return nil, nil
			}
		})

		It("should return error WatchEvent when the kwatch event is error", func() {
			events := kwc.convertEvent(kwatch.Event{
				Type: kwatch.Error,
			})
			Expect(events).To(HaveLen(1))
			Expect(events[0].Type).To(Equal(api.WatchError))
		})

		It("should return error WatchEvent with unexpected kwatch event type", func() {
			events := kwc.convertEvent(kwatch.Event{
				Type: kwatch.Bookmark,
			})
			Expect(events).To(HaveLen(1))
			Expect(events[0].Type).To(Equal(api.WatchError))
		})

		It("should return add events with kwatch Added event type", func() {
			kwc.converter = func(r Resource) ([]*model.KVPair, error) {
				return []*model.KVPair{
					{
						Key: model.ResourceKey{Name: "kns.copied", Kind: apiv3.KindProfile},
						Value: &apiv3.Profile{
							Spec: apiv3.ProfileSpec{
								LabelsToApply: map[string]string{
									"pcns.projectcalico.org/name": "copied",
								},
							},
						},
					},
					{
						Key: model.ResourceKey{Name: "kns.again", Kind: apiv3.KindProfile},
						Value: &apiv3.Profile{
							Spec: apiv3.ProfileSpec{
								LabelsToApply: map[string]string{
									"pcns.projectcalico.org/name": "again",
								},
							},
						},
					},
				}, nil
			}
			events := kwc.convertEvent(kwatch.Event{
				Type:   kwatch.Added,
				Object: &apiv3.Profile{},
			})
			Expect(events).To(HaveLen(2))
			Expect(events).To(ConsistOf(&api.WatchEvent{
				Type: api.WatchAdded,
				New: &model.KVPair{
					Key: model.ResourceKey{Name: "kns.copied", Kind: apiv3.KindProfile},
					Value: &apiv3.Profile{
						Spec: apiv3.ProfileSpec{
							LabelsToApply: map[string]string{
								"pcns.projectcalico.org/name": "copied",
							},
						},
					},
				},
			},
				&api.WatchEvent{
					Type: api.WatchAdded,
					New: &model.KVPair{
						Key: model.ResourceKey{Name: "kns.again", Kind: apiv3.KindProfile},
						Value: &apiv3.Profile{
							Spec: apiv3.ProfileSpec{
								LabelsToApply: map[string]string{
									"pcns.projectcalico.org/name": "again",
								},
							},
						},
					},
				}))
		})

		It("should return delete events with kwatch Delete event type", func() {
			kwc.converter = func(r Resource) ([]*model.KVPair, error) {
				return []*model.KVPair{
					{
						Key: model.ResourceKey{Name: "kns.copied", Kind: apiv3.KindProfile},
						Value: &apiv3.Profile{
							Spec: apiv3.ProfileSpec{
								LabelsToApply: map[string]string{
									"pcns.projectcalico.org/name": "copied",
								},
							},
						},
					},
					{
						Key: model.ResourceKey{Name: "kns.again", Kind: apiv3.KindProfile},
						Value: &apiv3.Profile{
							Spec: apiv3.ProfileSpec{
								LabelsToApply: map[string]string{
									"pcns.projectcalico.org/name": "again",
								},
							},
						},
					},
				}, nil
			}
			events := kwc.convertEvent(kwatch.Event{
				Type:   kwatch.Deleted,
				Object: &apiv3.Profile{},
			})
			Expect(events).To(HaveLen(2))
			Expect(events).To(ConsistOf(
				&api.WatchEvent{
					Type: api.WatchDeleted,
					Old: &model.KVPair{
						Key: model.ResourceKey{Name: "kns.copied", Kind: apiv3.KindProfile},
						Value: &apiv3.Profile{
							Spec: apiv3.ProfileSpec{
								LabelsToApply: map[string]string{
									"pcns.projectcalico.org/name": "copied",
								},
							},
						},
					},
				},
				&api.WatchEvent{
					Type: api.WatchDeleted,
					Old: &model.KVPair{
						Key: model.ResourceKey{Name: "kns.again", Kind: apiv3.KindProfile},
						Value: &apiv3.Profile{
							Spec: apiv3.ProfileSpec{
								LabelsToApply: map[string]string{
									"pcns.projectcalico.org/name": "again",
								},
							},
						},
					},
				}))
		})

		It("should return modified events with kwatch modified event type", func() {
			kwc.converter = func(r Resource) ([]*model.KVPair, error) {
				return []*model.KVPair{
					{
						Key: model.ResourceKey{Name: "kns.copied", Kind: apiv3.KindProfile},
						Value: &apiv3.Profile{
							Spec: apiv3.ProfileSpec{
								LabelsToApply: map[string]string{
									"pcns.projectcalico.org/name": "copied",
								},
							},
						},
					},
					{
						Key: model.ResourceKey{Name: "kns.again", Kind: apiv3.KindProfile},
						Value: &apiv3.Profile{
							Spec: apiv3.ProfileSpec{
								LabelsToApply: map[string]string{
									"pcns.projectcalico.org/name": "again",
								},
							},
						},
					},
				}, nil
			}
			events := kwc.convertEvent(kwatch.Event{
				Type:   kwatch.Modified,
				Object: &apiv3.Profile{},
			})
			Expect(events).To(HaveLen(2))
			Expect(events).To(ConsistOf(&api.WatchEvent{
				Type: api.WatchModified,
				New: &model.KVPair{
					Key: model.ResourceKey{Name: "kns.copied", Kind: apiv3.KindProfile},
					Value: &apiv3.Profile{
						Spec: apiv3.ProfileSpec{
							LabelsToApply: map[string]string{
								"pcns.projectcalico.org/name": "copied",
							},
						},
					},
				},
			},
				&api.WatchEvent{
					Type: api.WatchModified,
					New: &model.KVPair{
						Key: model.ResourceKey{Name: "kns.again", Kind: apiv3.KindProfile},
						Value: &apiv3.Profile{
							Spec: apiv3.ProfileSpec{
								LabelsToApply: map[string]string{
									"pcns.projectcalico.org/name": "again",
								},
							},
						},
					},
				}))
		})
	})
})
