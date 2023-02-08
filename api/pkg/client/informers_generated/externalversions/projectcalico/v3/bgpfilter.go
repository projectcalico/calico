// Copyright (c) 2023 Tigera, Inc. All rights reserved.

// Code generated by informer-gen. DO NOT EDIT.

package v3

import (
	"context"
	time "time"

	projectcalicov3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	clientset "github.com/projectcalico/api/pkg/client/clientset_generated/clientset"
	internalinterfaces "github.com/projectcalico/api/pkg/client/informers_generated/externalversions/internalinterfaces"
	v3 "github.com/projectcalico/api/pkg/client/listers_generated/projectcalico/v3"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	watch "k8s.io/apimachinery/pkg/watch"
	cache "k8s.io/client-go/tools/cache"
)

// BGPFilterInformer provides access to a shared informer and lister for
// BGPFilters.
type BGPFilterInformer interface {
	Informer() cache.SharedIndexInformer
	Lister() v3.BGPFilterLister
}

type bGPFilterInformer struct {
	factory          internalinterfaces.SharedInformerFactory
	tweakListOptions internalinterfaces.TweakListOptionsFunc
}

// NewBGPFilterInformer constructs a new informer for BGPFilter type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewBGPFilterInformer(client clientset.Interface, resyncPeriod time.Duration, indexers cache.Indexers) cache.SharedIndexInformer {
	return NewFilteredBGPFilterInformer(client, resyncPeriod, indexers, nil)
}

// NewFilteredBGPFilterInformer constructs a new informer for BGPFilter type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewFilteredBGPFilterInformer(client clientset.Interface, resyncPeriod time.Duration, indexers cache.Indexers, tweakListOptions internalinterfaces.TweakListOptionsFunc) cache.SharedIndexInformer {
	return cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options v1.ListOptions) (runtime.Object, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.ProjectcalicoV3().BGPFilters().List(context.TODO(), options)
			},
			WatchFunc: func(options v1.ListOptions) (watch.Interface, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.ProjectcalicoV3().BGPFilters().Watch(context.TODO(), options)
			},
		},
		&projectcalicov3.BGPFilter{},
		resyncPeriod,
		indexers,
	)
}

func (f *bGPFilterInformer) defaultInformer(client clientset.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
	return NewFilteredBGPFilterInformer(client, resyncPeriod, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}, f.tweakListOptions)
}

func (f *bGPFilterInformer) Informer() cache.SharedIndexInformer {
	return f.factory.InformerFor(&projectcalicov3.BGPFilter{}, f.defaultInformer)
}

func (f *bGPFilterInformer) Lister() v3.BGPFilterLister {
	return v3.NewBGPFilterLister(f.Informer().GetIndexer())
}
