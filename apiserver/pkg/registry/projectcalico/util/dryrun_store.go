// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package util

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/registry/generic/registry"
	"k8s.io/apiserver/pkg/registry/rest"
	storeerr "k8s.io/apiserver/pkg/storage/errors"
	"k8s.io/apiserver/pkg/util/dryrun"
)

// DryRunWriter is implemented by storage that can send a write to the Calico
// datastore as a dry run, validated in full but not persisted.
type DryRunWriter interface {
	DryRunCreate(ctx context.Context, key string, obj runtime.Object) error
	DryRunUpdate(ctx context.Context, key string, obj, old runtime.Object) error
}

// Store is the generic registry store, except that a server-side dry run of a create
// or update is also sent to the Calico datastore as a dry run. The generic store
// never calls its storage for a dry run, which skips the Calico client's validation
// and the backing CRD's schema, CEL rules and admission that a real write gets.
type Store struct {
	*registry.Store
}

// NewStore wraps s so its dry runs are validated by the Calico datastore.
func NewStore(s *registry.Store) *Store {
	return &Store{Store: s}
}

// Create creates obj, adding a datastore dry run to the validation of a dry-run request.
func (s *Store) Create(ctx context.Context, obj runtime.Object, createValidation rest.ValidateObjectFunc, options *metav1.CreateOptions) (runtime.Object, error) {
	if options != nil && dryrun.IsDryRun(options.DryRun) {
		createValidation = s.withDryRunCreate(createValidation)
	}
	return s.Store.Create(ctx, obj, createValidation, options)
}

// Update updates the named object, adding a datastore dry run to the validation of a
// dry-run request. Create validation is wrapped too, for an update that creates.
func (s *Store) Update(
	ctx context.Context,
	name string,
	objInfo rest.UpdatedObjectInfo,
	createValidation rest.ValidateObjectFunc,
	updateValidation rest.ValidateObjectUpdateFunc,
	forceAllowCreate bool,
	options *metav1.UpdateOptions,
) (runtime.Object, bool, error) {
	if options != nil && dryrun.IsDryRun(options.DryRun) {
		createValidation = s.withDryRunCreate(createValidation)
		updateValidation = s.withDryRunUpdate(updateValidation)
	}
	return s.Store.Update(ctx, name, objInfo, createValidation, updateValidation, forceAllowCreate, options)
}

// withDryRunCreate runs next, then sends the object to the datastore as a dry-run create.
func (s *Store) withDryRunCreate(next rest.ValidateObjectFunc) rest.ValidateObjectFunc {
	return func(ctx context.Context, obj runtime.Object) error {
		if next != nil {
			if err := next(ctx, obj); err != nil {
				return err
			}
		}
		w, ok := s.Storage.Storage.(DryRunWriter)
		if !ok {
			return nil
		}
		name, key, err := s.nameAndKey(ctx, obj)
		if err != nil {
			return err
		}
		err = w.DryRunCreate(ctx, key, obj.DeepCopyObject())
		return storeerr.InterpretCreateError(err, s.DefaultQualifiedResource, name)
	}
}

// withDryRunUpdate runs next, then sends the object to the datastore as a dry-run update.
func (s *Store) withDryRunUpdate(next rest.ValidateObjectUpdateFunc) rest.ValidateObjectUpdateFunc {
	return func(ctx context.Context, obj, old runtime.Object) error {
		if next != nil {
			if err := next(ctx, obj, old); err != nil {
				return err
			}
		}
		w, ok := s.Storage.Storage.(DryRunWriter)
		if !ok {
			return nil
		}
		name, key, err := s.nameAndKey(ctx, obj)
		if err != nil {
			return err
		}
		err = w.DryRunUpdate(ctx, key, obj.DeepCopyObject(), old)
		return storeerr.InterpretUpdateError(err, s.DefaultQualifiedResource, name)
	}
}

// nameAndKey returns obj's name and its storage key.
func (s *Store) nameAndKey(ctx context.Context, obj runtime.Object) (string, string, error) {
	name, err := s.ObjectNameFunc(obj)
	if err != nil {
		return "", "", err
	}
	key, err := s.KeyFunc(ctx, name)
	if err != nil {
		return "", "", err
	}
	return name, key, nil
}
