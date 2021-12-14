package resources_test

import (
	"errors"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	v1 "k8s.io/api/core/v1"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/resources"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

var _ = Describe("ConvertK8sResourceOneToOneAdapter", func() {
	DescribeTable("adapter conversion cases", func(ret1 *model.KVPair, ret2 error, expected1 []*model.KVPair, expected2 error) {
		fun := resources.ConvertK8sResourceOneToOneAdapter(func(r resources.Resource) (*model.KVPair, error) {
			return ret1, ret2
		})

		resources, err := fun(&v1.Pod{})

		matcher1 := BeNil()
		if expected1 != nil {
			matcher1 = Equal(expected1)
		}

		matcher2 := BeNil()
		if expected2 != nil {
			matcher2 = Equal(expected2)
		}

		Expect(resources).Should(matcher1)
		Expect(err).Should(matcher2)
	}, TableEntry{
		Description: "resource not nil error nil returns resource list of one with no error",
		Parameters:  []interface{}{&model.KVPair{}, nil, []*model.KVPair{{}}, nil},
	},
		TableEntry{
			Description: "resource nil error nil returns empty resource list with no error",
			Parameters:  []interface{}{nil, nil, []*model.KVPair(nil), nil},
		},
		TableEntry{
			Description: "resource nil error not nil returns resource empty list with error",
			Parameters:  []interface{}{nil, errors.New(""), []*model.KVPair(nil), errors.New("")},
		},
		TableEntry{
			Description: "resource not nil error not nil returns empty resource list with error",
			Parameters:  []interface{}{&model.KVPair{}, errors.New(""), []*model.KVPair(nil), errors.New("")},
		},
	)
})
