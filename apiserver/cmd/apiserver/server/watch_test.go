package server

import (
	"testing"

	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestFindFirstDifferingKey(t *testing.T) {
	RegisterTestingT(t)

	cfgmap1 := corev1.ConfigMap{
		ObjectMeta: v1.ObjectMeta{
			ResourceVersion: "1",
		},
		Data: map[string]string{
			"haystack0": "haystack",
			"haystack1": "haystack",
			"haystack2": "haystack",
		},
	}

	cfgmap2 := corev1.ConfigMap{
		ObjectMeta: v1.ObjectMeta{
			ResourceVersion: "2",
		},
		Data: map[string]string{
			"haystack0": "haystack",
			"haystack1": "haystack",
			"haystack2": "haystack",
		},
	}

	Expect(findFirstDifferingKey(&cfgmap1, &cfgmap2)).To(Equal(""))
	Expect(findFirstDifferingKey(&cfgmap2, &cfgmap1)).To(Equal(""))

	cfgmap2.Data["needle"] = "found-you"

	Expect(findFirstDifferingKey(&cfgmap1, &cfgmap2)).To(Equal("needle"))
	Expect(findFirstDifferingKey(&cfgmap2, &cfgmap1)).To(Equal("needle"))
	cfgmap1.Data["needle"] = ""
	Expect(findFirstDifferingKey(&cfgmap1, &cfgmap2)).To(Equal("needle"))
	Expect(findFirstDifferingKey(&cfgmap2, &cfgmap1)).To(Equal("needle"))
}
