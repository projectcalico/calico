package fv_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	. "github.com/onsi/gomega"

	. "github.com/projectcalico/calico/calicoctl/tests/fv/utils"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
)

func TestOptimize_SplitsGlobalNetworkPolicy_OnIngressSelectors(t *testing.T) {
	RunDatastoreTest(t, func(t *testing.T, kdd bool, _ clientv3.Interface) {
		RegisterTestingT(t)

		// Write a GlobalNetworkPolicy that will be split into two ingress policies.
		dir := t.TempDir()
		yaml := `
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: gnp-split
spec:
  selector: all()
  types:
  - Ingress
  ingress:
  - action: Allow
    destination:
      selector: "app == 'a'"
  - action: Allow
    destination:
      selector: "app == 'b'"
`
		f := filepath.Join(dir, "gnp.yaml")
		if err := os.WriteFile(f, []byte(yaml), 0600); err != nil {
			t.Fatalf("failed to write temp YAML: %v", err)
		}

		out := Calicoctl(kdd, "optimize", "-f", f)

		// Expect two split policies with suffixed names.
		Expect(out).To(ContainSubstring("name: gnp-split-i-0"))
		Expect(out).To(ContainSubstring("name: gnp-split-i-1"))
		// Expect both to be GlobalNetworkPolicy items.
		Expect(strings.Count(out, "kind: GlobalNetworkPolicy")).To(Equal(2))
		// Each should be ingress-only.
		Expect(strings.Count(out, "types:\n  - Ingress")).To(Equal(2))
	})
}
