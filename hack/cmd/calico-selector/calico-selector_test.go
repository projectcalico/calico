package main

import (
	"bytes"
	"testing"

	"github.com/projectcalico/calico/libcalico-go/lib/selector"
)

const selStr = `a == 'b' && c != 'd' && q in  {'1', '2'} && z not in {'6', '7'} && b startswith 'g' && b endswith 'h' && w contains 'u' && has(o) && !has(r) || global() || all()`
const expectedTree = `OR
+-AND
| +-(a == "b")
| +-(c != "d")
| +-(q in {1,2})
| +-(z not in {6,7})
| +-(b starts with "g")
| +-(b ends with "h")
| +-(w contains "u")
| +-has(o)
| +-NOT
|   +-has(r)
+-global()
+-all()
`

func TestPrintTree(t *testing.T) {
	var buf bytes.Buffer
	sel, err := selector.Parse(selStr)
	if err != nil {
		t.Fatal(err)
	}
	printTree(&buf, "", sel.Root(), false)
	if buf.String() != expectedTree {
		t.Errorf("Unexpected output, got:\n%s\n\nExpected:\n%s", buf.String(), expectedTree)
	}
}
