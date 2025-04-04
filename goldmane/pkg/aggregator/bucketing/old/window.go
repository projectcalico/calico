package old

import (
	"slices"
	"strings"
	"unique"
)

type Window struct {
	SourceLabels            unique.Handle[string]
	DestLabels              unique.Handle[string]
	PacketsIn               int64
	PacketsOut              int64
	BytesIn                 int64
	BytesOut                int64
	NumConnectionsStarted   int64
	NumConnectionsCompleted int64
	NumConnectionsLive      int64
}

func (w Window) Merge(other Window) Window {
	w.PacketsIn += other.PacketsIn
	w.PacketsOut += other.PacketsOut
	w.BytesIn += other.BytesIn
	w.BytesOut += other.BytesOut
	w.NumConnectionsStarted += other.NumConnectionsStarted
	w.NumConnectionsCompleted += other.NumConnectionsCompleted
	w.NumConnectionsLive += other.NumConnectionsLive
	w.SourceLabels = intersection(w.SourceLabels, other.SourceLabels)
	w.DestLabels = intersection(w.DestLabels, other.DestLabels)

	return w
}

// intersection returns the intersection of two slices of strings. i.e., all the values that
// exist in both input slices.
func intersection(a unique.Handle[string], b unique.Handle[string]) unique.Handle[string] {
	common := make([]string, 0)
	av := strings.Split(a.Value(), ",")
	bv := strings.Split(b.Value(), ",")
	for _, v := range av {
		if slices.Contains(bv, v) {
			common = append(common, v)
		}
	}
	return unique.Make(strings.Join(common, ","))
}
