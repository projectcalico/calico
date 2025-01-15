package v1

import "time"

const (
	FlowsPath       = sep + "flows"
	FlowsStreamPath = FlowsPath + sep + "_stream"
)

type listFlowsSortBy string

const (
	listFlowsSortByDest listFlowsSortBy = "dest"
)

type ListFlowsParams struct {
	StartTimeGt time.Time       `urlParam:"startTimeGt"`
	StartTimeLt time.Time       `urlParam:"startTimeLt"`
	SortBy      listFlowsSortBy `urlParam:"sortBy"`

	Filters FlowsFilters
}

type StreamFlowsParams struct {
	Filters FlowsFilters
}

type FlowsFilters struct {
}

type FlowResponse struct {
	StartTime       time.Time `json:"start_time"`
	EndTime         time.Time `json:"end_time"`
	Action          string    `json:"action"`
	SourceName      string    `json:"source_name"`
	SourceNamespace string    `json:"source_namespace"`
	SourceLabels    string    `json:"source_labels"`
	DestName        string    `json:"dest_name"`
	DestNamespace   string    `json:"dest_namespace"`
	DestLabels      string    `json:"dest_labels"`
	Protocol        string    `json:"protocol"`
	DestPort        int64     `json:"dest_port"`
	Reporter        string    `json:"reporter"`
	PacketsIn       int64     `json:"packets_in"`
	PacketsOut      int64     `json:"packets_out"`
	BytesIn         int64     `json:"bytes_in"`
	BytesOut        int64     `json:"bytes_out"`
}
