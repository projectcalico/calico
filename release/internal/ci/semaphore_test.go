package ci

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/projectcalico/calico/release/internal/command"
)

func TestFetchImagePromotions(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
			_, err := w.Write([]byte(`[
	{
		"status": "passed",
		"scheduled_pipeline_id": "pipeline-0",
		"name": "Pipeline"
	}
]`))
			if err != nil {
				t.Fatalf("failed to write response: %v", err)
			}
		}))
		defer mockServer.Close()
		promotions, err := fetchImagePromotions(mockServer.URL, "pipeline-12345", "test-token")
		if err != nil {
			t.Fatalf("failed to fetch promotions: %v", err)
		}
		if len(promotions) != 0 {
			t.Fatal("expected promotions to be empty, got:", len(promotions))
		}
	})

	t.Run("duplicate promotions - all failed", func(t *testing.T) {
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
			_, err := w.Write([]byte(`[
	{
		"status": "passed",
		"scheduled_pipeline_id": "pipeline-0",
		"name": "Publish something"
	},
	{
		"status": "failed",
		"scheduled_pipeline_id": "pipeline-1",
		"name": "Publish A images"
	},
	{
		"status": "failed",
		"scheduled_pipeline_id": "pipeline-2",
		"name": "Publish A images"
	}
]`))
			if err != nil {
				t.Fatalf("failed to write response: %v", err)
			}
		}))
		defer mockServer.Close()
		promotions, err := fetchImagePromotions(mockServer.URL, "pipeline-12345", "test-token")
		if err != nil {
			t.Fatalf("failed to fetch promotions: %v", err)
		}
		if len(promotions) != 2 {
			t.Fatal("expected promotions to be 2, got:", len(promotions))
		}
	})

	t.Run("duplicate promotions - all passed", func(t *testing.T) {
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
			_, err := w.Write([]byte(`[
	{
		"status": "passed",
		"scheduled_pipeline_id": "pipeline-0",
		"name": "Publish something"
	},
	{
		"status": "passed",
		"scheduled_pipeline_id": "pipeline-1",
		"name": "Publish A images"
	},
	{
		"status": "passed",
		"scheduled_pipeline_id": "pipeline-2",
		"name": "Publish A images"
	}
]`))
			if err != nil {
				t.Fatalf("failed to write response: %v", err)
			}
		}))
		defer mockServer.Close()
		promotions, err := fetchImagePromotions(mockServer.URL, "pipeline-12345", "test-token")
		if err != nil {
			t.Fatalf("failed to fetch promotions: %v", err)
		}
		if len(promotions) != 2 {
			t.Fatal("expected promotions to be 2, got:", len(promotions))
		}
	})

	t.Run("duplicate promotions - one passed", func(t *testing.T) {
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
			_, err := w.Write([]byte(`[
	{
		"triggered_by": "user",
		"triggered_at": {
				"seconds": 1747260536,
				"nanos": 85599000
		},
		"status": "passed",
		"scheduled_pipeline_id": "pipeline-0",
		"scheduled_at": {
				"seconds": 1747260536,
				"nanos": 739037000
		},
		"override": true,
		"name": "Publish something"
	},
	{
		"triggered_by": "user",
		"triggered_at": {
				"seconds": 1747260536,
				"nanos": 85599000
		},
		"status": "failed",
		"scheduled_pipeline_id": "pipeline-1",
		"scheduled_at": {
				"seconds": 1747260536,
				"nanos": 739037000
		},
		"override": true,
		"name": "Publish A images"
	},
	{
		"triggered_by": "user",
		"triggered_at": {
				"seconds": 1747260536,
				"nanos": 85599000
		},
		"status": "passed",
		"scheduled_pipeline_id": "pipeline-2",
		"scheduled_at": {
				"seconds": 1747260536,
				"nanos": 739037000
		},
		"override": true,
		"name": "Publish A images"
	}
]`))
			if err != nil {
				t.Fatalf("failed to write response: %v", err)
			}
		}))
		defer mockServer.Close()
		promotions, err := fetchImagePromotions(mockServer.URL, "pipeline-12345", "test-token")
		if err != nil {
			t.Fatalf("failed to fetch promotions: %v", err)
		}
		if len(promotions) != 2 {
			t.Fatal("expected promotions to be 2, got:", len(promotions))
		}
	})
}

func TestGetPipelineResult(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
			_, err := w.Write([]byte(`{
	"pipeline": {
		"result": "passed"
	}
}`))
			if err != nil {
				t.Fatalf("failed to write response: %v", err)
			}
		}))
		defer mockServer.Close()
		pipeline, err := getPipelineResult(mockServer.URL, "pipeline-12345", "test-token")
		if err != nil {
			t.Fatalf("failed to get pipeline details: %v", err)
		}
		if pipeline.Result != "passed" {
			t.Fatalf("expected pipeline result to be 'passed', got: %s", pipeline.Result)
		}
	})
}

func TestGetParentPipelineID(t *testing.T) {
	t.Run("no parent pipeline", func(t *testing.T) {
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
			_, err := w.Write([]byte(`{
	"pipeline": {
		"result": "passed"
	}
}`))
			if err != nil {
				t.Fatalf("failed to write response: %v", err)
			}
		}))
		defer mockServer.Close()
		pipeline, err := fetchParentPipelineID(mockServer.URL, "pipeline-1", "test-token")
		if err != nil {
			t.Fatalf("failed to get pipeline details: %v", err)
		}
		if pipeline != "" {
			t.Fatal("expected no parent pipeline ID, got:", pipeline)
		}
	})
	t.Run("parent pipeline", func(t *testing.T) {
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
			_, err := w.Write([]byte(`{
	"pipeline": {
		"result": "passed",
		"promotion_of": "pipeline-12345"
	}
}`))
			if err != nil {
				t.Fatalf("failed to write response: %v", err)
			}
		}))
		defer mockServer.Close()
		pipeline, err := fetchParentPipelineID(mockServer.URL, "pipeline-1", "test-token")
		if err != nil {
			t.Fatalf("failed to get pipeline details: %v", err)
		}
		if pipeline != "pipeline-12345" {
			t.Fatal("expected parent pipeline ID to be 'pipeline-12345', got:", pipeline)
		}
	})
}

func TestRetrieveExpectedPromotions(t *testing.T) {
	t.Run("repo root", func(t *testing.T) {
		repoRootDir, err := command.GitDir()
		if err != nil {
			t.Fatalf("failed to get repo root dir: %v", err)
		}
		expectedPromotions, err := retrieveExpectedPromotions(repoRootDir)
		if err != nil {
			t.Fatalf("failed to retrieve expected promotions: %v", err)
		}
		if len(expectedPromotions) == 0 {
			t.Fatal("expected promotions should not be empty")
		}
	})

	t.Run("wrong dir", func(t *testing.T) {
		_, err := retrieveExpectedPromotions(t.TempDir())
		if err == nil {
			t.Fatal("expected an error when retrieving promotions, but got none")
		}
	})
}

func TestGetDistintImagePromotions(t *testing.T) {
	t.Run("empty promotions", func(t *testing.T) {
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
			_, err := w.Write([]byte(`[]`))
			if err != nil {
				t.Fatalf("failed to write response: %v", err)
			}
		}))
		defer mockServer.Close()
		promotions := []promotion{}
		distinctPromotions, err := getDistinctImagePromotions(promotions, mockServer.URL, "test-token")
		if err != nil {
			t.Fatal("failed to get distinct promotions:", err)
		}
		if len(distinctPromotions) != 0 {
			t.Fatal("expected distinct promotions to be empty, got:", len(distinctPromotions))
		}
	})

	t.Run("failed promotions", func(t *testing.T) {
		calls := 0
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
			calls++
			_, err := w.Write([]byte(`{
	"pipeline": {
		"result": "failed",
		"promotion_of": "pipeline-12345"
	}
}`))
			if err != nil {
				t.Fatalf("failed to write response: %v", err)
			}
		}))
		defer mockServer.Close()
		promotions := []promotion{
			{
				Status:     "failed",
				PipelineID: "pipeline-1",
				Name:       "Publish A images",
			},
			{
				Status:     "passed",
				PipelineID: "pipeline-2",
				Name:       "Publish B images",
			},
		}
		distinctPromotions, err := getDistinctImagePromotions(promotions, mockServer.URL, "test-token")
		if err != nil {
			t.Fatal("failed to get distinct promotions:", err)
		}
		if len(distinctPromotions) != 2 {
			t.Fatal("expected distinct promotions to be 2, got:", len(distinctPromotions))
		}
		if calls != 1 {
			t.Fatalf("expected getPipelineResult to be called once, got: %d", calls)
		}
	})

	t.Run("duplicate promotions", func(t *testing.T) {
		calls := 0
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
			calls++
			_, err := w.Write([]byte(`{
	"pipeline": {
		"result": "passed",
		"promotion_of": "pipeline-12345"
	}
}`))
			if err != nil {
				t.Fatalf("failed to write response: %v", err)
			}
		}))
		defer mockServer.Close()
		promotions := []promotion{
			{
				Status:     "passed",
				PipelineID: "pipeline-1",
				Name:       "Publish A images",
			},
			{
				Status:     "passed",
				PipelineID: "pipeline-2",
				Name:       "Publish B images",
			},
			{
				Status:     "passed",
				PipelineID: "pipeline-3",
				Name:       "Publish B images",
			},
		}
		distinctPromotions, err := getDistinctImagePromotions(promotions, mockServer.URL, "test-token")
		if err != nil {
			t.Fatal("failed to get distinct promotions:", err)
		}
		if len(distinctPromotions) != 2 {
			t.Fatal("expected distinct promotions to be 2, got:", len(distinctPromotions))
		}
		if calls != 2 {
			t.Fatalf("expected getPipelineResult to be called twice, got: %d", calls)
		}
		for _, promotion := range distinctPromotions {
			if promotion.PipelineID == "pipeline-3" {
				t.Fatal("expected pipeline-3 to be filtered out, but it was not")
			}
		}
	})

	t.Run("duplicate promotions w/ one failed promotion", func(t *testing.T) {
		calls := 0
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
			calls++
			_, err := w.Write([]byte(`{
	"pipeline": {
		"result": "passed",
		"promotion_of": "pipeline-12345"
	}
}`))
			if err != nil {
				t.Fatalf("failed to write response: %v", err)
			}
		}))
		defer mockServer.Close()
		promotions := []promotion{
			{
				Status:     "passed",
				PipelineID: "pipeline-1",
				Name:       "Publish A images",
			},
			{
				Status:     "passed",
				PipelineID: "pipeline-2",
				Name:       "Publish B images",
			},
			{
				Status:     "failed",
				PipelineID: "pipeline-3",
				Name:       "Publish B images",
			},
		}
		distinctPromotions, err := getDistinctImagePromotions(promotions, mockServer.URL, "test-token")
		if err != nil {
			t.Fatal("failed to get distinct promotions:", err)
		}
		if len(distinctPromotions) != 2 {
			t.Fatal("expected distinct promotions to be 2, got:", len(distinctPromotions))
		}
		if calls != 2 {
			t.Fatalf("expected getPipelineResult to be called twice, got: %d", calls)
		}
		for _, promotion := range distinctPromotions {
			if promotion.PipelineID == "pipeline-3" {
				t.Fatal("expected pipeline-3 to be filtered out, but it was not")
			}
		}
	})

	t.Run("duplicate promotions passed promotion last", func(t *testing.T) {
		calls := 0
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
			calls++
			_, err := w.Write([]byte(`{
	"pipeline": {
		"result": "passed",
		"promotion_of": "pipeline-12345"
	}
}`))
			if err != nil {
				t.Fatalf("failed to write response: %v", err)
			}
		}))
		defer mockServer.Close()
		promotions := []promotion{
			{
				Status:     "passed",
				PipelineID: "pipeline-1",
				Name:       "Publish A images",
			},
			{
				Status:     "failed",
				PipelineID: "pipeline-2",
				Name:       "Publish B images",
			},
			{
				Status:     "passed",
				PipelineID: "pipeline-3",
				Name:       "Publish B images",
			},
		}
		distinctPromotions, err := getDistinctImagePromotions(promotions, mockServer.URL, "test-token")
		if err != nil {
			t.Fatal("failed to get distinct promotions:", err)
		}
		if len(distinctPromotions) != 2 {
			t.Fatal("expected distinct promotions to be 2, got:", len(distinctPromotions))
		}
		if calls != 2 {
			t.Fatalf("expected getPipelineResult to be called twice, got: %d", calls)
		}
		for _, promotion := range distinctPromotions {
			if promotion.PipelineID == "pipeline-2" {
				t.Fatal("expected pipeline-2 to be filtered out, but it was not")
			}
		}
	})
}
