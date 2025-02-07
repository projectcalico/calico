package ci

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/release/internal/command"
)

const passed = "passed"

type promotion struct {
	Status     string `json:"status"`
	Name       string `json:"name"`
	PipelineID string `json:"scheduled_pipeline_id"`
}

type pipeline struct {
	Result string `json:"result"`
}

func apiURL(orgURL, path string) string {
	orgURL = strings.TrimPrefix(orgURL, "/")
	path = strings.TrimSuffix(path, "/")
	return fmt.Sprintf("%s/api/v1alpha/%s", orgURL, path)
}

func fetchPromotions(orgURL, pipelineID, token string) ([]promotion, error) {
	url := apiURL(orgURL, "/promotions")
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create %s request: %s", url, err.Error())
	}
	req.Header.Set("Authorization", fmt.Sprintf("Token %s", token))
	q := req.URL.Query()
	q.Add("pipeline_id", pipelineID)
	req.URL.RawQuery = q.Encode()

	logrus.WithField("url", req.URL.String()).Debug("get pipeline promotions")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to request promotions: %s", err.Error())
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch promotions")
	}

	var promotions []promotion
	if err := json.NewDecoder(resp.Body).Decode(&promotions); err != nil {
		return nil, fmt.Errorf("failed to parse promotions: %s", err.Error())
	}

	var imagesPromotions []promotion
	for _, p := range promotions {
		if strings.HasPrefix(strings.ToLower(p.Name), "push ") {
			imagesPromotions = append(imagesPromotions, p)
		}
	}
	return imagesPromotions, nil
}

func getPipelineResult(orgURL, pipelineID, token string) (*pipeline, error) {
	url := apiURL(orgURL, fmt.Sprintf("/pipeline/%s", pipelineID))
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create %s request: %s", url, err.Error())
	}
	req.Header.Set("Authorization", fmt.Sprintf("Token %s", token))

	logrus.WithField("url", req.URL.String()).Debug("get pipeline details")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to request pipeline details: %s", err.Error())
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch pipeline details")
	}

	var p pipeline
	if err := json.NewDecoder(resp.Body).Decode(&p); err != nil {
		return nil, fmt.Errorf("failed to parse pipeline: %s", err.Error())
	}

	return &p, err
}

func ImagePromotionsDone(repoRootDir, orgURL, pipelineID, token string) (bool, error) {
	expectPromotionCountStr, err := command.Run("grep", []string{"-c", `"name: Push "`, fmt.Sprintf("%s/.semaphore/semaphore.yml.d/03-promotions.yml")})
	if err != nil {
		return false, fmt.Errorf("failed to get expected image promotions")
	}
	expectedPromotionCount, err := strconv.Atoi(expectPromotionCountStr)
	if err != nil {
		return false, fmt.Errorf("unable to convert expected promotions to int")
	}
	promotions, err := fetchPromotions(orgURL, pipelineID, token)
	if err != nil {
		return false, err
	}
	promotionsCount := len(promotions)
	if promotionsCount < expectedPromotionCount {
		return false, fmt.Errorf("number of promotions do not match: expected %d, got %d", expectedPromotionCount, promotionsCount)
	}
	for _, promotion := range promotions {
		if promotion.Status != passed {
			logrus.WithField("promotion", promotion.Name).Error("triggering promotion failed")
			return false, fmt.Errorf("triggering %q promotion failed, cannot check pipeline result", promotion.Name)
		}
		pipeline, err := getPipelineResult(orgURL, promotion.PipelineID, token)
		if err != nil {
			return false, fmt.Errorf("unable to get %q pipeline details", promotion.Name)
		}
		if pipeline.Result != passed {
			logrus.WithField("promotion", promotion.Name).Error("promotion failed")
			return false, fmt.Errorf("%q promotion failed", promotion.Name)
		}
	}
	return true, nil
}
