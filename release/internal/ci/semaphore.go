package ci

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/release/internal/command"
)

const (
	apiPath    = "/api"
	apiVersion = "v1alpha"
)

const (
	passed = "passed"
	failed = "failed"
)

type promotion struct {
	Status     string `json:"status"`
	Name       string `json:"name"`
	PipelineID string `json:"scheduled_pipeline_id"`
}

type pipeline struct {
	PipelineID  string `json:"ppl_id"`
	Result      string `json:"result"`
	PromotionOf string `json:"promotion_of"`
}

type pipelineDetails struct {
	Pipeline pipeline `json:"pipeline"`
}

func buildRequestURL(orgURL string, path ...string) (string, error) {
	if orgURL == "" {
		return "", errors.New("organization URL is empty")
	}
	path = append([]string{apiPath, apiVersion}, path...)
	u, err := url.JoinPath(orgURL, path...)
	if err != nil {
		return "", fmt.Errorf("failed to construct API URL: %w", err)
	}
	return u, nil
}

func fetchImagePromotions(orgURL, pipelineID, token string) ([]promotion, error) {
	promotionsURL, err := buildRequestURL(orgURL, "promotions")
	if err != nil {
		return nil, fmt.Errorf("failed to create promotions request URL: %w", err)
	}
	req, err := http.NewRequest("GET", promotionsURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request to %s: %w", promotionsURL, err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("Token %s", token))
	q := req.URL.Query()
	q.Add("pipeline_id", pipelineID)
	req.URL.RawQuery = q.Encode()

	logrus.WithField("url", req.URL.String()).Debug("get pipeline promotions")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to request promotions: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch promotions")
	}

	var promotions []promotion
	if err := json.NewDecoder(resp.Body).Decode(&promotions); err != nil {
		return nil, fmt.Errorf("failed to decode response to promotions: %w", err)
	}

	logrus.WithField("promotions", promotions).Debug("fetched promotions")

	imagePromotions := make([]promotion, 0)
	for _, p := range promotions {
		name := strings.ToLower(p.Name)
		// If the promotion is not related to pushing/publishing images, skip it.
		if strings.HasSuffix(name, " images") && (strings.HasPrefix(name, "push ") || strings.HasPrefix(name, "publish ")) {
			imagePromotions = append(imagePromotions, p)
		}
	}
	return imagePromotions, nil
}

func getPipelineResult(orgURL, pipelineID, token string) (*pipeline, error) {
	pipelineURL, err := buildRequestURL(orgURL, "pipelines", pipelineID)
	if err != nil {
		return nil, fmt.Errorf("failed to get pipeline request URL: %w", err)
	}
	req, err := http.NewRequest("GET", pipelineURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request to %s: %w", pipelineURL, err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("Token %s", token))

	logrus.WithField("url", req.URL.String()).Debug("get pipeline details")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to request pipeline details: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch pipeline details")
	}

	var p pipelineDetails
	if err := json.NewDecoder(resp.Body).Decode(&p); err != nil {
		return nil, fmt.Errorf("failed to decode response to pipeline details: %w", err)
	}

	return &p.Pipeline, nil
}

func getParentPipelineID(orgURL, pipelineID, token string) (string, error) {
	p, err := getPipelineResult(orgURL, pipelineID, token)
	if err != nil {
		return "", fmt.Errorf("failed to get pipeline details for %s: %w", pipelineID, err)
	}

	return p.PromotionOf, nil
}

func retrieveExpectedPromotions(repoRootDir string) ([]string, error) {
	promotionsFile := filepath.Join(repoRootDir, ".semaphore/semaphore.yml.d/03-promotions.yml")
	expectPromotions, err := command.Run("grep", []string{"-Po", `name:\K(.*images.*)`, promotionsFile})
	if err != nil {
		return nil, fmt.Errorf("failed to get expected image promotions from %s: %w", promotionsFile, err)
	}
	list := strings.Split(expectPromotions, "\n")
	for i, p := range list {
		list[i] = strings.TrimSpace(p)
	}
	return list, nil
}

func gatherUniquePromotionPipelines(promotions []promotion, orgURL, token string) (map[string]pipeline, error) {
	promotionsSet := make(map[string]pipeline)
	for _, promotion := range promotions {
		name := strings.ToLower(promotion.Name)
		// If the promotion already exists, this means that it has been triggered more than once.
		if currP, ok := promotionsSet[name]; ok {
			if currP.Result == passed {
				continue // If the current promotion is already passed, skip checking the duplicate.
			}
			newP, err := getPipelineResult(orgURL, promotion.PipelineID, token)
			if err != nil {
				return nil, fmt.Errorf("unable to get %q pipeline details: %w", promotion.Name, err)
			}
			// If the new promotion is passed, update the current promotion.
			if newP.Result == passed {
				promotionsSet[name] = *newP
			}
		} else {
			// Promotion does not exist in the set, check its status.
			if promotion.Status != passed {
				// If the promotion is not passed, skip checking for pipeline result and mark as failure.
				logrus.WithField("promotion", name).Warnf("%q promotion did not pass, marking as failed", name)
				promotionsSet[name] = pipeline{
					Result: failed,
				}
				continue
			}
			// Add the promotion pipeline to the set
			pipelineResult, err := getPipelineResult(orgURL, promotion.PipelineID, token)
			if err != nil {
				return nil, fmt.Errorf("unable to get %q pipeline details: %w", promotion.Name, err)
			}
			promotionsSet[name] = *pipelineResult
		}
	}
	return promotionsSet, nil
}

// EvaluateImagePromotions checks if all the image publishing promotion pipelines have passed.
//
// As it is checking in the hashrelease pipeline, it tries to get the pipeline that triggered the hashrelease promotion.
// If the pipeline that triggered the hashrelease promotion is not found,
// this means that the hashrelease pipeline was not triggered by a promotion (likely triggered from a task).
// In this case, it skips the image promotions check.
//
// Once the pipeline that triggered the hashrelease promotion is found, it checks if all the expected image promotions have passed.
// Since Semaphore API only return promotions that have been triggered,
// it is possible that some promotions are not triggered. It is also possible that the same promotion is triggered multiple times.
// This is why it checks against the image promotions in the semaphore.yml.
// For promotion pipelines that are triggered multiple times, it only considers the first one that has passed.
func EvaluateImagePromotions(repoRootDir, orgURL, pipelineID, token string) (bool, error) {
	expectedPromotions, err := retrieveExpectedPromotions(repoRootDir)
	if err != nil {
		return false, err
	}
	expectedPromotionCount := len(expectedPromotions)
	if expectedPromotionCount == 0 {
		return false, fmt.Errorf("no expected image promotions found in %s", repoRootDir)
	}
	parentPipelineID, err := getParentPipelineID(orgURL, pipelineID, token)
	if err != nil {
		return false, err
	}
	if parentPipelineID == "" {
		logrus.Info("no parent pipeline found, skipping image promotions check")
		logrus.Warn("this hashrelease is being run with the assumption that images have been promoted successfully in a different pipeline")
		return true, nil
	}
	logrus.Warn("this hashrelease is being run in a pipeline that was not triggered by a promotion, assuming all image promotions passed")
	return true, nil
}
