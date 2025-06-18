package ci

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
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
	Result      string `json:"result"`
	PromotionOf string `json:"promotion_of"`
}

type pipelineDetails struct {
	Pipeline pipeline `json:"pipeline"`
}

func apiURL(orgURL, path string) string {
	orgURL = strings.TrimPrefix(orgURL, "/")
	path = strings.TrimSuffix(path, "/")
	return fmt.Sprintf("%s/api/v1alpha/%s", orgURL, path)
}

func fetchImagePromotions(orgURL, pipelineID, token string) ([]promotion, error) {
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

	imagesPromotionsMap := make(map[string]promotion)
	for _, p := range promotions {
		if (strings.HasPrefix(strings.ToLower(p.Name), "push ") || strings.HasPrefix(strings.ToLower(p.Name), "publish ")) &&
			strings.HasPrefix(strings.ToLower(p.Name), "push ") {
			if currentP, ok := imagesPromotionsMap[p.Name]; ok {
				// If the promotion is already in the map,
				// only if the staus for the promotion in the map is not passed.
				if currentP.Status != passed {
					imagesPromotionsMap[p.Name] = p
				}
			} else {
				imagesPromotionsMap[p.Name] = p
			}
		}
	}

	imagesPromotions := make([]promotion, 0, len(imagesPromotionsMap))
	for _, p := range imagesPromotionsMap {
		imagesPromotions = append(imagesPromotions, p)
	}
	return imagesPromotions, nil
}

func getPipelineResult(orgURL, pipelineID, token string) (*pipeline, error) {
	url := apiURL(orgURL, fmt.Sprintf("/pipelines/%s", pipelineID))
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

	var p pipelineDetails
	if err := json.NewDecoder(resp.Body).Decode(&p); err != nil {
		return nil, fmt.Errorf("failed to parse pipeline: %s", err.Error())
	}

	return &p.Pipeline, err
}

func fetchParentPipelineID(orgURL, pipelineID, token string) (string, error) {
	url := apiURL(orgURL, fmt.Sprintf("/pipelines/%s", pipelineID))
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create %s request: %s", url, err.Error())
	}
	req.Header.Set("Authorization", fmt.Sprintf("Token %s", token))

	logrus.WithField("url", req.URL.String()).Debug("get pipeline details")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to request pipeline details: %s", err.Error())
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to fetch pipeline details")
	}

	var p pipelineDetails
	if err := json.NewDecoder(resp.Body).Decode(&p); err != nil {
		return "", fmt.Errorf("failed to parse pipeline: %s", err.Error())
	}

	return p.Pipeline.PromotionOf, err
}

func retrieveExpectedPromotions(repoRootDir string) ([]string, error) {
	promotionsFile := fmt.Sprintf("%s/.semaphore/semaphore.yml.d/03-promotions.yml", repoRootDir)
	expectPromotions, err := command.Run("grep", []string{"-Po", `"name: \K(((P|p)ush|(P|p)ublish).*images.*)"`, promotionsFile})
	if err != nil {
		return nil, fmt.Errorf("failed to get expected image promotions from %s: %s", promotionsFile, err.Error())
	}
	return strings.Split(expectPromotions, "\n"), nil
}

func getDistinctImagePromotions(promotions []promotion, orgURL, token string) (map[string]pipeline, error) {
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
				return nil, fmt.Errorf("unable to get %q pipeline details: %s", promotion.Name, err.Error())
			}
			// If the new promotion is passed, update the current promotion.
			if newP.Result == passed {
				promotionsSet[name] = *newP
			}
		} else {
			// If the promotion does not exist, add it to the set.
			pipelineResult, err := getPipelineResult(orgURL, promotion.PipelineID, token)
			if err != nil {
				return nil, fmt.Errorf("unable to get %q pipeline details: %s", promotion.Name, err.Error())
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
	parentPipelineID, err := fetchParentPipelineID(orgURL, pipelineID, token)
	if err != nil {
		return false, err
	}
	if parentPipelineID == "" {
		logrus.Info("no parent pipeline found, skipping image promotions check")
		return true, nil
	}
	logrus.WithField("pipeline_id", parentPipelineID).Debug("found pipeline that triggered image promotions")
	promotions, err := fetchImagePromotions(orgURL, pipelineID, token)
	if err != nil {
		return false, err
	}

	// actualUniquePromotions is used to ensure that there are no duplicate promotions.
	// It contains the names of the promotions in lowercase and their pipeline details.
	actualUniquePromotions, err := getDistinctImagePromotions(promotions, orgURL, token)
	if err != nil {
		return false, err
	}
	// If there are no promotions, return an error.
	if len(actualUniquePromotions) == 0 {
		return false, fmt.Errorf("no image promotions found for in pipeline %s, wait till all image promotions are completed", parentPipelineID)
	}

	var missingPromotions, failedPromotions []string

	for _, p := range expectedPromotions {
		p = strings.ToLower(p)
		if pipeline, ok := actualUniquePromotions[p]; !ok {
			missingPromotions = append(missingPromotions, p)
		} else if pipeline.Result != passed {
			failedPromotions = append(failedPromotions, p)
		}
	}

	if len(missingPromotions) > 0 || len(failedPromotions) > 0 {
		errMsg := "image promotions check failed: "
		if len(missingPromotions) > 0 {
			errMsg += fmt.Sprintf("missing: %v", strings.Join(missingPromotions, ", "))
			if len(failedPromotions) > 0 {
				errMsg += ", "
			}
		}
		if len(failedPromotions) > 0 {
			errMsg += fmt.Sprintf("failed: %v", strings.Join(failedPromotions, ", "))
		}
		logrus.Error(errMsg)
		return false, errors.New(errMsg)
	}

	return true, nil
}
