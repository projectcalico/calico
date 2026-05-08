// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// certify runs Openshift preflight against Calico images and optionally
// submits the results to Openshift Connect for the certification process.
//
// The certification process also requires:
//   - the operator metadata bundle (see the tigera/operator repo) to be
//     submitted by PR to https://github.com/redhat-openshift-ecosystem/certified-operators
//   - running the Openshift End-to-End tests for CNI and CNV; results are
//     passed to the Certification team for verification.
//
// Neither of those is handled here.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

const catalogAPIBase = "https://catalog.redhat.com/api/containers/v1/projects/certification/id/"

var httpClient = &http.Client{Timeout: 30 * time.Second}

const defaultValuesFilePath = "charts/tigera-operator/values.yaml"

// httpConcurrency caps concurrent HTTP fetches against catalog.redhat.com
// during privileged-flag and certification-status lookups, so a large image
// catalog doesn't hammer the API.
const httpConcurrency = 8

// imagesPageSize is the page_size used for the paginated /images endpoint.
const imagesPageSize = 100

var linuxPlatforms = []string{"amd64", "arm64", "s390x", "ppc64le"}

var calicoImageProject = map[string]string{
	"node":                         "5e61a7ab06151b52d45a1148",
	"cni":                          "5e7e3829afa92f4963e7d9db",
	"kube-controllers":             "5e6054f906151b52d45a1081",
	"typha":                        "5e60724f2f3c1acdd05f6012",
	"pod2daemon-flexvol":           "5e6054fb06151b52d45a1082",
	"apiserver":                    "64b7c1758357ec6208cd2c72",
	"csi":                          "64b7c10b46357734e64690ac",
	"node-driver-registrar":        "64c01702093679e0f47fa153",
	"flannel-migration-controller": "5e619bec2c5f183d03415978",
	"dikastes":                     "5e619e432f3c1acdd05f6240",
}

var operatorImageProject = map[string]string{
	"operator": "5e60736f2f3c1acdd05f6014",
}

type checkResult struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Help        string `json:"help,omitempty"`
	Suggestion  string `json:"suggestion,omitempty"`
}

type preflightResults struct {
	Image   string `json:"image"`
	Passed  bool   `json:"passed"`
	Results struct {
		Passed []checkResult `json:"passed"`
		Failed []checkResult `json:"failed"`
		Errors []checkResult `json:"errors"`
	} `json:"results"`
}

type scanJob struct {
	image    string
	platform string
	org      string
	project  string
	version  string
	workdir  string
}

type scanResult struct {
	job       scanJob
	output    []byte
	runErr    error
	preflight *preflightResults
	parseErr  error
}

type rootOpts struct {
	calicoVersion   string
	operatorVersion string
	rhAPIKey        string
	valuesFile      string
	allowMaster     bool
}

// exitErr lets RunE / PersistentPreRunE signal a specific exit code through
// cobra's error path. main() unwraps it and exits with the requested code.
type exitErr struct {
	code int
	err  error
}

func (e *exitErr) Error() string { return e.err.Error() }
func (e *exitErr) Unwrap() error { return e.err }

func usageErrorf(format string, args ...any) error {
	return &exitErr{code: 2, err: fmt.Errorf(format, args...)}
}

func lookForGitRoot() (string, error) {
	cmd := exec.Command("git", "rev-parse", "--show-toplevel")
	if output, err := cmd.Output(); err != nil {
		return "", fmt.Errorf("could not find git toplevel")
	} else {
		return strings.TrimSpace(string(output)), nil
	}
}

func relativeGitRoot() (string, error) {
	gitRoot, err := lookForGitRoot()
	if err != nil {
		return "", err
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("could not get cwd: %w", err)
	}
	rel, err := filepath.Rel(cwd, gitRoot)
	if err != nil {
		return "", fmt.Errorf("could not get relative path: %w", err)
	}
	fmt.Println(rel)
	return rel, nil

}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := newRootCmd().ExecuteContext(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		var ee *exitErr
		if errors.As(err, &ee) {
			os.Exit(ee.code)
		}
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	opts := &rootOpts{}
	gitRoot, err := relativeGitRoot()
	if err != nil {
		os.Exit(1)
	}
	defaultAbsValuesFilePath := filepath.Join(gitRoot, defaultValuesFilePath)
	cmd := &cobra.Command{
		Use:           "certify",
		Short:         "Openshift preflight runner and certification checker for Calico images",
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return resolveVersions(opts)
		},
	}
	cmd.PersistentFlags().StringVar(&opts.calicoVersion, "calico-version", os.Getenv("CALICO_VERSION"), "calico version to certify (defaults to value from --values-file)")
	cmd.PersistentFlags().StringVar(&opts.operatorVersion, "operator-version", os.Getenv("OPERATOR_VERSION"), "operator version to certify (defaults to value from --values-file)")
	cmd.PersistentFlags().StringVar(&opts.rhAPIKey, "rh-api-key", os.Getenv("RH_API_KEY"), "Red Hat API key (sent as the X-API-KEY header)")
	cmd.PersistentFlags().StringVar(&opts.valuesFile, "values-file", defaultAbsValuesFilePath, "helm values.yaml file to read default versions from")
	cmd.PersistentFlags().BoolVar(&opts.allowMaster, "allow-master", false, "proceed even if a version is \"master\" (not a valid certification target)")
	cmd.AddCommand(newRunCmd(opts), newCheckCmd(opts))
	return cmd
}

// resolveVersions fills in any unset version flags from the helm values file
// (falling back to "master") and rejects "master" unless --allow-master is set.
func resolveVersions(opts *rootOpts) error {
	if opts.calicoVersion == "" || opts.operatorVersion == "" {
		cv, ov, err := readChartVersions(opts.valuesFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not read defaults from %s: %v\n", opts.valuesFile, err)
		}
		if opts.calicoVersion == "" {
			opts.calicoVersion = cv
		}
		if opts.operatorVersion == "" {
			opts.operatorVersion = ov
		}
	}
	if opts.calicoVersion == "" {
		opts.calicoVersion = "master"
	}
	if opts.operatorVersion == "" {
		opts.operatorVersion = "master"
	}
	if opts.allowMaster {
		return nil
	}
	var bad []string
	if opts.calicoVersion == "master" {
		bad = append(bad, "--calico-version is \"master\"")
	}
	if opts.operatorVersion == "master" {
		bad = append(bad, "--operator-version is \"master\"")
	}
	if len(bad) > 0 {
		return usageErrorf("%s — not a valid certification target. Pass --allow-master to bypass.", strings.Join(bad, " and "))
	}
	return nil
}

func newRunCmd(opts *rootOpts) *cobra.Command {
	var (
		preflightTag string
		submit       bool
		concurrency  int
	)
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run preflight scans against Calico images and optionally submit results to Openshift Connect",
		RunE: func(cmd *cobra.Command, args []string) error {
			if submit && opts.rhAPIKey == "" {
				return usageErrorf("--submit requires --rh-api-key (or RH_API_KEY env var)")
			}
			return runScans(cmd.Context(), opts, preflightTag, submit, concurrency)
		},
	}
	cmd.Flags().StringVar(&preflightTag, "preflight-tag", envOr("PREFLIGHT_TAG", "stable"), "preflight image tag")
	cmd.Flags().BoolVar(&submit, "submit", false, "actually submit results to Openshift Connect")
	cmd.Flags().IntVar(&concurrency, "concurrency", runtime.GOMAXPROCS(0), "number of scans to run concurrently")
	return cmd
}

func newCheckCmd(opts *rootOpts) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "check",
		Short: "Fetch certification status from catalog.redhat.com and report per-architecture results",
		RunE: func(cmd *cobra.Command, args []string) error {
			if opts.rhAPIKey == "" {
				return usageErrorf("check requires --rh-api-key (or RH_API_KEY env var)")
			}
			return runCertCheck(cmd.Context(), opts)
		},
	}
	return cmd
}

func runScans(ctx context.Context, opts *rootOpts, preflightTag string, submit bool, concurrency int) error {
	outputRoot := "output-" + opts.calicoVersion
	jobs := buildJobs(outputRoot, opts.calicoVersion, opts.operatorVersion)

	if err := os.MkdirAll(outputRoot, 0o755); err != nil {
		return fmt.Errorf("failed to create %s: %w", outputRoot, err)
	}

	preflightImage := "quay.io/opdev/preflight:" + preflightTag
	fmt.Printf("Pulling %s\n", preflightImage)
	if out, err := exec.CommandContext(ctx, "podman", "pull", preflightImage).CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", out)
		return fmt.Errorf("podman pull: %w", err)
	}

	fmt.Printf("Running %d scans (concurrency %d)\n", len(jobs), concurrency)

	var privileged map[string]bool
	if opts.rhAPIKey != "" {
		fmt.Println("Fetching project info from catalog.redhat.com")
		privileged = fetchProjectPrivileged(ctx, jobs, opts.rhAPIKey)
	} else {
		fmt.Fprintln(os.Stderr, "note: no --rh-api-key supplied; skipping project privileged-flag lookup")
	}

	results := runJobs(ctx, jobs, concurrency, preflightImage, opts.rhAPIKey, submit)

	if err := consolidate(outputRoot, linuxPlatforms); err != nil {
		fmt.Fprintf(os.Stderr, "consolidation failed: %v\n", err)
	}

	if !printReport(results, privileged) {
		return &exitErr{code: 1, err: errors.New("one or more scans had issues; see report above")}
	}
	return nil
}

func runCertCheck(ctx context.Context, opts *rootOpts) error {
	outputRoot := "output-" + opts.calicoVersion
	jobs := buildJobs(outputRoot, opts.calicoVersion, opts.operatorVersion)
	fmt.Println("Fetching certification status from catalog.redhat.com")
	certResults := fetchAllCertStatus(ctx, jobs, opts.rhAPIKey)
	if !printCertStatus(certResults) {
		return &exitErr{code: 1, err: errors.New("one or more images are not fully certified")}
	}
	return nil
}

type projectInfo struct {
	Container struct {
		Privileged bool `json:"privileged"`
	} `json:"container"`
}

func fetchProjectInfo(ctx context.Context, projectID, apiKey string) (*projectInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, catalogAPIBase+projectID, nil)
	if err != nil {
		return nil, err
	}
	// The Pyxis catalog API requires the header in upper-case (X-API-KEY);
	// http.Header.Set would canonicalise to X-Api-Key.
	req.Header["X-API-KEY"] = []string{apiKey}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var pi projectInfo
	if err := json.NewDecoder(resp.Body).Decode(&pi); err != nil {
		return nil, err
	}
	return &pi, nil
}

type imageCertEntry struct {
	Architecture string `json:"architecture"`
	Certified    bool   `json:"certified"`
	Repositories []struct {
		Tags []struct {
			Name string `json:"name"`
		} `json:"tags"`
	} `json:"repositories"`
}

type imagesResponse struct {
	Data     []imageCertEntry `json:"data"`
	Page     int              `json:"page"`
	PageSize int              `json:"page_size"`
	Total    int              `json:"total"`
}

// fetchProjectImagesPaged walks every page of the project's /images endpoint
// and returns the full set of entries.
func fetchProjectImagesPaged(ctx context.Context, projectID, apiKey string) ([]imageCertEntry, error) {
	var all []imageCertEntry
	for page := 0; ; page++ {
		url := fmt.Sprintf("%s%s/images?page_size=%d&page=%d", catalogAPIBase, projectID, imagesPageSize, page)
		ir, err := fetchImagesPage(ctx, url, apiKey)
		if err != nil {
			return nil, err
		}
		all = append(all, ir.Data...)
		if len(ir.Data) == 0 || len(all) >= ir.Total {
			return all, nil
		}
	}
}

func fetchImagesPage(ctx context.Context, url, apiKey string) (*imagesResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	// See fetchProjectInfo for the upper-case header rationale.
	req.Header["X-API-KEY"] = []string{apiKey}
	req.Header["Accept"] = []string{"application/json"}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var ir imagesResponse
	if err := json.NewDecoder(resp.Body).Decode(&ir); err != nil {
		return nil, err
	}
	return &ir, nil
}

type certStatus int

const (
	certMissing certStatus = iota
	certNotCertified
	certCertified
)

type imageCertResult struct {
	image    string
	version  string
	statuses map[string]certStatus // arch -> status
	err      error
}

func entryHasVersion(e imageCertEntry, version string) bool {
	for _, repo := range e.Repositories {
		for _, tag := range repo.Tags {
			if tag.Name == version {
				return true
			}
		}
	}
	return false
}

// checkProjectCertification fetches all images for a project and classifies
// each architecture in linuxPlatforms as certified, not certified (arch
// present but no entry satisfies all criteria), or missing (no entry at all
// for that arch).
func checkProjectCertification(ctx context.Context, projectID, version, apiKey string) (map[string]certStatus, error) {
	entries, err := fetchProjectImagesPaged(ctx, projectID, apiKey)
	if err != nil {
		return nil, err
	}
	archPresent := map[string]bool{}
	archCertified := map[string]bool{}
	for _, e := range entries {
		archPresent[e.Architecture] = true
		if e.Certified && entryHasVersion(e, version) {
			archCertified[e.Architecture] = true
		}
	}
	statuses := map[string]certStatus{}
	for _, arch := range linuxPlatforms {
		switch {
		case archCertified[arch]:
			statuses[arch] = certCertified
		case archPresent[arch]:
			statuses[arch] = certNotCertified
		default:
			statuses[arch] = certMissing
		}
	}
	return statuses, nil
}

// fetchAllCertStatus runs checkProjectCertification concurrently for every
// unique image in jobs, capped at httpConcurrency in flight at a time.
func fetchAllCertStatus(ctx context.Context, jobs []scanJob, apiKey string) []imageCertResult {
	type info struct{ projectID, version string }
	seen := map[string]info{}
	for _, j := range jobs {
		seen[j.image] = info{j.project, j.version}
	}
	results := make([]imageCertResult, 0, len(seen))
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, httpConcurrency)
	for image, i := range seen {
		wg.Add(1)
		sem <- struct{}{}
		go func(image string, i info) {
			defer wg.Done()
			defer func() { <-sem }()
			statuses, err := checkProjectCertification(ctx, i.projectID, i.version, apiKey)
			mu.Lock()
			results = append(results, imageCertResult{
				image:    image,
				version:  i.version,
				statuses: statuses,
				err:      err,
			})
			mu.Unlock()
		}(image, i)
	}
	wg.Wait()
	sort.Slice(results, func(i, j int) bool { return results[i].image < results[j].image })
	return results
}

// printCertStatus prints the per-image certification breakdown and returns
// true if every image is fully certified across all linuxPlatforms.
func printCertStatus(results []imageCertResult) bool {
	fmt.Println()
	fmt.Println("================ certification status ================")
	allOK := true
	for _, r := range results {
		fmt.Printf("\n%s @ %s:\n", r.image, r.version)
		if r.err != nil {
			fmt.Printf("  error: %v\n", r.err)
			allOK = false
			continue
		}
		var certified, notCertified, missing []string
		for _, arch := range linuxPlatforms {
			switch r.statuses[arch] {
			case certCertified:
				certified = append(certified, arch)
			case certNotCertified:
				notCertified = append(notCertified, arch)
			case certMissing:
				missing = append(missing, arch)
			}
		}
		if len(certified) > 0 {
			fmt.Printf("  certified:     %s\n", strings.Join(certified, ", "))
		}
		if len(notCertified) > 0 {
			fmt.Printf("  not certified: %s\n", strings.Join(notCertified, ", "))
			allOK = false
		}
		if len(missing) > 0 {
			fmt.Printf("  missing:       %s\n", strings.Join(missing, ", "))
			allOK = false
		}
	}
	return allOK
}

// fetchProjectPrivileged returns image -> privileged for every unique project
// referenced by jobs. Failures are reported as warnings and the corresponding
// image is omitted (treated as not privileged). At most httpConcurrency
// fetches run at once.
func fetchProjectPrivileged(ctx context.Context, jobs []scanJob, apiKey string) map[string]bool {
	seen := map[string]string{}
	for _, j := range jobs {
		seen[j.image] = j.project
	}
	privileged := make(map[string]bool, len(seen))
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, httpConcurrency)
	for image, projectID := range seen {
		wg.Add(1)
		sem <- struct{}{}
		go func(image, projectID string) {
			defer wg.Done()
			defer func() { <-sem }()
			pi, err := fetchProjectInfo(ctx, projectID, apiKey)
			if err != nil {
				fmt.Fprintf(os.Stderr, "warning: project info for %s (%s): %v\n", image, projectID, err)
				return
			}
			mu.Lock()
			privileged[image] = pi.Container.Privileged
			mu.Unlock()
		}(image, projectID)
	}
	wg.Wait()
	return privileged
}

func buildJobs(outputRoot, calicoVersion, operatorVersion string) []scanJob {
	var jobs []scanJob
	add := func(images map[string]string, org, version string) {
		for _, image := range sortedKeys(images) {
			for _, platform := range linuxPlatforms {
				jobs = append(jobs, scanJob{
					image:    image,
					platform: platform,
					org:      org,
					project:  images[image],
					version:  version,
					workdir:  filepath.Join(outputRoot, image, platform),
				})
			}
		}
	}
	add(calicoImageProject, "quay.io/calico", calicoVersion)
	add(operatorImageProject, "quay.io/tigera", operatorVersion)
	return jobs
}

func runJobs(ctx context.Context, jobs []scanJob, concurrency int, preflightImage, apiKey string, submit bool) []scanResult {
	if concurrency < 1 {
		concurrency = 1
	}
	results := make([]scanResult, len(jobs))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for i, job := range jobs {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, job scanJob) {
			defer wg.Done()
			defer func() { <-sem }()
			fmt.Printf("[start] %s/%s\n", job.image, job.platform)
			results[i] = runScan(ctx, job, preflightImage, apiKey, submit)
			fmt.Printf("[done ] %s/%s — %s\n", job.image, job.platform, summarise(results[i]))
		}(i, job)
	}
	wg.Wait()
	return results
}

func runScan(ctx context.Context, job scanJob, preflightImage, apiKey string, submit bool) scanResult {
	res := scanResult{job: job}
	if err := os.MkdirAll(job.workdir, 0o755); err != nil {
		res.runErr = fmt.Errorf("mkdir %s: %w", job.workdir, err)
		return res
	}
	abs, err := filepath.Abs(job.workdir)
	if err != nil {
		res.runErr = fmt.Errorf("abs %s: %w", job.workdir, err)
		return res
	}

	imageRef := fmt.Sprintf("%s/%s:%s", job.org, job.image, job.version)
	args := []string{
		"run", "--rm", "--security-opt=label=disable",
		"--env", "PFLT_PYXIS_API_TOKEN",
		"-v", abs + ":/artifacts",
		preflightImage,
		"check", "container", imageRef,
		"--platform", job.platform,
		"--artifacts", "/artifacts",
		"--logfile", "/artifacts/preflight.log",
		"--certification-component-id", job.project,
	}
	if submit {
		args = append(args, "--submit")
	}

	var buf bytes.Buffer
	cmd := exec.CommandContext(ctx, "podman", args...)
	cmd.Env = append(os.Environ(), "PFLT_PYXIS_API_TOKEN="+apiKey)
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	if err := cmd.Run(); err != nil {
		res.runErr = err
	}
	res.output = buf.Bytes()

	data, err := os.ReadFile(filepath.Join(job.workdir, "results.json"))
	if err != nil {
		res.parseErr = fmt.Errorf("read results.json: %w", err)
		return res
	}
	var pr preflightResults
	if err := json.Unmarshal(data, &pr); err != nil {
		res.parseErr = fmt.Errorf("parse results.json: %w", err)
		return res
	}
	res.preflight = &pr
	return res
}

func summarise(r scanResult) string {
	switch {
	case r.runErr != nil:
		return fmt.Sprintf("podman error: %v", r.runErr)
	case r.parseErr != nil:
		return fmt.Sprintf("parse error: %v", r.parseErr)
	case r.preflight == nil:
		return "no results"
	case r.preflight.Passed:
		return "passed"
	default:
		return fmt.Sprintf("did not pass (%d failed, %d errors)",
			len(r.preflight.Results.Failed), len(r.preflight.Results.Errors))
	}
}

// consolidate writes a single JSON array per architecture combining every
// per-image results.json. The original shell script emitted concatenated
// objects with no separator (technically invalid JSON); we emit a real array
// so the file is parseable with jq / json.Unmarshal.
func consolidate(outputRoot string, platforms []string) error {
	for _, platform := range platforms {
		matches, err := filepath.Glob(filepath.Join(outputRoot, "*", platform, "results.json"))
		if err != nil {
			return err
		}
		out := filepath.Join(outputRoot, platform+"-results.json")
		if err := writeConsolidated(out, matches); err != nil {
			return err
		}
	}
	return nil
}

func writeConsolidated(out string, paths []string) error {
	f, err := os.Create(out)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := io.WriteString(f, "[\n"); err != nil {
		return err
	}
	for i, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if !json.Valid(data) {
			return fmt.Errorf("%s: invalid JSON", p)
		}
		if i > 0 {
			if _, err := io.WriteString(f, ",\n"); err != nil {
				return err
			}
		}
		if _, err := f.Write(bytes.TrimRight(data, "\n")); err != nil {
			return err
		}
	}
	if _, err := io.WriteString(f, "\n]\n"); err != nil {
		return err
	}
	return nil
}

// printReport writes the end-of-run summary and returns true if every scan
// passed cleanly. Errors are consolidated per image: each unique error lists
// the architectures it affects, with help and suggestion shown once.
//
// privileged is image -> whether the corresponding Openshift Connect project
// has .container.privileged=true; for those images, RunAsNonRoot failures
// (but not errors) are hidden from the output.
func printReport(results []scanResult, privileged map[string]bool) bool {
	var podmanFails, scanIssues []scanResult
	for _, r := range results {
		switch {
		case r.runErr != nil, r.preflight == nil:
			podmanFails = append(podmanFails, r)
		case scanHasRemainingIssues(r, privileged):
			scanIssues = append(scanIssues, r)
		}
	}

	fmt.Println()
	fmt.Println("===================== summary =====================")
	fmt.Printf("scans run: %d, podman failures: %d, scans with issues: %d\n",
		len(results), len(podmanFails), len(scanIssues))

	if len(podmanFails) > 0 {
		printPodmanFails(podmanFails)
	}
	if len(scanIssues) > 0 {
		printScanIssues(scanIssues, privileged)
	}

	if len(podmanFails) == 0 && len(scanIssues) == 0 {
		fmt.Println("All scans passed.")
		return true
	}
	return false
}

// failureHidden reports whether a failed check should be suppressed for the
// given image. RunAsNonRoot is expected to fail on projects whose Openshift
// Connect entry is marked privileged.
func failureHidden(c checkResult, image string, privileged map[string]bool) bool {
	return c.Name == "RunAsNonRoot" && privileged[image]
}

func scanHasRemainingIssues(r scanResult, privileged map[string]bool) bool {
	if r.preflight == nil {
		return false
	}
	if len(r.preflight.Results.Errors) > 0 {
		return true
	}
	for _, c := range r.preflight.Results.Failed {
		if !failureHidden(c, r.job.image, privileged) {
			return true
		}
	}
	return false
}

// archIndex returns a comparator that orders architectures by their position
// in linuxPlatforms (unknown ones sort last).
func archIndex(a string) int {
	for i, p := range linuxPlatforms {
		if p == a {
			return i
		}
	}
	return len(linuxPlatforms)
}

func sortArchs(archs []string) {
	sort.Slice(archs, func(i, j int) bool { return archIndex(archs[i]) < archIndex(archs[j]) })
}

func printPodmanFails(fails []scanResult) {
	fmt.Println()
	fmt.Println("--- podman runs that failed ---")

	type key struct{ msg, output string }
	byImage := map[string]map[key][]string{}
	for _, r := range fails {
		m := byImage[r.job.image]
		if m == nil {
			m = map[key][]string{}
			byImage[r.job.image] = m
		}
		k := key{summarise(r), string(r.output)}
		m[k] = append(m[k], r.job.platform)
	}

	images := make([]string, 0, len(byImage))
	for i := range byImage {
		images = append(images, i)
	}
	sort.Strings(images)

	for _, image := range images {
		m := byImage[image]
		fmt.Printf("\n%s:\n", image)
		keys := make([]key, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return keys[i].msg < keys[j].msg })
		for _, k := range keys {
			archs := m[k]
			sortArchs(archs)
			fmt.Printf("  %s [%s]\n", k.msg, strings.Join(archs, ", "))
			if k.output != "" {
				for line := range strings.SplitSeq(strings.TrimRight(k.output, "\n"), "\n") {
					fmt.Printf("    %s\n", line)
				}
			}
		}
	}
}

func printScanIssues(issues []scanResult, privileged map[string]bool) {
	fmt.Println()
	fmt.Println("--- preflight failures and errors ---")

	type key struct{ kind, name string }
	type val struct {
		help, suggestion string
		archs            []string
	}
	byImage := map[string]map[key]*val{}
	record := func(image, platform, kind string, c checkResult) {
		m := byImage[image]
		if m == nil {
			m = map[key]*val{}
			byImage[image] = m
		}
		k := key{kind, c.Name}
		v := m[k]
		if v == nil {
			v = &val{help: c.Help, suggestion: c.Suggestion}
			m[k] = v
		}
		v.archs = append(v.archs, platform)
	}
	for _, r := range issues {
		for _, c := range r.preflight.Results.Failed {
			if failureHidden(c, r.job.image, privileged) {
				continue
			}
			record(r.job.image, r.job.platform, "FAIL", c)
		}
		for _, c := range r.preflight.Results.Errors {
			record(r.job.image, r.job.platform, "ERROR", c)
		}
	}

	images := make([]string, 0, len(byImage))
	for i := range byImage {
		images = append(images, i)
	}
	sort.Strings(images)

	for _, image := range images {
		m := byImage[image]
		keys := make([]key, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			if keys[i].kind != keys[j].kind {
				return keys[i].kind == "FAIL" // FAIL before ERROR
			}
			return keys[i].name < keys[j].name
		})

		fmt.Printf("\n%s:\n", image)
		for _, k := range keys {
			v := m[k]
			sortArchs(v.archs)
			fmt.Printf("  %-5s %s [%s]\n", k.kind, k.name, strings.Join(v.archs, ", "))
			if v.help != "" {
				fmt.Printf("        help: %s\n", v.help)
			}
			if v.suggestion != "" {
				fmt.Printf("        suggestion: %s\n", v.suggestion)
			}
		}
	}
}

// readChartVersions extracts the Calico (calicoctl.tag) and operator
// (tigeraOperator.version) versions from the helm values.yaml. The format is
// stable and shallow enough that a small line scanner avoids pulling in a YAML
// dep.
func readChartVersions(path string) (calico, operator string, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", "", err
	}
	defer f.Close()
	section := ""
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := s.Text()
		if line == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if line[0] != ' ' && line[0] != '\t' {
			if i := strings.IndexByte(line, ':'); i > 0 {
				section = line[:i]
			} else {
				section = ""
			}
			continue
		}
		key, val, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		val = strings.Trim(strings.TrimSpace(val), `"'`)
		switch {
		case section == "tigeraOperator" && key == "version":
			operator = val
		case section == "calicoctl" && key == "tag":
			calico = val
		}
	}
	if err := s.Err(); err != nil {
		return "", "", err
	}
	return calico, operator, nil
}

func envOr(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
