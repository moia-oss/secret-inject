/*
Copyright 2021 MOIA GmbH.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package await

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/moia-dev/secret-inject/credentials"
	"golang.org/x/oauth2"
)

//nolint:gosec // gosec thinks this is a static credential, but it's not
const ghTokenEnvVarName = "GITHUB_TOKEN"
const ghRepoEnvVarName = "GITHUB_REPOSITORY"
const ghSHAEnvVarName = "GITHUB_SHA"
const ghURLPrefix = "https://api.github.com"

type ghInputs struct {
	token, repo, commitSHA string
}

func ghInputsFromEnv() (ghInputs, error) {
	ghi := ghInputs{}

	ghi.token = os.Getenv(ghTokenEnvVarName)
	if ghi.token == "" {
		return ghInputs{}, fmt.Errorf("no Github token found in environment variable '%s'",
			ghTokenEnvVarName)
	}

	ghi.repo = os.Getenv(ghRepoEnvVarName)
	if ghi.repo == "" {
		return ghInputs{}, fmt.Errorf("no Github repo found in environment variable '%s'",
			ghRepoEnvVarName)
	}

	ghi.commitSHA = os.Getenv(ghSHAEnvVarName)
	if ghi.commitSHA == "" {
		return ghInputs{}, fmt.Errorf("no commitSHA found in environment variable '%s'",
			ghSHAEnvVarName)
	}

	return ghi, nil
}

func isHTTPStatusCodeOKRange(resp *http.Response) bool {
	return resp.StatusCode >= 200 && resp.StatusCode <= 299
}

func (h *Handler) commentOnPR(ghi ghInputs) error {
	src := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: ghi.token},
	)
	hc := oauth2.NewClient(context.Background(), src)

	// We first need to get the PRs belonging to the commit
	// https://docs.github.com/en/free-pro-team@latest/rest/reference/repos#list-pull-requests-associated-with-a-commit
	// curl \
	//  -H "Accept: application/vnd.github.groot-preview+json" \
	//  https://api.github.com/repos/octocat/hello-world/commits/COMMIT_SHA/pulls

	uri := fmt.Sprintf("%s/repos/%s/commits/%s/pulls", ghURLPrefix, ghi.repo, ghi.commitSHA)

	req, err := http.NewRequest(http.MethodGet, uri, nil)
	if err != nil {
		return fmt.Errorf("failed to generate HTTP request for getting PRs belonging to commit: %w", err)
	}

	// necessary to use this header because it's not part of the stable API
	req.Header.Set("Accept", "application/vnd.github.groot-preview+json")

	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("failed to perform HTTP request for getting PRs belonging to commit: %w", err)
	}

	if !isHTTPStatusCodeOKRange(resp) {
		return fmt.Errorf("failed to perform HTTP request for getting PRs belonging to commit. It returned status code: %d", resp.StatusCode)
	}

	bodyBuf, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read result of HTTP request for getting PRs belonging to commit into buffer: %w", err)
	}

	var jsonRepr []map[string]interface{}

	err = json.Unmarshal(bodyBuf, &jsonRepr)
	if err != nil {
		return fmt.Errorf("failed to unmarshal result of HTTP request for getting PRs belonging to commit into JSON: %w", err)
	}

	if len(jsonRepr) == 0 {
		fmt.Printf("Unable to find a PR belonging to this commit '%s'. Skipping commenting on PR.\n", ghi.commitSHA)

		return nil
	}

	if len(jsonRepr) > 1 {
		fmt.Printf("Found more than one PR belonging to this commit '%s' (found %d PRs). Will just use the first PR, however this could be less than ideal.\n", ghi.commitSHA, len(jsonRepr))
	}

	prNum, ok := jsonRepr[0]["number"].(float64)
	if !ok {
		return fmt.Errorf("failed to assert that what we expect to be the PR number is a float64 type. We found the following data in the JSON object:  %v", jsonRepr[0]["number"])
	}

	// finally we can perform the actual comment action
	// we need to use the 'issues' endpoint (Github considers PRs to be a form of issues). '%.0f' renders the float in an integer style, e.g. '85'
	uri = fmt.Sprintf("%s/repos/%s/issues/%.0f/comments", ghURLPrefix, ghi.repo, prNum)

	var buf bytes.Buffer

	msg := fmt.Sprintf("Please inject credentials into the workflow run by running `secret-inject inject %s`",
		credentials.PublicKeyAsCommandLineArg(h.publicKey))
	je := json.NewEncoder(&buf)

	err = je.Encode(map[string]string{"body": msg})
	if err != nil {
		return fmt.Errorf("failed to JSON marshal message which would have been posted as PR comment: %w", err)
	}

	req, err = http.NewRequest(http.MethodPost, uri, &buf)
	if err != nil {
		return fmt.Errorf("failed to generate HTTP request for posting PR comment: %w", err)
	}

	// recommended as per Github API docs
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err = hc.Do(req)
	if err != nil {
		return fmt.Errorf("failed to perform HTTP request for posting PR comment: %w", err)
	}

	if !isHTTPStatusCodeOKRange(resp) {
		return fmt.Errorf("failed to perform HTTP request for posting PR comment. It returned status code: %d",
			resp.StatusCode)
	}

	return nil
}

func (h *Handler) CommentOnPR() error {
	ghi, err := ghInputsFromEnv()
	if err != nil {
		return err
	}

	err = h.commentOnPR(ghi)
	if err != nil {
		return err
	}

	return nil
}
