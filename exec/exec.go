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

package exec

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/moia-dev/secret-inject/config"
	"github.com/moia-dev/secret-inject/credentials"
)

func NewHandler(conf config.ApplicationConfig) *Handler {
	return &Handler{
		conf: conf,
	}
}

type Handler struct {
	conf config.ApplicationConfig
}

type stageAndIndex struct {
	stage credentials.Stage
	i     int
}

func whichShell() string {
	shell := os.Getenv("SHELL")
	if shell == "" {
		return "sh"
	}

	return shell
}

func (h *Handler) shouldExecute(si stageAndIndex, stages []credentials.Stage) (doExecute bool, reason string) {
	if h.conf.EnforceOrderOrDefault() {
		if si.stage.WasExecuted {
			return false, "stage was already executed"
		}

		if si.i != 0 && !stages[si.i-1].WasExecuted {
			return false, "predecessor stage was not yet executed"
		}
	}

	// We only give a reason if we don't execute
	return true, ""
}

func (h *Handler) Execute(stageName string, remainingArgs []string) (*exec.ExitError, error) {
	cs, err := credentials.LoadCredentialSetFromDisk(h.conf.CredentialsPathOrDefault())
	if err != nil {
		return nil, err
	}

	if len(h.conf.Stages) != len(cs.Stages) {
		return nil,
			fmt.Errorf("number of stages in config is %v while number of stages in credential-set is %v",
				len(h.conf.Stages), len(cs.Stages))
	}

	stageNameToStageAndIndex := make(map[string]stageAndIndex)
	for i, s := range cs.Stages {
		stageNameToStageAndIndex[s.Name] = stageAndIndex{
			stage: s,
			i:     i,
		}
	}

	si, found := stageNameToStageAndIndex[stageName]
	if !found {
		return nil, fmt.Errorf("unable to find stage '%v' in the stages present in credentials file", stageName)
	}

	if shouldExecute, reason := h.shouldExecute(si, cs.Stages); !shouldExecute {
		return nil, fmt.Errorf("command should not be executed: %s", reason)
	}

	// AWS_SECURITY_TOKEN is deprectaed and AWS_SESSION_TOKEN should be used instead
	// However, if AWS_SECURITY_TOKEN is set and has a different value than AWS_SESSION_TOKEN
	// we noted that it can cause authentication to fail
	err = os.Unsetenv("AWS_SECURITY_TOKEN")
	if err != nil {
		return nil,
			fmt.Errorf("unexpected error when unsetting environment variable 'AWS_SECURITY_TOKEN': %w", err)
	}

	//nolint:gosec // gosec complains that we just execute untested input. But that's the point of this program
	cmd := exec.Command(whichShell(), "-c", strings.Join(remainingArgs, " "))
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("AWS_SECRET_ACCESS_KEY=%s", si.stage.AWSCredentials.SecretAccessKey),
		fmt.Sprintf("AWS_ACCESS_KEY_ID=%s", si.stage.AWSCredentials.AccessKeyID),
		fmt.Sprintf("AWS_SESSION_TOKEN=%s", si.stage.AWSCredentials.SessionToken),
	)

	err = cmd.Run()
	if err != nil {
		innerErr := fmt.Errorf("command execution returned an error: %w", err)

		var e *exec.ExitError
		_ = errors.As(err, &e)

		return nil, innerErr
	}

	if h.conf.EnforceOrderOrDefault() {
		cs.Stages[si.i].WasExecuted = true

		err := cs.PersistToDisk(h.conf.CredentialsPathOrDefault())
		if err != nil {
			return nil, fmt.Errorf("failed to write updated credentials to disk after command execution: %w", err)
		}
	}

	return nil, nil
}
