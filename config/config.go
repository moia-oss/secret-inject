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

package config

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"

	validation "github.com/go-ozzo/ozzo-validation"
	"gopkg.in/yaml.v2"
)

const confFileName = "secret-inject.yaml"

var errUnableToFindConf = errors.New("unable to find config")

type (
	ApplicationConfig struct {
		S3Bucket                   S3BucketConf `yaml:"s3bucket"`
		Stages                     []Stage      `yaml:"stages"`
		EnforceOrder               *bool        `yaml:"enforce-order"`
		CredentialsPath            *string      `yaml:"credentials-path"`
		CredentialsDurationSeconds *int64       `yaml:"credentials-duration-seconds"`
		CommentOnPR                bool         `yaml:"comment-on-pr"`
	}

	S3BucketConf struct {
		RoleARN      string  `yaml:"role-arn"`
		AwaitRoleARN *string `yaml:"await-role-arn"`
		BucketName   string  `yaml:"bucket-name"`
	}

	Stage struct {
		Name    string `yaml:"name"`
		RoleARN string `yaml:"role-arn"`
	}
)

func (ac *ApplicationConfig) CredentialsDurationOrDefault() time.Duration {
	if ac.CredentialsDurationSeconds != nil {
		return time.Duration(*ac.CredentialsDurationSeconds) * time.Second
	}

	return 1200 * time.Second
}

func (ac *ApplicationConfig) EnforceOrderOrDefault() bool {
	return ac.EnforceOrder == nil || *ac.EnforceOrder
}

func (ac *ApplicationConfig) CredentialsPathOrDefault() string {
	if ac.CredentialsPath != nil {
		return *ac.CredentialsPath
	}

	return "./secret-inject-cred-set.yaml"
}

func (ac ApplicationConfig) Validate() error {
	validation.ErrorTag = "yaml"

	const iamSubstr = "arn:aws:iam::"

	isIamArn := validation.NewStringRule(func(s string) bool {
		return strings.Contains(s, iamSubstr)
	}, fmt.Sprintf("must be a valid IAM role ARN (we validate this by checking that it contains '%s')", iamSubstr))

	err := validation.ValidateStruct(&ac,
		validation.Field(&ac.S3Bucket, validation.Required),
		validation.Field(&ac.Stages, validation.Required),
		validation.Field(&ac.Stages, validation.Length(1, 256)),
		validation.Field(&ac.CredentialsDurationSeconds, validation.Min(1)),
		validation.Field(&ac.CredentialsDurationSeconds, validation.Max(60*60)),
	)
	if err != nil {
		return err
	}

	err = validation.ValidateStruct(&ac.S3Bucket,
		validation.Field(&ac.S3Bucket.BucketName, validation.Required),
		validation.Field(&ac.S3Bucket.RoleARN, validation.Required),
		validation.Field(&ac.S3Bucket.AwaitRoleARN, isIamArn),
		validation.Field(&ac.S3Bucket.RoleARN, isIamArn),
	)
	if err != nil {
		return err
	}

	for i := range ac.Stages {
		err = validation.ValidateStruct(&ac.Stages[i],
			validation.Field(&ac.Stages[i].Name, validation.Required),
			validation.Field(&ac.Stages[i].RoleARN, validation.Required),
			validation.Field(&ac.Stages[i].RoleARN, isIamArn),
		)
		if err != nil {
			return err
		}
	}

	return nil
}

func parseConf(bytes []byte) (ApplicationConfig, error) {
	ac := ApplicationConfig{}

	err := yaml.Unmarshal(bytes, &ac)
	if err != nil {
		return ApplicationConfig{}, fmt.Errorf("failed to unmarshal YAML: %w", err)
	}

	return ac, nil
}

func gitRepoRootOptional() *string {
	// git rev-parse --show-toplevel
	cmd := exec.Command("git", "rev-parse", "--show-toplevel")

	outputAsBytes, err := cmd.Output()
	if err != nil {
		log.Printf("Failed to get git top level. Possibly not a git repo or git not installed: %v\n", err)

		return nil
	}

	outputAsString := string(outputAsBytes)

	return &outputAsString
}

func confPath(p string) (string, error) {
	if p != "" {
		return p, nil
	}

	confPathCurDir := fmt.Sprintf("./%s", confFileName)
	_, err := os.Stat(confPathCurDir)
	fileExistsInCurrentDir := err == nil

	if fileExistsInCurrentDir {
		return confPathCurDir, nil
	}

	gr := gitRepoRootOptional()
	if gr == nil {
		return "", errUnableToFindConf
	}

	confPathGitRootDir := fmt.Sprintf("%s/%s", *gr, confFileName)
	_, err = os.Stat(confPathGitRootDir)

	fileExistsInGitRootDir := err == nil
	if fileExistsInGitRootDir {
		return confPathCurDir, nil
	}

	return "", errUnableToFindConf
}

func loadConfFile(confFilePath string) ([]byte, error) {
	confPath, err := confPath(confFilePath)
	if err != nil {
		return nil, err
	}

	bytes, err := ioutil.ReadFile(confPath)
	if err != nil {
		return nil, fmt.Errorf("unable to load config file contents: %w", err)
	}

	return bytes, nil
}

func LoadAndParseConf(confFilePath string) (ApplicationConfig, error) {
	bytes, err := loadConfFile(confFilePath)

	if err != nil {
		return ApplicationConfig{}, err
	}

	conf, err := parseConf(bytes)
	if err != nil {
		return ApplicationConfig{}, err
	}

	return conf, nil
}
