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

package inject

import (
	"bytes"
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/client"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"github.com/moia-dev/secret-inject/config"
	"github.com/moia-dev/secret-inject/credentials"
	"gopkg.in/yaml.v2"
)

type Handler struct {
	session client.ConfigProvider
	conf    config.ApplicationConfig
}

func NewHandler(session client.ConfigProvider, conf config.ApplicationConfig) *Handler {
	return &Handler{
		session: session,
		conf:    conf,
	}
}

func (h *Handler) credentialsFromRoleAssumptions() ([]credentials.Stage, error) {
	credStages := make([]credentials.Stage, len(h.conf.Stages))

	for i := range h.conf.Stages {
		credsOption := func(p *stscreds.AssumeRoleProvider) {
			p.Duration = h.conf.CredentialsDurationOrDefault()
		}
		awsCreds := stscreds.NewCredentials(h.session, h.conf.Stages[i].RoleARN, credsOption)

		credVal, err := awsCreds.Get()
		if err != nil {
			return nil, fmt.Errorf("failed to generate AWS credentials via role assumption of role '%s': %w",
				h.conf.Stages[i].RoleARN, err)
		}

		credStages[i] = credentials.Stage{
			Name:    h.conf.Stages[i].Name,
			RoleARN: h.conf.Stages[i].RoleARN,
			AWSCredentials: credentials.AWSCredentials{
				AccessKeyID:     credVal.AccessKeyID,
				SecretAccessKey: credVal.SecretAccessKey,
				SessionToken:    credVal.SessionToken,
			},
		}
	}

	return credStages, nil
}

func (h *Handler) s3Client() s3iface.S3API {
	s3BucketCreds := stscreds.NewCredentials(h.session, h.conf.S3Bucket.RoleARN)

	return s3.New(h.session, &aws.Config{Credentials: s3BucketCreds})
}

func (h *Handler) Inject(encodedPubKey string) error {
	credStages, err := h.credentialsFromRoleAssumptions()
	if err != nil {
		return err
	}

	credsSet := credentials.Set{
		Stages: credStages,
	}

	pubKey, err := credentials.PublicKeyFromCommandLineArg(encodedPubKey)
	if err != nil {
		return fmt.Errorf("failed to parse public key from s3 key: %w", err)
	}

	encryptedSet, err := credentials.EncryptedSetFromSet(credsSet, pubKey)
	if err != nil {
		return err
	}

	marshalledEncrSet, err := yaml.Marshal(&encryptedSet)
	if err != nil {
		return err
	}

	_, err = h.s3Client().PutObject(&s3.PutObjectInput{
		Key:    aws.String(credentials.PublicKeyAsS3Key(pubKey)),
		Bucket: aws.String(h.conf.S3Bucket.BucketName),
		Body:   bytes.NewReader(marshalledEncrSet)})
	if err != nil {
		return fmt.Errorf("failed to put credentials into S3: %w", err)
	}

	return nil
}
