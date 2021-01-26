// +build integration

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

package main

import (
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/client"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/aws/aws-sdk-go/service/sts/stsiface"
	"github.com/moia-dev/secret-inject/await"
	"github.com/moia-dev/secret-inject/config"
	injectCreds "github.com/moia-dev/secret-inject/credentials"
	"github.com/moia-dev/secret-inject/inject"
	"github.com/stretchr/testify/suite"
)

const localstackEndpoint = "http://localhost:4566"

func localStackSession() (*session.Session, error) {
	lsc := aws.NewConfig().WithCredentials(credentials.NewStaticCredentials("id", "secret", "token"))
	lsc.S3ForcePathStyle = aws.Bool(true)
	return session.NewSession(
		lsc.WithRegion("eu-central-1").WithEndpoint(localstackEndpoint))
}

type IntegrationSuite struct {
	suite.Suite
	session   client.ConfigProvider
	s3Client  s3iface.S3API
	iamClient iamiface.IAMAPI
	stsClient stsiface.STSAPI
}

func (s *IntegrationSuite) SetupSuite() {
	sess, err := localStackSession()
	s.Require().NoError(err)

	s.session = sess
	s.s3Client = s3.New(sess)
	s.iamClient = iam.New(sess)
	s.stsClient = sts.New(sess)
}

// TestIntegrationSuite allows the normal Golang testing framework to run the test suite
func TestIntegrationSuite(t *testing.T) {
	suite.Run(t, new(IntegrationSuite))
}

// this is just an arbitrary policy document
// seems like localstack doesn't actually enforce anything here
const policyDoc = `
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:ListBucket"],
      "Resource": ["arn:aws:s3:::test"]
    }
  ]
}
`

func (s *IntegrationSuite) TestHappyPath() {
	const (
		s3Role    = "s3-role"
		stageRole = "stage-role"
		bucket    = "bucket"
	)

	cri := &iam.CreateRoleInput{
		RoleName:                 aws.String(stageRole),
		AssumeRolePolicyDocument: aws.String(policyDoc),
	}
	stageRoleOutput, err := s.iamClient.CreateRole(cri)
	defer s.iamClient.DeleteRole(&iam.DeleteRoleInput{
		RoleName: aws.String(stageRole),
	})
	s.Require().NoError(err)

	cri = &iam.CreateRoleInput{
		RoleName:                 aws.String(s3Role),
		AssumeRolePolicyDocument: aws.String(policyDoc),
	}
	s3RoleOutput, err := s.iamClient.CreateRole(cri)
	defer s.iamClient.DeleteRole(&iam.DeleteRoleInput{
		RoleName: aws.String(s3Role),
	})
	s.Require().NoError(err)

	_, err = s.s3Client.CreateBucket(&s3.CreateBucketInput{
		Bucket: aws.String(bucket),
	})
	s.Require().NoError(err)

	cnf := config.ApplicationConfig{
		S3Bucket: config.S3BucketConf{
			RoleARN:    *s3RoleOutput.Role.Arn,
			BucketName: bucket,
		},
		Stages: []config.Stage{{
			Name:    "dev",
			RoleARN: *stageRoleOutput.Role.Arn,
		}},
	}
	err = cnf.Validate()
	s.Require().NoError(err)

	awaitHandler := await.NewHandler(cnf, s.session)
	injectHandler := inject.NewHandler(s.session, cnf)

	cliKey := awaitHandler.PromptUser()

	// Clean up S3 stuff
	defer func() {
		pubKey, err := injectCreds.PublicKeyFromCommandLineArg(cliKey)
		s.Require().NoError(err)
		s3Key := injectCreds.PublicKeyAsS3Key(pubKey)
		_, err = s.s3Client.DeleteObject(&s3.DeleteObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(s3Key),
		})
		s.Require().NoError(err)

		_, err = s.s3Client.DeleteBucket(&s3.DeleteBucketInput{
			Bucket: aws.String(bucket),
		})
		s.Require().NoError(err)
	}()

	err = injectHandler.Inject(cliKey)
	s.Require().NoError(err)

	set, reached, err := awaitHandler.Await()
	s.Require().NoError(err)
	s.False(bool(reached))
	s.NotEmpty(set)
}
