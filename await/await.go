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
	"fmt"
	"io/ioutil"
	"log"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/client"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"github.com/moia-dev/secret-inject/config"
	"github.com/moia-dev/secret-inject/credentials"
	"gopkg.in/yaml.v2"
)

const pollingInterval = 10 * time.Second
const timeoutDefault = 10 * time.Minute

type Handler struct {
	session    client.ConfigProvider
	conf       config.ApplicationConfig
	publicKey  *[credentials.KeyLen]byte
	privateKey *[credentials.KeyLen]byte
}

func NewHandler(conf config.ApplicationConfig, session client.ConfigProvider) *Handler {
	h := &Handler{
		conf:    conf,
		session: session,
	}

	pubKey, privKey, err := credentials.Keys()
	if err != nil {
		// shouldn't really happen at all
		log.Panicf("unexpectedly failed to generate key pair: %v\n", err)
	}

	h.publicKey, h.privateKey = pubKey, privKey

	return h
}

func (h *Handler) s3Client() s3iface.S3API {
	if h.conf.S3Bucket.AwaitRoleARN != nil {
		s3BucketCreds := stscreds.NewCredentials(h.session, *h.conf.S3Bucket.AwaitRoleARN)

		return s3.New(h.session, &aws.Config{Credentials: s3BucketCreds})
	}

	return s3.New(h.session)
}

func (h *Handler) decodeAndDecryptCredentials(s3Obj []byte) (credentials.Set, error) {
	var encryptedSet credentials.EncryptedSet

	err := yaml.Unmarshal(s3Obj, &encryptedSet)
	if err != nil {
		return credentials.Set{}, fmt.Errorf("failed to unmarshal encrypted credential set YAML: %w", err)
	}

	credSet, err := encryptedSet.Decrypt(h.privateKey)
	if err != nil {
		return credentials.Set{}, err
	}

	return credSet, nil
}

type TimeoutReached bool

func (h *Handler) Await() (credentials.Set, TimeoutReached, error) {
	start := time.Now()
	getObjectInput := &s3.GetObjectInput{
		Bucket: aws.String(h.conf.S3Bucket.BucketName),
		Key:    aws.String(credentials.PublicKeyAsS3Key(h.publicKey)),
	}

	for {
		if time.Since(start) > timeoutDefault {
			fmt.Println("Reached timeout trying to get credentials from S3")

			return credentials.Set{}, true, nil
		}

		obj, err := h.s3Client().GetObject(getObjectInput)
		if err != nil {
			//nolint:errorlint // awserr does not support errors.As
			if aerr, ok := err.(awserr.Error); ok {
				switch aerr.Code() {
				case s3.ErrCodeNoSuchKey: // user hasn't injected yet
					time.Sleep(pollingInterval)

					continue
				default:
					return credentials.Set{}, false, fmt.Errorf("encountered error when polling S3: %w", err)
				}
			} else {
				// Shouldn't happen, as errors from AWS SDK should satisfy awserr.Error
				log.Panicf("Encountered unexpected error when polling S3: %v", err)
			}
		}

		// if payload is very long, something is fishy
		if obj.ContentLength != nil && *obj.ContentLength > 32*1024 {
			return credentials.Set{}, false, fmt.Errorf("unexpectedly long S3 object: %v bytes long", *obj.ContentLength)
		}

		s3Obj, err := ioutil.ReadAll(obj.Body)
		if err != nil {
			return credentials.Set{}, false, fmt.Errorf("failed to read S3 object stream into byte slice: %w", err)
		}

		decryptedCreds, err := h.decodeAndDecryptCredentials(s3Obj)
		if err != nil {
			return credentials.Set{}, false, err
		}

		return decryptedCreds, false, nil
	}
}

func (h *Handler) PromptUser() string {
	return credentials.PublicKeyAsCommandLineArg(h.publicKey)
}

func (h *Handler) NotifyUserIfConfigured() error {
	if h.conf.CommentOnPR {
		return h.CommentOnPR()
	}

	return nil
}
