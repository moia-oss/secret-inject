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
package credentials

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCredentialsCryptoFlow(t *testing.T) {
	pubKey, privateKey, err := Keys()
	require.NoError(t, err)

	originalSet := Set{
		Stages: []Stage{{
			Name:    "poc",
			RoleARN: "someARN",
			AWSCredentials: AWSCredentials{
				AccessKeyID:     "lorem",
				SecretAccessKey: "ipsum",
				SessionToken:    "dolor",
			},
		}},
	}

	encrSet, err := originalSet.Encrypt(pubKey)
	require.NoError(t, err)

	decryptedSet, err := encrSet.Decrypt(privateKey)
	require.NoError(t, err)

	assert.Equal(t, originalSet, decryptedSet)
}
