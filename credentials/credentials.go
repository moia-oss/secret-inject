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
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"

	"golang.org/x/crypto/nacl/box"
	"gopkg.in/yaml.v2"
)

const (
	KeyLen   = 32
	NonceLen = 24
)

type (
	Set struct {
		Stages []Stage `yaml:"stages"`
	}

	Stage struct {
		Name           string         `yaml:"name"`
		RoleARN        string         `yaml:"role-arn"`
		AWSCredentials AWSCredentials `yaml:"aws-credentials"`
		WasExecuted    bool           `yaml:"was-executed"`
	}

	AWSCredentials struct {
		AccessKeyID     string `yaml:"access-key-id"`
		SecretAccessKey string `yaml:"secret-access-key"`
		SessionToken    string `yaml:"session-token"`
	}

	// EncryptedSet contains a public NaCl Box public key.
	// The credential set is encrypted with the private key.
	// At decryption time NaCl implementation will require this public key in addition to the private key, therefore it needs to be part of the message.
	// The nonce is a 24 byte string which is also required to decrypt the ciphertext. In our case it's random data.
	// For a good overall explanation NaCl Box cryptographic abstraction see section 2 in https://cr.yp.to/highspeed/coolnacl-20120725.pdf
	EncryptedSet struct {
		PublicKey              string `yaml:"public-key"`
		Nonce                  string `yaml:"nonce"`
		EncryptedCredentialSet string `yaml:"encrypted-credential-set"`
	}
)

func randomNonce() (*[NonceLen]byte, error) {
	var (
		nonceSlice = make([]byte, NonceLen)
		nonce      [NonceLen]byte
	)

	_, err := io.ReadFull(rand.Reader, nonceSlice)
	if err != nil {
		return nil, fmt.Errorf("failed to get random bytes for nonce: %w", err)
	}

	copy(nonce[:], nonceSlice)

	return &nonce, nil
}

func EncryptedSetFromSet(set Set, peerPubKey *[KeyLen]byte) (EncryptedSet, error) {
	marshaledSet, err := yaml.Marshal(&set)
	if err != nil {
		return EncryptedSet{}, fmt.Errorf("failed to encode credential set as YAML: %w", err)
	}

	pubKey, privKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return EncryptedSet{}, fmt.Errorf("failed to generate encryption keys fro NaCl Box: %w", err)
	}

	nonce, err := randomNonce()
	if err != nil {
		return EncryptedSet{}, err
	}

	var setCiphertext []byte
	setCiphertext = box.Seal(setCiphertext, marshaledSet, nonce, peerPubKey, privKey)

	return EncryptedSet{
		PublicKey:              base64.StdEncoding.EncodeToString(pubKey[:]),
		EncryptedCredentialSet: base64.StdEncoding.EncodeToString(setCiphertext),
		Nonce:                  base64.StdEncoding.EncodeToString(nonce[:]),
	}, nil
}

func SetFromEncryptedSet(encrSet EncryptedSet, privKey *[KeyLen]byte) (Set, error) {
	decodedCiphertext, err := base64.StdEncoding.DecodeString(encrSet.EncryptedCredentialSet)
	if err != nil {
		return Set{}, fmt.Errorf("failed to decode base64 encoded encrypted credential set: %w", err)
	}

	decodedPeerPubKey, err := base64.StdEncoding.DecodeString(encrSet.PublicKey)
	if err != nil {
		return Set{}, fmt.Errorf("failed to decode base64 encoded public key: %w", err)
	}

	decodedNonce, err := base64.StdEncoding.DecodeString(encrSet.Nonce)
	if err != nil {
		return Set{}, fmt.Errorf("failed to decode base64 encoded nonce: %w", err)
	}

	var (
		peerPubKey            [KeyLen]byte
		nonce                 [NonceLen]byte
		decryptedMarshaledSet []byte
		set                   Set
	)

	copy(peerPubKey[:], decodedPeerPubKey)
	copy(nonce[:], decodedNonce)

	decryptedMarshaledSet, ok := box.Open(decryptedMarshaledSet, decodedCiphertext, &nonce, &peerPubKey, privKey)
	if !ok {
		return Set{}, errors.New("error occurred while decrypting encoded credential set")
	}

	err = yaml.Unmarshal(decryptedMarshaledSet, &set)
	if err != nil {
		return Set{}, fmt.Errorf("failed to unmarshal credential set: %w", err)
	}

	return set, nil
}

func Keys() (publicKey, privateKey *[KeyLen]byte, err error) {
	publicKey, privateKey, err = box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate NaCl crypto/box key pair: %w", err)
	}

	return publicKey, privateKey, nil
}

func PublicKeyAsCommandLineArg(publicKey *[KeyLen]byte) string {
	// base64 may begin with "-", this is a problem as it causes the base64 to be interpreted as a flag
	// so we need an arbitrary prefix character to make sure this does not happen
	const cmdLineArgPrefix = "0"

	// 'raw' just means that base64 isn't padded, which is what we'd like here
	// 'urlencoded' makes sure there are no other characters which cause problems for the shell
	return fmt.Sprintf("%s%s", cmdLineArgPrefix, base64.RawURLEncoding.EncodeToString(publicKey[:]))
}

func PublicKeyAsS3Key(publicKey *[KeyLen]byte) string {
	h := sha256.New()

	_, err := h.Write(publicKey[:])
	if err != nil {
		// never returns an error as per docs
		log.Panicf("unexpected error when creating hash for S3 key: %v", err)
	}

	return hex.EncodeToString(h.Sum(nil))
}

func PublicKeyFromCommandLineArg(arg string) (*[KeyLen]byte, error) {
	// the first char is just a random prefix to make sure the key isn't interpreted as a flag
	decodedPubKey, err := base64.RawURLEncoding.DecodeString(arg[1:])
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64: %w", err)
	}

	if len(decodedPubKey) != KeyLen {
		return nil, fmt.Errorf("unexpected length of bytes we got from base64 string: %v. Expected is %v",
			len(decodedPubKey), KeyLen)
	}

	var pubKey [KeyLen]byte

	copy(pubKey[:], decodedPubKey)

	return &pubKey, nil
}

func (s *Set) PersistToDisk(toPath string) error {
	marshaled, err := yaml.Marshal(s)
	if err != nil {
		return fmt.Errorf("failed to marshal credential-set to YAML: %w", err)
	}

	err = ioutil.WriteFile(toPath, marshaled, 0600)
	if err != nil {
		return fmt.Errorf("failed to write credential-set to disk at path %v: %w", toPath, err)
	}

	return nil
}

func LoadCredentialSetFromDisk(fromPath string) (Set, error) {
	var set Set

	f, err := os.Open(fromPath)
	if err != nil {
		return Set{}, fmt.Errorf("failed to open file to read credential-set: %w", err)
	}

	decoder := yaml.NewDecoder(f)

	err = decoder.Decode(&set)
	if err != nil {
		return Set{}, fmt.Errorf("failed to decode credential-set file into unmarshaled YAML: %w", err)
	}

	return set, nil
}
