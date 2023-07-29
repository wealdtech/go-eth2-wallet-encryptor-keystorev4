// Copyright © 2019 - 2023 Weald Technology Trading.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and

package keystorev4

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/pkg/errors"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

const (
	// Algorithms.
	algoScrypt = "scrypt"
	algoPbkdf2 = "pbkdf2"

	// Scrypt parameters.
	scryptr      = 8
	scryptp      = 1
	scryptKeyLen = 32

	// PBKDF2 parameters.
	pbkdf2KeyLen = 32
	pbkdf2PRF    = "hmac-sha256"

	// Ciphers.
	cipherAes128Ctr = "aes-128-ctr"

	// Misc constants.
	saltSize             = 32
	ivSize               = 16
	minDecryptionKeySize = 32
)

// Encrypt encrypts data.
func (e *Encryptor) Encrypt(secret []byte, passphrase string) (map[string]any, error) {
	if secret == nil {
		return nil, errors.New("no secret")
	}

	// Random salt.
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, errors.Wrap(err, "failed to obtain random salt")
	}

	normedPassphrase := []byte(normPassphrase(passphrase))

	decryptionKey, err := e.generateDecryptionKey(salt, normedPassphrase)
	if err != nil {
		return nil, err
	}

	// Generate the cipher message.
	cipherMsg := make([]byte, len(secret))

	aesCipher, err := aes.NewCipher(decryptionKey[:minDecryptionKeySize/2])
	if err != nil {
		return nil, errors.Wrap(err, "failed to create cipher")
	}

	// Random IV.
	iv := make([]byte, ivSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, errors.Wrap(err, "failed to obtain initialization vector")
	}
	stream := cipher.NewCTR(aesCipher, iv)
	stream.XORKeyStream(cipherMsg, secret)

	// Generate the checksum.
	hash := sha256.New()
	if _, err := hash.Write(decryptionKey[minDecryptionKeySize/2 : minDecryptionKeySize]); err != nil {
		return nil, errors.Wrap(err, "failed to write hash")
	}
	if _, err := hash.Write(cipherMsg); err != nil {
		return nil, errors.Wrap(err, "failed to write cipher message")
	}
	checksumMsg := hash.Sum(nil)

	kdf := e.buildKDF(salt)

	res, err := buildEncryptOutput(kdf, iv, checksumMsg, cipherMsg)
	if err != nil {
		return nil, err
	}

	return res, nil
}

func (e *Encryptor) generateDecryptionKey(salt []byte, normedPassphrase []byte) ([]byte, error) {
	var decryptionKey []byte
	var err error

	switch e.cipher {
	case algoScrypt:
		decryptionKey, err = scrypt.Key(normedPassphrase, salt, e.cost, scryptr, scryptp, scryptKeyLen)
	case algoPbkdf2:
		decryptionKey = pbkdf2.Key(normedPassphrase, salt, e.cost, pbkdf2KeyLen, sha256.New)
	default:
		return nil, fmt.Errorf("unknown cipher %q", e.cipher)
	}
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain decryption key")
	}

	return decryptionKey, nil
}

func (e *Encryptor) buildKDF(salt []byte) *ksKDF {
	var kdf *ksKDF
	switch e.cipher {
	case algoScrypt:
		kdf = &ksKDF{
			Function: algoScrypt,
			Params: &ksKDFParams{
				DKLen: scryptKeyLen,
				N:     e.cost,
				P:     scryptp,
				R:     scryptr,
				Salt:  hex.EncodeToString(salt),
			},
			Message: "",
		}
	case algoPbkdf2:
		kdf = &ksKDF{
			Function: algoPbkdf2,
			Params: &ksKDFParams{
				DKLen: pbkdf2KeyLen,
				C:     e.cost,
				PRF:   pbkdf2PRF,
				Salt:  hex.EncodeToString(salt),
			},
			Message: "",
		}
	}

	return kdf
}

func buildEncryptOutput(kdf *ksKDF, iv []byte, checksumMsg []byte, cipherMsg []byte) (map[string]any, error) {
	output := &keystoreV4{
		KDF: kdf,
		Checksum: &ksChecksum{
			Function: "sha256",
			Params:   make(map[string]any),
			Message:  hex.EncodeToString(checksumMsg),
		},
		Cipher: &ksCipher{
			Function: cipherAes128Ctr,
			Params: &ksCipherParams{
				IV: hex.EncodeToString(iv),
			},
			Message: hex.EncodeToString(cipherMsg),
		},
	}

	// We need to return a generic map; go to JSON and back to obtain it.
	bytes, err := json.Marshal(output)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal JSON")
	}
	res := make(map[string]any)
	err = json.Unmarshal(bytes, &res)
	if err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal JSON")
	}

	return res, nil
}
