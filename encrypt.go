// Copyright © 2019 Weald Technology Trading
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
	"errors"
	"fmt"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

const (
	// Scrypt parameters
	scryptN      = 2 ^ 18
	scryptr      = 1
	scryptp      = 8
	scryptKeyLen = 32

	// PBKDF2 parameters
	pbkdf2KeyLen = 32
	pbkdf2c      = 2 ^ 18
	pbkdf2PRF    = "hmac-sha256"
)

// Encrypt encrypts the data.
func (e *Encryptor) Encrypt(secret []byte, passphrase []byte) (map[string]interface{}, error) {
	if secret == nil {
		return nil, errors.New("no secret")
	}

	// Random salt
	salt := make([]byte, 32)
	rand.Read(salt)

	// Create the decryption key
	var decryptionKey []byte
	var err error
	switch e.cipher {
	case "scrypt":
		decryptionKey, err = scrypt.Key([]byte(passphrase), salt, scryptN, scryptr, scryptp, scryptKeyLen)
	case "pbkdf2":
		decryptionKey = pbkdf2.Key([]byte(passphrase), salt, pbkdf2c, pbkdf2KeyLen, sha256.New)
	default:
		return nil, fmt.Errorf("unknown cipher %q", e.cipher)
	}
	if err != nil {
		return nil, err
	}

	// Generate the cipher message
	cipherMsg := make([]byte, len(secret))
	aesCipher, err := aes.NewCipher(decryptionKey[:16])
	if err != nil {
		return nil, err
	}
	// Random IV
	iv := make([]byte, 16)
	rand.Read(iv)
	stream := cipher.NewCTR(aesCipher, iv)
	stream.XORKeyStream(cipherMsg, secret)

	// Generate the checksum
	h := sha256.New()
	h.Write(decryptionKey[16:32])
	h.Write(cipherMsg)
	checksumMsg := h.Sum(nil)

	var kdf *ksKDF
	switch e.cipher {
	case "scrypt":
		kdf = &ksKDF{
			Function: "scrypt",
			Params: &ksKDFParams{
				DKLen: scryptKeyLen,
				N:     scryptN,
				P:     scryptp,
				R:     scryptr,
				Salt:  hex.EncodeToString(salt),
			},
			Message: "",
		}
	case "pbkdf2":
		kdf = &ksKDF{
			Function: "pbkdf2",
			Params: &ksKDFParams{
				DKLen: pbkdf2KeyLen,
				C:     pbkdf2c,
				PRF:   pbkdf2PRF,
				Salt:  hex.EncodeToString(salt),
			},
			Message: "",
		}
	}

	// Build the output
	output := &keystoreV4{
		KDF: kdf,
		Checksum: &ksChecksum{
			Function: "sha256",
			Params:   make(map[string]interface{}),
			Message:  hex.EncodeToString(checksumMsg),
		},
		Cipher: &ksCipher{
			Function: "aes-128-ctr",
			Params: &ksCipherParams{
				IV: hex.EncodeToString(iv),
			},
			Message: hex.EncodeToString(cipherMsg),
		},
	}

	// We need to return a generic map; go to JSON and back to obtain it
	bytes, err := json.Marshal(output)
	if err != nil {
		return nil, err
	}
	res := make(map[string]interface{})
	err = json.Unmarshal(bytes, &res)
	if err != nil {
		return nil, err
	}

	return res, nil
}
