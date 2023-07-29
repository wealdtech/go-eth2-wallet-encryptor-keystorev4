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
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/pkg/errors"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

// Decrypt decrypts the data provided, returning the secret.
func (e *Encryptor) Decrypt(input map[string]any, passphrase string) ([]byte, error) {
	if input == nil {
		return nil, errors.New("no data supplied")
	}
	// Marshal the map and unmarshal it back in to a keystore format so we can work with it.
	data, err := json.Marshal(input)
	if err != nil {
		return nil, errors.New("failed to parse keystore")
	}

	ks := &keystoreV4{}
	err = json.Unmarshal(data, &ks)
	if err != nil {
		return nil, errors.New("failed to parse keystore")
	}

	// Checksum and cipher are required.
	if ks.Checksum == nil {
		return nil, errors.New("no checksum")
	}

	if ks.Cipher == nil {
		return nil, errors.New("no cipher")
	}

	normedPassphrase := []byte(normPassphrase(passphrase))
	res, err := decryptNorm(ks, normedPassphrase)
	if err != nil {
		// There is an alternate method to generate a normalised
		// passphrase that can produce different results.  To allow
		// decryption of data that may have been encrypted with the
		// alternate method we attempt to decrypt using that method
		// given the failure of the standard normalised method.
		normedPassphrase = []byte(altNormPassphrase(passphrase))

		res, err = decryptNorm(ks, normedPassphrase)
		if err != nil {
			// No luck either way.
			return nil, err
		}
	}

	return res, nil
}

func decryptNorm(ks *keystoreV4, normedPassphrase []byte) ([]byte, error) {
	decryptionKey, err := obtainDecryptionKey(ks, normedPassphrase)
	if err != nil {
		return nil, err
	}

	cipherMsg, err := hex.DecodeString(ks.Cipher.Message)
	if err != nil {
		return nil, errors.New("invalid cipher message")
	}

	if err := ks.confirmChecksum(cipherMsg, decryptionKey); err != nil {
		return nil, err
	}

	// Decrypt.
	res := make([]byte, len(cipherMsg))

	switch ks.Cipher.Function {
	case cipherAes128Ctr:
		aesCipher, err := aes.NewCipher(decryptionKey[:16])
		if err != nil {
			return nil, errors.Wrap(err, "failed to create AES cipher")
		}

		iv, err := hex.DecodeString(ks.Cipher.Params.IV)
		if err != nil {
			return nil, errors.Wrap(err, "invalid IV")
		}

		stream := cipher.NewCTR(aesCipher, iv)
		stream.XORKeyStream(res, cipherMsg)
	default:
		return nil, fmt.Errorf("unsupported cipher %q", ks.Cipher.Function)
	}

	return res, nil
}

func obtainDecryptionKey(ks *keystoreV4, normedPassphrase []byte) ([]byte, error) {
	// Decryption key.
	var decryptionKey []byte
	if ks.KDF == nil {
		decryptionKey = normedPassphrase
	} else {
		kdfParams := ks.KDF.Params
		salt, err := hex.DecodeString(kdfParams.Salt)
		if err != nil {
			return nil, errors.New("invalid KDF salt")
		}
		switch ks.KDF.Function {
		case algoScrypt:
			decryptionKey, err = scrypt.Key(normedPassphrase, salt, kdfParams.N, kdfParams.R, kdfParams.P, kdfParams.DKLen)
		case algoPbkdf2:
			switch kdfParams.PRF {
			case "hmac-sha256":
				decryptionKey = pbkdf2.Key(normedPassphrase, salt, kdfParams.C, kdfParams.DKLen, sha256.New)
			default:
				return nil, fmt.Errorf("unsupported PBKDF2 PRF %q", kdfParams.PRF)
			}
		default:
			return nil, fmt.Errorf("unsupported KDF %q", ks.KDF.Function)
		}
		if err != nil {
			return nil, errors.New("invalid KDF parameters")
		}
	}

	return decryptionKey, nil
}

func (ks *keystoreV4) confirmChecksum(cipherMsg []byte, decryptionKey []byte) error {
	if len(decryptionKey) < minDecryptionKeySize {
		return fmt.Errorf("decryption key must be at least %d bytes", minDecryptionKeySize)
	}

	hash := sha256.New()
	if _, err := hash.Write(decryptionKey[16:32]); err != nil {
		return errors.Wrap(err, "failed to write hash")
	}

	if _, err := hash.Write(cipherMsg); err != nil {
		return errors.Wrap(err, "failed to write cipher message")
	}

	checksum := hash.Sum(nil)

	checksumMsg, err := hex.DecodeString(ks.Checksum.Message)
	if err != nil {
		return errors.Wrap(err, "invalid checksum message")
	}

	if !bytes.Equal(checksum, checksumMsg) {
		return errors.New("invalid checksum")
	}

	return nil
}
