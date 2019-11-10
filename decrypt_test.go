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
// limitations under the License.

package keystorev4_test

import (
	"encoding/json"
	"errors"
	"testing"

	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
	keystorev4 "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4"
)

func TestDecrypt(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		passphrase []byte
		output     []byte
		err        error
	}{
		{
			name:  "Empty",
			input: "",
			err:   errors.New("no checksum"),
		},
		{
			name:       "NoCipher",
			input:      `{"checksum":{"function":"SHA256","message":"cb27fe860c96f269f7838525ba8dce0886e0b7753caccc14162195bcdacbf49e","params":{}},"kdf":{"function":"scrypt","message":"","params":{"dklen":32,"n":262144,"p":8,"r":1,"salt":"ab0c7876052600dd703518d6fc3fe8984592145b591fc8fb5c6d43190334ba19"}}}`,
			passphrase: []byte("testpassword"),
			err:        errors.New("no cipher"),
		},
		{
			name:       "ShortPassphrase",
			input:      `{"checksum":{"function":"SHA256","message":"cb27fe860c96f269f7838525ba8dce0886e0b7753caccc14162195bcdacbf49e","params":{}},"cipher":{"function":"xor","message":"e18afad793ec8dc3263169c07add77515d9f301464a05508d7ecb42ced24ed3a","params":{}}}`,
			passphrase: []byte("testpassword"),
			err:        errors.New("decryption key must be at least 32 bytes"),
		},
		{
			name:       "BadSalt",
			input:      `{"checksum":{"function":"SHA256","message":"cb27fe860c96f269f7838525ba8dce0886e0b7753caccc14162195bcdacbf49e","params":{}},"cipher":{"function":"xor","message":"e18afad793ec8dc3263169c07add77515d9f301464a05508d7ecb42ced24ed3a","params":{}},"kdf":{"function":"scrypt","message":"","params":{"dklen":32,"n":262144,"p":8,"r":1,"salt":"hb0c7876052600dd703518d6fc3fe8984592145b591fc8fb5c6d43190334ba19"}}}`,
			passphrase: []byte("testpassword"),
			err:        errors.New("invalid KDF salt"),
		},
		{
			name:       "BadPRF",
			input:      `{"kdf":{"function":"pbkdf2","params":{"dklen":32,"c":262144,"prf":"hmac-sha128","salt":"d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"},"message":""},"checksum":{"function":"sha256","params":{},"message":"18b148af8e52920318084560fd766f9d09587b4915258dec0676cba5b0da09d8"},"cipher":{"function":"aes-128-ctr","params":{"iv":"264daa3f303d7259501c93d997d84fe6"},"message": "a9249e0ca7315836356e4c7440361ff22b9fe71e2e2ed34fc1eb03976924ed48"}}`,
			passphrase: []byte("testpassword"),
			err:        errors.New(`unsupported PBKDF2 PRF "hmac-sha128"`),
		},
		{
			name:       "BadKDF",
			input:      `{"kdf":{"function":"magic","params":{"dklen":32,"c":262144,"prf":"hmac-sha128","salt":"d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"},"message":""},"checksum":{"function":"sha256","params":{},"message":"18b148af8e52920318084560fd766f9d09587b4915258dec0676cba5b0da09d8"},"cipher":{"function":"aes-128-ctr","params":{"iv":"264daa3f303d7259501c93d997d84fe6"},"message": "a9249e0ca7315836356e4c7440361ff22b9fe71e2e2ed34fc1eb03976924ed48"}}`,
			passphrase: []byte("testpassword"),
			err:        errors.New(`unsupported KDF "magic"`),
		},
		{
			name:       "InvalidScryptParams",
			input:      `{"checksum":{"function":"SHA256","message":"cb27fe860c96f269f7838525ba8dce0886e0b7753caccc14162195bcdacbf49e","params":{}},"cipher":{"function":"xor","message":"e18afad793ec8dc3263169c07add77515d9f301464a05508d7ecb42ced24ed3a","params":{}},"kdf":{"function":"scrypt","message":"","params":{"dklen":0,"n":3,"p":-4,"r":1,"salt":"ab0c7876052600dd703518d6fc3fe8984592145b591fc8fb5c6d43190334ba19"}}}`,
			passphrase: []byte("testpassword"),
			err:        errors.New("invalid KDF parameters"),
		},
		{
			name:       "BadCipherMessage",
			input:      `{"checksum":{"function":"SHA256","message":"cb27fe860c96f269f7838525ba8dce0886e0b7753caccc14162195bcdacbf49e","params":{}},"cipher":{"function":"xor","message":"h18afad793ec8dc3263169c07add77515d9f301464a05508d7ecb42ced24ed3a","params":{}},"kdf":{"function":"scrypt","message":"","params":{"dklen":32,"n":262144,"p":8,"r":1,"salt":"ab0c7876052600dd703518d6fc3fe8984592145b591fc8fb5c6d43190334ba19"}}}`,
			passphrase: []byte("testpassword"),
			err:        errors.New("invalid cipher message"),
		},
		{
			name:       "BadChecksumMessage",
			input:      `{"checksum":{"function":"SHA256","message":"hb27fe860c96f269f7838525ba8dce0886e0b7753caccc14162195bcdacbf49e","params":{}},"cipher":{"function":"xor","message":"e18afad793ec8dc3263169c07add77515d9f301464a05508d7ecb42ced24ed3a","params":{}},"kdf":{"function":"scrypt","message":"","params":{"dklen":32,"n":262144,"p":8,"r":1,"salt":"ab0c7876052600dd703518d6fc3fe8984592145b591fc8fb5c6d43190334ba19"}}}`,
			passphrase: []byte("testpassword"),
			err:        errors.New("invalid checksum message"),
		},
		{
			name:       "InvalidChecksum",
			input:      `{"checksum":{"function":"SHA256","message":"db27fe860c96f269f7838525ba8dce0886e0b7753caccc14162195bcdacbf49e","params":{}},"cipher":{"function":"xor","message":"e18afad793ec8dc3263169c07add77515d9f301464a05508d7ecb42ced24ed3a","params":{}},"kdf":{"function":"scrypt","message":"","params":{"dklen":32,"n":262144,"p":8,"r":1,"salt":"ab0c7876052600dd703518d6fc3fe8984592145b591fc8fb5c6d43190334ba19"}}}`,
			passphrase: []byte("testpassword"),
			err:        errors.New("invalid checksum"),
		},
		{
			name:       "BadIV",
			input:      `{"checksum":{"function":"SHA256","message":"cb27fe860c96f269f7838525ba8dce0886e0b7753caccc14162195bcdacbf49e","params":{}},"cipher":{"function":"xor","message":"e18afad793ec8dc3263169c07add77515d9f301464a05508d7ecb42ced24ed3a","params":{}},"kdf":{"function":"scrypt","message":"","params":{"dklen":32,"n":262144,"p":8,"r":1,"salt":"ab0c7876052600dd703518d6fc3fe8984592145b591fc8fb5c6d43190334ba19"}}}`,
			passphrase: []byte("testpassword"),
			output:     []byte{0x1b, 0x4b, 0x68, 0x19, 0x26, 0x11, 0xfa, 0xea, 0x20, 0x8f, 0xca, 0x21, 0x62, 0x7b, 0xe9, 0xda, 0xe6, 0xc3, 0xf2, 0x56, 0x4d, 0x42, 0x58, 0x8f, 0xb1, 0x11, 0x9d, 0xae, 0x7c, 0x9f, 0x4b, 0x87},
		},
		{
			name:       "BadIV",
			input:      `{"kdf":{"function":"pbkdf2","params":{"dklen":32,"c":262144,"prf":"hmac-sha256","salt":"d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"},"message":""},"checksum":{"function":"sha256","params":{},"message":"18b148af8e52920318084560fd766f9d09587b4915258dec0676cba5b0da09d8"},"cipher":{"function":"aes-128-ctr","params":{"iv":"h64daa3f303d7259501c93d997d84fe6"},"message": "a9249e0ca7315836356e4c7440361ff22b9fe71e2e2ed34fc1eb03976924ed48"}}`,
			passphrase: []byte("testpassword"),
			err:        errors.New("invalid IV"),
		},
		{
			name:       "BadCipher",
			input:      `{"kdf":{"function":"pbkdf2","params":{"dklen":32,"c":262144,"prf":"hmac-sha256","salt":"d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"},"message":""},"checksum":{"function":"sha256","params":{},"message":"18b148af8e52920318084560fd766f9d09587b4915258dec0676cba5b0da09d8"},"cipher":{"function":"aes-64-ctr","params":{"iv":"264daa3f303d7259501c93d997d84fe6"},"message": "a9249e0ca7315836356e4c7440361ff22b9fe71e2e2ed34fc1eb03976924ed48"}}`,
			passphrase: []byte("testpassword"),
			err:        errors.New(`unsupported cipher "aes-64-ctr"`),
		},
		{
			name:       "Good",
			input:      `{"checksum":{"function":"SHA256","message":"cb27fe860c96f269f7838525ba8dce0886e0b7753caccc14162195bcdacbf49e","params":{}},"cipher":{"function":"xor","message":"e18afad793ec8dc3263169c07add77515d9f301464a05508d7ecb42ced24ed3a","params":{}},"kdf":{"function":"scrypt","message":"","params":{"dklen":32,"n":262144,"p":8,"r":1,"salt":"ab0c7876052600dd703518d6fc3fe8984592145b591fc8fb5c6d43190334ba19"}}}`,
			passphrase: []byte("testpassword"),
			output:     []byte{0x1b, 0x4b, 0x68, 0x19, 0x26, 0x11, 0xfa, 0xea, 0x20, 0x8f, 0xca, 0x21, 0x62, 0x7b, 0xe9, 0xda, 0xe6, 0xc3, 0xf2, 0x56, 0x4d, 0x42, 0x58, 0x8f, 0xb1, 0x11, 0x9d, 0xae, 0x7c, 0x9f, 0x4b, 0x87},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			encryptor := keystorev4.New()
			input := make(map[string]interface{})
			json.Unmarshal([]byte(test.input), &input)
			output, err := encryptor.Decrypt(input, test.passphrase)
			if test.err != nil {
				require.NotNil(t, err)
				assert.Equal(t, test.err.Error(), err.Error())
			} else {
				require.Nil(t, err)
				assert.Equal(t, test.output, output)
			}
		})
	}
}
