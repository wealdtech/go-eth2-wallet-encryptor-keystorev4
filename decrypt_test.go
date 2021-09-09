// Copyright © 2019-2021 Weald Technology Trading
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
	"testing"

	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
	keystorev4 "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4"
)

func TestDecrypt(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		passphrase string
		output     []byte
		err        string
	}{
		{
			name:       "NoCipher",
			input:      `{"checksum":{"function":"SHA256","message":"cb27fe860c96f269f7838525ba8dce0886e0b7753caccc14162195bcdacbf49e","params":{}},"kdf":{"function":"scrypt","message":"","params":{"dklen":32,"n":262144,"p":8,"r":1,"salt":"ab0c7876052600dd703518d6fc3fe8984592145b591fc8fb5c6d43190334ba19"}}}`,
			passphrase: "testpassword",
			err:        "no cipher",
		},
		{
			name:       "ShortPassphrase",
			input:      `{"checksum":{"function":"SHA256","message":"cb27fe860c96f269f7838525ba8dce0886e0b7753caccc14162195bcdacbf49e","params":{}},"cipher":{"function":"aes-128-ctr","message":"e18afad793ec8dc3263169c07add77515d9f301464a05508d7ecb42ced24ed3a","params":{"iv":"b29d49568661b61e92352e3bb36038d9"}}}`,
			passphrase: "testpassword",
			err:        "decryption key must be at least 32 bytes",
		},
		{
			name:       "BadSalt",
			input:      `{"checksum":{"function":"sha256","message":"9ca5a58a8a8d7a62c3bd890c51ab3169bcfd7f154947458ac4f2950b059b6b38","params":{}},"cipher":{"function":"aes-128-ctr","message":"12edd28c7290896ea24ecda9066f34a70dbab972d8d975f5727f938ba5a8641f","params":{"iv":"b29d49568661b61e92352e3bb36038d9"}},"kdf":{"function":"pbkdf2","message":"","params":{"c":262144,"dklen":32,"prf":"hmac-sha256","salt":"hbd90262ceea3018400076177f5bc55b6e185d5e63361bebdda4a2f7a2066caadc"}}}`,
			passphrase: "testpassword",
			err:        "invalid KDF salt",
		},
		{
			name:       "BadPRF",
			input:      `{"checksum":{"function":"sha256","message":"9ca5a58a8a8d7a62c3bd890c51ab3169bcfd7f154947458ac4f2950b059b6b38","params":{}},"cipher":{"function":"aes-128-ctr","message":"12edd28c7290896ea24ecda9066f34a70dbab972d8d975f5727f938ba5a8641f","params":{"iv":"b29d49568661b61e92352e3bb36038d9"}},"kdf":{"function":"pbkdf2","message":"","params":{"c":262144,"dklen":32,"prf":"hmac-sha128","salt":"d90262ceea3018400076177f5bc55b6e185d5e63361bebdda4a2f7a2066caadc"}}}`,
			passphrase: "testpassword",
			err:        `unsupported PBKDF2 PRF "hmac-sha128"`,
		},
		{
			name:       "BadKDF",
			input:      `{"checksum":{"sha256":"magic","message":"9ca5a58a8a8d7a62c3bd890c51ab3169bcfd7f154947458ac4f2950b059b6b38","params":{}},"cipher":{"function":"aes-128-ctr","message":"12edd28c7290896ea24ecda9066f34a70dbab972d8d975f5727f938ba5a8641f","params":{"iv":"b29d49568661b61e92352e3bb36038d9"}},"kdf":{"function":"magic","message":"","params":{"c":262144,"dklen":32,"prf":"hmac-sha256","salt":"d90262ceea3018400076177f5bc55b6e185d5e63361bebdda4a2f7a2066caadc"}}}`,
			passphrase: "testpassword",
			err:        `unsupported KDF "magic"`,
		},
		{
			name:       "InvalidScryptParams",
			input:      `{"checksum":{"function":"SHA256","message":"cb27fe860c96f269f7838525ba8dce0886e0b7753caccc14162195bcdacbf49e","params":{}},"cipher":{"function":"aes-128-ctr","message":"e18afad793ec8dc3263169c07add77515d9f301464a05508d7ecb42ced24ed3a","params":{"iv":"b29d49568661b61e92352e3bb36038d9"}},"kdf":{"function":"scrypt","message":"","params":{"dklen":0,"n":3,"p":-4,"r":1,"salt":"ab0c7876052600dd703518d6fc3fe8984592145b591fc8fb5c6d43190334ba19"}}}`,
			passphrase: "testpassword",
			err:        "invalid KDF parameters",
		},
		{
			name:       "BadCipherMessage",
			input:      `{"checksum":{"function":"sha256","message":"9ca5a58a8a8d7a62c3bd890c51ab3169bcfd7f154947458ac4f2950b059b6b38","params":{}},"cipher":{"function":"aes-128-ctr","message":"h12edd28c7290896ea24ecda9066f34a70dbab972d8d975f5727f938ba5a8641f","params":{"iv":"b29d49568661b61e92352e3bb36038d9"}},"kdf":{"function":"pbkdf2","message":"","params":{"c":262144,"dklen":32,"prf":"hmac-sha256","salt":"d90262ceea3018400076177f5bc55b6e185d5e63361bebdda4a2f7a2066caadc"}}}`,
			passphrase: "testpassword",
			err:        "invalid cipher message",
		},
		{
			name:       "BadChecksumMessage",
			input:      `{"checksum":{"function":"sha256","message":"hb9ca5a58a8a8d7a62c3bd890c51ab3169bcfd7f154947458ac4f2950b059b6b38","params":{}},"cipher":{"function":"aes-128-ctr","message":"12edd28c7290896ea24ecda9066f34a70dbab972d8d975f5727f938ba5a8641f","params":{"iv":"b29d49568661b61e92352e3bb36038d9"}},"kdf":{"function":"pbkdf2","message":"","params":{"c":262144,"dklen":32,"prf":"hmac-sha256","salt":"d90262ceea3018400076177f5bc55b6e185d5e63361bebdda4a2f7a2066caadc"}}}`,
			passphrase: "testpassword",
			err:        "invalid checksum message",
		},
		{
			name:       "InvalidChecksum",
			input:      `{"checksum":{"function":"sha256","message":"0ca5a58a8a8d7a62c3bd890c51ab3169bcfd7f154947458ac4f2950b059b6b38","params":{}},"cipher":{"function":"aes-128-ctr","message":"12edd28c7290896ea24ecda9066f34a70dbab972d8d975f5727f938ba5a8641f","params":{"iv":"b29d49568661b61e92352e3bb36038d9"}},"kdf":{"function":"pbkdf2","message":"","params":{"c":262144,"dklen":32,"prf":"hmac-sha256","salt":"d90262ceea3018400076177f5bc55b6e185d5e63361bebdda4a2f7a2066caadc"}}}`,
			passphrase: "testpassword",
			err:        "invalid checksum",
		},
		{
			name:       "BadIV",
			input:      `{"checksum":{"function":"sha256","message":"9ca5a58a8a8d7a62c3bd890c51ab3169bcfd7f154947458ac4f2950b059b6b38","params":{}},"cipher":{"function":"aes-128-ctr","message":"12edd28c7290896ea24ecda9066f34a70dbab972d8d975f5727f938ba5a8641f","params":{"iv":"h29d49568661b61e92352e3bb36038d9"}},"kdf":{"function":"pbkdf2","message":"","params":{"c":262144,"dklen":32,"prf":"hmac-sha256","salt":"d90262ceea3018400076177f5bc55b6e185d5e63361bebdda4a2f7a2066caadc"}}}`,
			passphrase: "testpassword",
			err:        "invalid IV",
		},
		{
			name:       "BadCipher",
			input:      `{"checksum":{"function":"sha256","message":"9ca5a58a8a8d7a62c3bd890c51ab3169bcfd7f154947458ac4f2950b059b6b38","params":{}},"cipher":{"function":"aes-64-ctr","message":"12edd28c7290896ea24ecda9066f34a70dbab972d8d975f5727f938ba5a8641f","params":{"iv":"b29d49568661b61e92352e3bb36038d9"}},"kdf":{"function":"pbkdf2","message":"","params":{"c":262144,"dklen":32,"prf":"hmac-sha256","salt":"d90262ceea3018400076177f5bc55b6e185d5e63361bebdda4a2f7a2066caadc"}}}`,
			passphrase: "testpassword",
			err:        `unsupported cipher "aes-64-ctr"`,
		},
		{
			name:       "InvalidCipher",
			input:      `{"checksum":{"function":"sha256","message":"9ca5a58a8a8d7a62c3bd890c51ab3169bcfd7f154947458ac4f2950b059b6b38","params":{}},"cipher":{"function":"xor","message":"12edd28c7290896ea24ecda9066f34a70dbab972d8d975f5727f938ba5a8641f","params":{"iv":"b29d49568661b61e92352e3bb36038d9"}},"kdf":{"function":"pbkdf2","message":"","params":{"c":262144,"dklen":32,"prf":"hmac-sha256","salt":"d90262ceea3018400076177f5bc55b6e185d5e63361bebdda4a2f7a2066caadc"}}}`,
			passphrase: "testpassword",
			err:        `unsupported cipher "xor"`,
		},
		{
			name:       "Good",
			input:      `{"checksum":{"function":"sha256","message":"9ca5a58a8a8d7a62c3bd890c51ab3169bcfd7f154947458ac4f2950b059b6b38","params":{}},"cipher":{"function":"aes-128-ctr","message":"12edd28c7290896ea24ecda9066f34a70dbab972d8d975f5727f938ba5a8641f","params":{"iv":"b29d49568661b61e92352e3bb36038d9"}},"kdf":{"function":"pbkdf2","message":"","params":{"c":262144,"dklen":32,"prf":"hmac-sha256","salt":"d90262ceea3018400076177f5bc55b6e185d5e63361bebdda4a2f7a2066caadc"}}}`,
			passphrase: "testpassword",
			output:     []byte{0x11, 0xdd, 0xc, 0x87, 0xfe, 0xf7, 0x48, 0xdc, 0x7, 0xee, 0xb7, 0xe, 0xd, 0xe5, 0xdc, 0x94, 0x4c, 0xd4, 0xd5, 0xbe, 0x86, 0x4e, 0xc, 0x40, 0x35, 0x26, 0xf2, 0xfd, 0x34, 0x61, 0xa8, 0x3e},
		},
		{
			name:       "GoodNorm",
			input:      `{"checksum":{"function":"sha256","message":"3e1d45e3e47bcb2406ab25b6119225c85e7b2276b0834c7203a125bd7b6ca34f","params":{}},"cipher":{"function":"aes-128-ctr","message":"0ed64a392274f7fcc76f8cf4d22f86057c42e6c6b726cc19dc64e80ebab5d1dd","params":{"iv":"ff6cc499ff4bbfca0125700b29cfa4dc"}},"kdf":{"function":"pbkdf2","message":"","params":{"c":262144,"dklen":32,"prf":"hmac-sha256","salt":"70f3ebd9776781f46c2ead400a3a9ed7ad2880871fe9422a734303d1492f2477"}}}`,
			passphrase: "testpasswordü",
			output:     []byte{0x3f, 0xa3, 0xc2, 0xa1, 0xc9, 0xf5, 0xe6, 0xb3, 0x5b, 0x22, 0x3b, 0x8e, 0x84, 0xcc, 0xb3, 0x94, 0x83, 0x77, 0x20, 0xa7, 0x12, 0xbb, 0xd1, 0xdc, 0xdd, 0xcf, 0xeb, 0x78, 0xa2, 0x98, 0xd0, 0x63},
		},
		{
			name:       "GoodAltNorm",
			input:      `{"checksum":{"function":"sha256","message":"5bbf87c004da9b7f39f9374725c1ae89e15a52306a4d0a73654769ecb39341ed","params":{}},"cipher":{"function":"aes-128-ctr","message":"e3f3ef7027c3ddf579c7a88001ea2fcb17f850dcc8198c3f3ba0610a70a293a0","params":{"iv":"f0855894642fecdcce1696a50a2c0e4e"}},"kdf":{"function":"pbkdf2","message":"","params":{"c":262144,"dklen":32,"prf":"hmac-sha256","salt":"454932cffe9fbc0767c46280663550df4bf64205bfe9f3a359012f21dd9c30bb"}}}`,
			passphrase: "testpasswordü",
			output:     []byte{0x3f, 0xa3, 0xc2, 0xa1, 0xc9, 0xf5, 0xe6, 0xb3, 0x5b, 0x22, 0x3b, 0x8e, 0x84, 0xcc, 0xb3, 0x94, 0x83, 0x77, 0x20, 0xa7, 0x12, 0xbb, 0xd1, 0xdc, 0xdd, 0xcf, 0xeb, 0x78, 0xa2, 0x98, 0xd0, 0x63},
		},
		{
			name: "SCrypt",
			input: `{"checksum":{"function":"sha256","message":"a230c7d50dc1e141433559a12cedbe2db2014012b7d5bcda08f399d06ec9bd87","params":{}},"cipher":{"function":"aes-128-ctr","message":"5263382e2ae83dd06020baac533e0173f195be6726f362a683de885c0bdc8e0cec93a411ebc10dfccf8408e23a0072fadc581ab1fcd7a54faae8d2db0680fa76","params":{"iv":"c6437d26eb11abafd373bfb470fd0ad4"}},"kdf":{"function":"scrypt","message":"","params":{"dklen":32,"n":16,"p":8,"r":1,"salt":"20c085c4048f5592cc36bb2a6aa16f0d887f4eb4110849830ceb1eb2dfc0d1be"}}}
`,
			passphrase: "wallet passphrase",
			output: []byte{
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
				0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
				0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
				0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			encryptor := keystorev4.New()
			input := make(map[string]interface{})
			err := json.Unmarshal([]byte(test.input), &input)
			require.Nil(t, err)
			output, err := encryptor.Decrypt(input, test.passphrase)
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.Nil(t, err)
				assert.Equal(t, test.output, output)
			}
		})
	}
}

func TestDecryptBadInput(t *testing.T) {
	tests := []struct {
		name  string
		input map[string]interface{}
		err   string
	}{
		{
			name: "Nil",
			err:  "no data supplied",
		},
		{
			name:  "Empty",
			input: map[string]interface{}{},
			err:   "no checksum",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			encryptor := keystorev4.New()
			_, err := encryptor.Decrypt(test.input, "irrelevant")
			require.EqualError(t, err, test.err)
		})
	}
}
