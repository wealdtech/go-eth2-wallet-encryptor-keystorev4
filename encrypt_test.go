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
	"errors"
	"testing"

	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
	keystorev4 "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4"
)

func TestEncrypt(t *testing.T) {
	tests := []struct {
		name       string
		cipher     string
		costPower  uint
		secret     []byte
		passphrase string
		err        error
	}{
		{
			name:       "Nil",
			cipher:     "pbkdf2",
			secret:     nil,
			passphrase: "",
			err:        errors.New("no secret"),
		},
		{
			name:       "EmptyPBKDF2",
			cipher:     "pbkdf2",
			secret:     []byte(""),
			passphrase: "",
		},
		{
			name:       "EmptyScrypt",
			cipher:     "scrypt",
			secret:     []byte(""),
			passphrase: "",
		},
		{
			name:       "UnknownCipher",
			cipher:     "unknown",
			secret:     []byte(""),
			passphrase: "",
			err:        errors.New(`unknown cipher "unknown"`),
		},
		{
			name:      "Good",
			cipher:    "pbkdf2",
			costPower: 10,
			secret: []byte{
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
				0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
				0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
				0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
			},
			passphrase: "wallet passphrase",
		},
		{
			name:       "LowCostScrypt",
			cipher:     "scrypt",
			costPower:  10,
			secret:     []byte(""),
			passphrase: "",
		},
		{
			name:       "LowCostPBKDF2",
			cipher:     "pbkdf2",
			costPower:  10,
			secret:     []byte(""),
			passphrase: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var options []keystorev4.Option
			if test.cipher != "" {
				options = append(options, keystorev4.WithCipher(test.cipher))
			}
			if test.costPower != 0 {
				options = append(options, keystorev4.WithCost(t, test.costPower))
			}

			encryptor := keystorev4.New(options...)
			_, err := encryptor.Encrypt(test.secret, test.passphrase)
			if test.err != nil {
				require.NotNil(t, err)
				assert.Equal(t, test.err.Error(), err.Error())
			} else {
				require.Nil(t, err)
			}
		})
	}
}

func TestWithCostPanic(t *testing.T) {
	require.Panics(t, func() {
		keystorev4.WithCost(nil, 1)
	})
}
