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
		secret     []byte
		passphrase []byte
		err        error
	}{
		{
			name:       "Nil",
			cipher:     "pbkdf2",
			secret:     nil,
			passphrase: []byte(""),
			err:        errors.New("no secret"),
		},
		{
			name:       "EmptyPBKDF2",
			cipher:     "pbkdf2",
			secret:     []byte(""),
			passphrase: []byte(""),
		},
		{
			name:       "EmptyScrypt",
			cipher:     "scrypt",
			secret:     []byte(""),
			passphrase: []byte(""),
		},
		{
			name:       "UnknownCipher",
			cipher:     "unknown",
			secret:     []byte(""),
			passphrase: []byte(""),
			err:        errors.New(`unknown cipher "unknown"`),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			encryptor := keystorev4.New(keystorev4.WithCipher(test.cipher))
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
