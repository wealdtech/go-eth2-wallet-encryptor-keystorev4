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
	"testing"

	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
	keystorev4 "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

func TestInterfaces(t *testing.T) {
	encryptor := keystorev4.New()
	require.Implements(t, (*e2wtypes.Encryptor)(nil), encryptor)
}

func TestRoundTrip(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		passphrase string
		secret     []byte
		options    []keystorev4.Option
		err        error
	}{
		{
			name:       "TT",
			input:      `{"checksum":{"function":"sha256","message":"149aafa27b041f3523c53d7acba1905fa6b1c90f9fef137568101f44b531a3cb","params":{}},"cipher":{"function":"aes-128-ctr","message":"54ecc8863c0550351eee5720f3be6a5d4a016025aa91cd6436cfec938d6a8d30","params":{"iv":"264daa3f303d7259501c93d997d84fe6"}},"kdf":{"function":"scrypt","message":"","params":{"dklen":32,"n":262144,"p":1,"r":8,"salt":"d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"}}}`,
			passphrase: "testpassword",
			secret:     []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x19, 0xd6, 0x68, 0x9c, 0x08, 0x5a, 0xe1, 0x65, 0x83, 0x1e, 0x93, 0x4f, 0xf7, 0x63, 0xae, 0x46, 0xa2, 0xa6, 0xc1, 0x72, 0xb3, 0xf1, 0xb6, 0x0a, 0x8c, 0xe2, 0x6f},
		},
		// Spec tests come from https://eips.ethereum.org/EIPS/eip-2335
		{
			name:       "Spec1",
			input:      `{"kdf":{"function":"scrypt","params":{"dklen":32,"n":262144,"p":1,"r":8,"salt":"d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"},"message":""},"checksum":{"function":"sha256","params":{},"message":"d2217fe5f3e9a1e34581ef8a78f7c9928e436d36dacc5e846690a5581e8ea484"},"cipher":{"function":"aes-128-ctr","params":{"iv":"264daa3f303d7259501c93d997d84fe6"},"message":"06ae90d55fe0a6e9c5c3bc5b170827b2e5cce3929ed3f116c2811e6366dfe20f"}}`,
			passphrase: "𝔱𝔢𝔰𝔱𝔭𝔞𝔰𝔰𝔴𝔬𝔯𝔡🔑",
			secret:     []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x19, 0xd6, 0x68, 0x9c, 0x08, 0x5a, 0xe1, 0x65, 0x83, 0x1e, 0x93, 0x4f, 0xf7, 0x63, 0xae, 0x46, 0xa2, 0xa6, 0xc1, 0x72, 0xb3, 0xf1, 0xb6, 0x0a, 0x8c, 0xe2, 0x6f},
		},
		{
			name:       "Spec2",
			input:      `{"kdf":{"function":"pbkdf2","params":{"dklen":32,"c":262144,"prf":"hmac-sha256","salt":"d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"},"message":""},"checksum":{"function":"sha256","params":{},"message":"8a9f5d9912ed7e75ea794bc5a89bca5f193721d30868ade6f73043c6ea6febf1"},"cipher":{"function":"aes-128-ctr","params":{"iv":"264daa3f303d7259501c93d997d84fe6"},"message":"cee03fde2af33149775b7223e7845e4fb2c8ae1792e5f99fe9ecf474cc8c16ad"}}`,
			passphrase: "𝔱𝔢𝔰𝔱𝔭𝔞𝔰𝔰𝔴𝔬𝔯𝔡🔑",
			secret:     []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x19, 0xd6, 0x68, 0x9c, 0x08, 0x5a, 0xe1, 0x65, 0x83, 0x1e, 0x93, 0x4f, 0xf7, 0x63, 0xae, 0x46, 0xa2, 0xa6, 0xc1, 0x72, 0xb3, 0xf1, 0xb6, 0x0a, 0x8c, 0xe2, 0x6f},
		},
		{
			name:       "LowCostScrypt",
			input:      `{"checksum":{"function":"sha256","message":"e4c3c7171f8ff54478868dbf1648dac50c6f38dafe5d9c8dd9f312b812f7fc44","params":{}},"cipher":{"function":"aes-128-ctr","message":"a71e9211932429462d3f6b032a800452651d0cf4517cc0f28c65be57df78f675","params":{"iv":"f68ce93072d0b6c6ca8afbc9b002cd89"}},"kdf":{"function":"scrypt","message":"","params":{"dklen":32,"n":1024,"p":1,"r":8,"salt":"316bd15fbca6d44e543f91762b66a29d2e3f590a9f7a42b9eff1dec48df0075f"}}}`,
			passphrase: "𝔱𝔢𝔰𝔱𝔭𝔞𝔰𝔰𝔴𝔬𝔯𝔡🔑",
			secret:     []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x19, 0xd6, 0x68, 0x9c, 0x08, 0x5a, 0xe1, 0x65, 0x83, 0x1e, 0x93, 0x4f, 0xf7, 0x63, 0xae, 0x46, 0xa2, 0xa6, 0xc1, 0x72, 0xb3, 0xf1, 0xb6, 0x0a, 0x8c, 0xe2, 0x6f},
			options:    []keystorev4.Option{keystorev4.WithCipher("scrypt"), keystorev4.WithCost(t, 10)},
		},
		{
			name:       "LowCostPBKDF2",
			input:      `{"checksum":{"function":"sha256","message":"57dbef6061fe5832064da342e92cac95917ff6d928d278919e3ddb7ae89c05c7","params":{}},"cipher":{"function":"aes-128-ctr","message":"cfe1132d3f0fe4f59d38f5eef01b80be32517448fa65dd0476171324cc3ab5fc","params":{"iv":"5975ccd92bc36290f082f134ec4c52bd"}},"kdf":{"function":"pbkdf2","message":"","params":{"c":1024,"dklen":32,"prf":"hmac-sha256","salt":"700ca70794d861f8f35d733e83c67431c893aa8e83b0dc43b6abd62edf9df0d1"}}}`,
			passphrase: "𝔱𝔢𝔰𝔱𝔭𝔞𝔰𝔰𝔴𝔬𝔯𝔡🔑",
			secret:     []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x19, 0xd6, 0x68, 0x9c, 0x08, 0x5a, 0xe1, 0x65, 0x83, 0x1e, 0x93, 0x4f, 0xf7, 0x63, 0xae, 0x46, 0xa2, 0xa6, 0xc1, 0x72, 0xb3, 0xf1, 0xb6, 0x0a, 0x8c, 0xe2, 0x6f},
			options:    []keystorev4.Option{keystorev4.WithCost(t, 10)},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			encryptor := keystorev4.New(test.options...)
			input := make(map[string]any)
			err := json.Unmarshal([]byte(test.input), &input)
			require.Nil(t, err)
			secret, err := encryptor.Decrypt(input, test.passphrase)
			if test.err != nil {
				require.NotNil(t, err)
				assert.Equal(t, test.err.Error(), err.Error())
			} else {
				require.Nil(t, err)
				require.Equal(t, test.secret, secret)
				newInput, err := encryptor.Encrypt(secret, test.passphrase)
				require.Nil(t, err)
				newSecret, err := encryptor.Decrypt(newInput, test.passphrase)
				require.Nil(t, err)
				require.Equal(t, test.secret, newSecret)
			}
		})
	}
}

func TestNameAndVersion(t *testing.T) {
	encryptor := keystorev4.New()
	assert.Equal(t, "keystore", encryptor.Name())
	assert.Equal(t, uint(4), encryptor.Version())
	assert.Equal(t, "keystorev4", encryptor.String())
}

func TestGenerateKey(t *testing.T) {
	encryptor := keystorev4.New()
	x, err := encryptor.Encrypt([]byte{0x25, 0x29, 0x5f, 0x0d, 0x1d, 0x59, 0x2a, 0x90, 0xb3, 0x33, 0xe2, 0x6e, 0x85, 0x14, 0x97, 0x08, 0x20, 0x8e, 0x9f, 0x8e, 0x8b, 0xc1, 0x8f, 0x6c, 0x77, 0xbd, 0x62, 0xf8, 0xad, 0x7a, 0x68, 0x66}, "")
	require.Nil(t, err)
	assert.NotNil(t, x)
}
