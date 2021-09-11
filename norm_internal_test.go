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

package keystorev4

import (
	"testing"

	assert "github.com/stretchr/testify/assert"
)

func TestNormPassphrase(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		output string
	}{
		{
			name:   "Empty",
			input:  "",
			output: "",
		},
		{
			name:   "ASCII",
			input:  "passphrase",
			output: "passphrase",
		},
		{
			name:   "Unicode",
			input:  "𝔱𝔢𝔰𝔱𝔭𝔞𝔰𝔰𝔴𝔬𝔯𝔡🔑",
			output: "testpassword🔑",
		},
		{
			name:   "Umlauts",
			input:  "üöüöäöüöü",
			output: "üöüöäöüöü",
		},
		{
			name: "ControlCharacters",
			input: string([]byte{
				0x74, 0x65, 0x73, 0x74,
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
				0x63, 0x6f,
				0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
				0x6e, 0x74,
				0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
				0x72, 0x6f,
				0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
				0x6c, 0x7f,
			}),
			output: "testcontrol",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.output, normPassphrase(test.input))
		})
	}
}

func TestAltNormPassphrase(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		output string
	}{
		{
			name:   "Empty",
			input:  "",
			output: "",
		},
		{
			name:   "ASCII",
			input:  "passphrase",
			output: "passphrase",
		},
		{
			name:   "Unicode",
			input:  "𝔱𝔢𝔰𝔱𝔭𝔞𝔰𝔰𝔴𝔬𝔯𝔡🔑",
			output: "testpassword🔑",
		},
		{
			name:   "Umlauts",
			input:  "üöüöäöüöü",
			output: "uouoaouou",
		},
		{
			name: "ControlCharacters",
			input: string([]byte{
				0x74, 0x65, 0x73, 0x74,
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
				0x63, 0x6f,
				0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
				0x6e, 0x74,
				0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
				0x72, 0x6f,
				0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
				0x6c, 0x7f,
			}),
			output: "testcontrol",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.output, altNormPassphrase(test.input))
		})
	}
}
