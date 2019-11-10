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

// Encryptor is an encryptor that follows the Ethereum keystore V4 specification.
type Encryptor struct {
	cipher string
}

type ksKDFParams struct {
	// Shared parameters
	Salt  string `json:"salt"`
	DKLen int    `json:"dklen"`
	// Scrypt-specific parameters
	N int `json:"n,omitempty"`
	P int `json:"p,omitempty"`
	R int `json:"r,omitempty"`
	// PBKDF2-specific parameters
	C   int    `json:"c,omitempty"`
	PRF string `json:"prf,omitempty"`
}
type ksKDF struct {
	Function string       `json:"function"`
	Params   *ksKDFParams `json:"params"`
	Message  string       `json:"message"`
}
type ksChecksum struct {
	Function string                 `json:"function"`
	Params   map[string]interface{} `json:"params"`
	Message  string                 `json:"message"`
}
type ksCipherParams struct {
	// AES-128-CTR-specific parameters
	IV string `json:"iv,omitempty"`
}
type ksCipher struct {
	Function string          `json:"function"`
	Params   *ksCipherParams `json:"params"`
	Message  string          `json:"message"`
}
type keystoreV4 struct {
	KDF      *ksKDF      `json:"kdf"`
	Checksum *ksChecksum `json:"checksum"`
	Cipher   *ksCipher   `json:"cipher"`
}

const (
	name    = "keystore"
	version = 4
)

// options are the options for the keystore encryptor.
type options struct {
	cipher string
}

// Option gives options to New
type Option interface {
	apply(*options)
}

type optionFunc func(*options)

func (f optionFunc) apply(o *options) {
	f(o)
}

// WithCipher sets the cipher for the encryptor.
func WithCipher(cipher string) Option {
	return optionFunc(func(o *options) {
		o.cipher = cipher
	})
}

// New creates a new keystore V4 encryptor.
// This takes the following options:
// - cipher: the cipher to use when encrypting the secret, can be either "pbkdf2" (default) or "scrypt"
func New(opts ...Option) *Encryptor {
	options := options{
		cipher: "pbkdf2",
	}
	for _, o := range opts {
		o.apply(&options)
	}

	return &Encryptor{
		cipher: options.cipher,
	}
}

// Name returns the name of this encryptor
func (e *Encryptor) Name() string {
	return name
}

// Version returns the version of this encryptor
func (e *Encryptor) Version() uint {
	return version
}
