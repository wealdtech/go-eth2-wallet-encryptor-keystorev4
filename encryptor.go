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
	"fmt"
	"testing"
)

const (
	// defaultCostPower is the power to which to raise 2 to obtain the difficulty of the encryption.
	defaultCostPower = 18
)

// Encryptor is an encryptor that follows the Ethereum keystore V4 specification.
type Encryptor struct {
	cipher string
	cost   int
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
	Function string         `json:"function"`
	Params   map[string]any `json:"params"`
	Message  string         `json:"message"`
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
	cipher    string
	costPower uint
}

// Option gives options to New.
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

// WithCost sets the cipher key cost for the encryptor to 2^power overriding
// the default value. Higher values increases the cost of an exhaustive search
// but makes encoding and decoding proportionally slower.  This should only be
// in testing as it affects security. It panics if t is nil.
//
//nolint:thelper
func WithCost(t *testing.T, costPower uint) Option {
	if t == nil {
		panic("nil testing parameter")
	}

	return optionFunc(func(o *options) {
		o.costPower = costPower
	})
}

// New creates a new keystore V4 encryptor.
// This takes the following options:
// - cipher: the cipher to use when encrypting the secret, can be either "pbkdf2" (default) or "scrypt".
// - costPower: the cipher key cost to use as power of 2.
func New(opts ...Option) *Encryptor {
	options := options{
		cipher:    algoPbkdf2,
		costPower: defaultCostPower,
	}
	for _, o := range opts {
		o.apply(&options)
	}

	return &Encryptor{
		cipher: options.cipher,
		cost:   1 << options.costPower,
	}
}

// Name returns the name of this encryptor.
func (e *Encryptor) Name() string {
	return name
}

// Version returns the version of this encryptor.
func (e *Encryptor) Version() uint {
	return version
}

// String returns a string representing this encryptor.
func (e *Encryptor) String() string {
	return fmt.Sprintf("%sv%d", name, version)
}
