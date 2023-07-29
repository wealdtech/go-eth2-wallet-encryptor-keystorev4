// Copyright © 2020, 2021 Weald Technology Trading
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
	"strings"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

var stripChars = map[byte]bool{
	0x00: true,
	0x01: true,
	0x02: true,
	0x03: true,
	0x04: true,
	0x05: true,
	0x06: true,
	0x07: true,
	0x08: true,
	0x09: true,
	0x0a: true,
	0x0b: true,
	0x0c: true,
	0x0d: true,
	0x0e: true,
	0x0f: true,
	0x10: true,
	0x11: true,
	0x12: true,
	0x13: true,
	0x14: true,
	0x15: true,
	0x16: true,
	0x17: true,
	0x18: true,
	0x19: true,
	0x1a: true,
	0x1b: true,
	0x1c: true,
	0x1d: true,
	0x1e: true,
	0x1f: true,
	0x7f: true,
	0x80: true,
	0x81: true,
	0x82: true,
	0x83: true,
	0x84: true,
	0x85: true,
	0x86: true,
	0x87: true,
	0x88: true,
	0x89: true,
	0x8a: true,
	0x8b: true,
	0x8c: true,
	0x8d: true,
	0x8e: true,
	0x8f: true,
	0x90: true,
	0x91: true,
	0x92: true,
	0x93: true,
	0x94: true,
	0x95: true,
	0x96: true,
	0x97: true,
	0x98: true,
	0x99: true,
	0x9a: true,
	0x9b: true,
	0x9c: true,
	0x9d: true,
	0x9e: true,
	0x9f: true,
}

// normPassphrase normalises a passphrase, as per the rules at
// https://eips.ethereum.org/EIPS/eip-2335#password-requirements
func normPassphrase(input string) string {
	res := strings.Builder{}
	str := norm.NFKD.String(input)

	for _, rune := range str {
		if len(string(rune)) == 1 && stripChars[string(rune)[0]] {
			continue
		}
		res.WriteRune(rune)
	}

	return res.String()
}

// altNormPassphrase is the old method for normalising a passphrase.  It is
// known to give different (non-standard) results under certain
// circumstances (e.g. when the passphrase contains 'ü').
func altNormPassphrase(input string) string {
	var output []byte
	iter := &norm.Iter{}
	iter.InitString(norm.NFKD, input)

	for !iter.Done() {
		r, _ := utf8.DecodeRune(iter.Next())
		buf := make([]byte, utf8.RuneLen(r))
		utf8.EncodeRune(buf, r)
		if len(buf) == 1 && stripChars[buf[0]] {
			continue
		}
		output = norm.NFKD.Append(output, buf...)
	}

	return string(output)
}
