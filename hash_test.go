// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package hash_test

import (
	"crypto"
	"errors"
	"fmt"
	"strconv"
	"testing"

	"github.com/bytemare/hash"
)

type data struct {
	message []byte
	secret  []byte
	key     map[int]string
	salt    []byte
	info    []byte
}

var testData = &data{
	message: []byte("This is the message."),
	secret:  []byte("secret"),
	key: map[int]string{
		32: "2bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b",
		64: "bd2b1aaf7ef4f09be9f52ce2d8d599674d81aa9d6a4421696dc4d93dd0619d682ce56b4d64a9ef097761ced99e0f67265b5f76085e5b0ee7ca4696b2ad6fe2b2",
	},
	salt: nil,
	info: []byte("contextInfo"),
}

func TestAvailability(t *testing.T) {
	for _, id := range []hash.Hashing{hash.SHA256, hash.SHA512, hash.SHA3_256, hash.SHA3_512} {
		if !id.Available() {
			t.Errorf("%v is not available, but should be", id)
		}
	}

	wrong := hash.Hashing(crypto.MD4)
	if wrong.Available() {
		t.Errorf("%v is considered available when it should not", wrong)
	}
}

func TestID(t *testing.T) {
	ids := []struct {
		hash.Hashing
		crypto.Hash
	}{
		{
			hash.SHA256,
			crypto.SHA256,
		},
		{
			hash.SHA512,
			crypto.SHA512,
		},
		{
			hash.SHA3_256,
			crypto.SHA3_256,
		},
		{
			hash.SHA3_512,
			crypto.SHA3_512,
		},
	}

	for _, id := range ids {
		if id.Hash != id.Hashing.GetCryptoID() {
			t.Fatalf("GetCryptoID match error: %q vs. %q", id.Hash, id.Hashing.GetCryptoID())
		}

		if id.Hashing != hash.FromCrypto(id.Hash) {
			t.Fatalf("FromCrypto matching error: %q vs. %q", id.Hashing, hash.FromCrypto(id.Hash))
		}
	}
}

func TestHash(t *testing.T) {
	for _, id := range []hash.Hashing{hash.SHA256, hash.SHA512, hash.SHA3_256, hash.SHA3_512} {
		t.Run(strconv.Itoa(int(id)), func(t *testing.T) {
			h := id.Get()

			hh := h.Hash(testData.message)

			if len(hh) != h.OutputSize() {
				t.Errorf("#%v : invalid hash output length length. Expected %d, got %d", id, h.OutputSize(), len(hh))
			}
		})
	}

	for _, id := range []hash.Extendable{hash.SHAKE128, hash.SHAKE256, hash.BLAKE2XB, hash.BLAKE2XS} {
		t.Run(string(id), func(t *testing.T) {
			h := id.Get()

			hh := h.Hash(h.MinOutputSize(), testData.message)

			if len(hh) != h.MinOutputSize() {
				t.Errorf("#%v : invalid hash output length length. Expected %d, got %d", id, 32, len(hh))
			}
		})
	}
}

var (
	errNoPanic        = errors.New("no panic")
	errNoPanicMessage = errors.New("panic but no message")
)

func hasPanic(f func()) (has bool, err error) {
	err = nil
	var report interface{}
	func() {
		defer func() {
			if report = recover(); report != nil {
				has = true
			}
		}()

		f()
	}()

	if has {
		err = fmt.Errorf("%v", report)
	}

	return has, err
}

// expectPanic executes the function f with the expectation to recover from a panic. If no panic occurred or if the
// panic message is not the one expected, ExpectPanic returns (false, error).
func expectPanic(expectedError error, f func()) (bool, error) {
	hasPanic, err := hasPanic(f)

	if !hasPanic {
		return false, errNoPanic
	}

	if expectedError == nil {
		return true, nil
	}

	if err == nil {
		return false, errNoPanicMessage
	}

	if err.Error() != expectedError.Error() {
		return false, fmt.Errorf("expected %q, got: %w", expectedError, err)
	}

	return true, nil
}

func TestSmallXOFOutput(t *testing.T) {
	for _, id := range []hash.Extendable{hash.SHAKE128, hash.SHAKE256, hash.BLAKE2XB, hash.BLAKE2XS} {
		t.Run(string(id), func(t *testing.T) {
			h := id.Get()

			if hasPanic, _ := expectPanic(nil, func() {
				_ = h.Hash(h.MinOutputSize()-1, testData.message)
			}); !hasPanic {
				t.Fatal("expected panic")
			}
		})
	}
}
