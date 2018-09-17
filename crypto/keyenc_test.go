// Copyright © 2018 SENETAS SECURITY PTY LTD
//
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

package crypto_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/Senetas/crypto-cli/crypto"
	"github.com/Senetas/crypto-cli/utils"
)

var (
	//passphrase = "196884 = 196883 + 1"
	passphrase = "hunter2"
	opts       = &crypto.Opts{
		Algos:  crypto.Pbkdf2Aes256Gcm,
		Compat: false,
	}
	optsNone = &crypto.Opts{
		Algos:  crypto.None,
		Compat: false,
	}
	optsCompat = &crypto.Opts{
		Algos:  crypto.Pbkdf2Aes256Gcm,
		Compat: true,
	}
	optsMock = &crypto.Opts{
		Algos: crypto.Algos("mock"),
	}
	urlsValid   = []string{"https://crypto.senetas.com/?algos=PBKDF2-AES256-GCM&key=AAAAAAAAnECtJQZpzaepbGxVsLqfhEVdGEh3tadKd7w-wZIXTY-yMo8LidOYbJZ2axuUExIhDGPQZxyZzdzVD2OuiPyFMNj98Ju1rF-D2Sh2Qxd3"}
	urlsInvalid = []string{"http://crypto.senetas.com/?algos=PBKDF2-AES256-GCM&key=3m6X-rV110o2DEm3pU-8qZpV-7ZKbBroFkWOUaI1Dv0_WRaVceZy5tsJ-PMoOMUW5CScc2wpL-PoBPMVAen7Nf9BPPCdcbrtpmFsMw=="}
)

func TestCrypto(t *testing.T) {
	assert := assert.New(t)

	tests := []struct {
		opts       *crypto.Opts
		passphrase string
	}{
		{opts, passphrase},
		{optsNone, passphrase},
		{optsCompat, passphrase},
	}

	for _, test := range tests {
		test.opts.SetPassphrase(test.passphrase)

		c, err := crypto.NewDecrypto(test.opts)
		if !assert.NoError(err) {
			continue
		}

		e, err := crypto.EncryptKey(*c, test.opts)
		if !assert.NoError(err) {
			continue
		}

		d, err := crypto.DecryptKey(e, test.opts)
		if !assert.NoError(err) {
			continue
		}

		assert.Equal(*c, d)
	}
}

func TestEncDecCrypto(t *testing.T) {
	assert := assert.New(t)

	tests := []struct {
		opts    *crypto.Opts
		optsEnc *crypto.Opts
		optsDec *crypto.Opts
		errEnc  error
		errDec  error
	}{
		{
			opts,
			opts,
			opts,
			nil,
			nil,
		},
		{
			opts,
			optsNone,
			nil,
			utils.NewError("encryption type does not match decryption type", false),
			nil,
		},
		{
			opts,
			opts,
			optsNone,
			nil,
			utils.NewError("encryption type does not match decryption type", false),
		},
	}

	for _, test := range tests {
		d, err := crypto.NewDecrypto(test.opts)
		if !assert.NoError(err) {
			continue
		}

		e, err := crypto.EncryptKey(*d, test.optsEnc)
		if err != nil {
			assert.Equal(test.errEnc, err)
			continue
		}

		assert.NotNil(test.optsDec)
		assert.NotNil(e)

		c, err := crypto.DecryptKey(e, test.optsDec)
		if err != nil {
			assert.Equal(test.errDec, err)
			continue
		}

		assert.Equal(d, &c)
	}
}

func TestEncCrypto(t *testing.T) {
	assert := assert.New(t)

	tests := []struct {
		opts     *crypto.Opts
		encrypto *crypto.EnCrypto
		errMsg   string
	}{
		{
			opts,
			&crypto.EnCrypto{
				Crypto: crypto.Crypto{
					Algos:   crypto.Pbkdf2Aes256Gcm,
					Version: -1,
				},
			},
			"unknown version",
		},
		{
			opts,
			&crypto.EnCrypto{
				Crypto: crypto.Crypto{
					Algos:   crypto.Pbkdf2Aes256Gcm,
					Version: 0,
					Salt:    make([]byte, 0),
				},
			},
			"salt is wrong length",
		},
		{
			opts,
			&crypto.EnCrypto{
				Crypto: crypto.Crypto{
					Algos:   crypto.Pbkdf2Aes256Gcm,
					Version: 0,
					Salt:    make([]byte, 16),
					Nonce:   make([]byte, 0),
				},
			},
			"nonce is wrong length",
		},
	}

	for _, test := range tests {
		opts.SetPassphrase(passphrase)
		_, err := crypto.DecryptKey(*test.encrypto, test.opts)
		_ = err != nil && assert.EqualError(err, test.errMsg) || !assert.Equal(test.errMsg, "")
	}
}

func TestEncDecCryptoCompat(t *testing.T) {
	assert := assert.New(t)

	tests := []struct {
		urls   []string
		opts   *crypto.Opts
		errMsg string
	}{
		{urlsValid, opts, ""},
		{urlsInvalid, opts, ""},
		{[]string{}, opts, "missing encryption key"},
		{urlsValid, optsNone, "encryption type does not match decryption type"},
	}

	for _, test := range tests {
		_, err := crypto.NewEncryptoCompat(test.urls, test.opts)
		if err != nil {
			assert.Error(err, test.errMsg)
		} else {
			assert.Equal(test.errMsg, "")
		}
	}
}
