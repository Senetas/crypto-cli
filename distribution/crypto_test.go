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

package distribution_test

import (
	"crypto/rand"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	digest "github.com/opencontainers/go-digest"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/udhos/equalfile"

	"github.com/Senetas/crypto-cli/crypto"
	"github.com/Senetas/crypto-cli/distribution"
	"github.com/Senetas/crypto-cli/utils"
)

var (
	passphrase = "196884 = 196883 + 1"
	opts       = &crypto.Opts{
		Salt:    "MgSO4(H2O)x",
		EncType: crypto.Pbkdf2Aes256Gcm,
		Compat:  false,
	}
	optsCompat = &crypto.Opts{
		Salt:    "MgSO4(H2O)x",
		EncType: crypto.Pbkdf2Aes256Gcm,
		Compat:  true,
	}
)

func TestCrypto(t *testing.T) {
	assert := assert.New(t)

	tests := []struct {
		opts       *crypto.Opts
		passphrase string
	}{
		{opts, passphrase},
		{optsCompat, passphrase},
	}

	for _, test := range tests {
		test.opts.SetPassphrase(test.passphrase)

		c, err := distribution.NewDecrypto(test.opts)
		if !assert.Nil(err) {
			continue
		}

		e, err := distribution.EncryptKey(*c, test.opts)
		if !assert.Nil(err) {
			continue
		}

		d, err := distribution.DecryptKey(e, test.opts)
		if !assert.Nil(err) {
			continue
		}

		if !assert.Equal(*c, d) {
			t.Fatalf("inversion failed, c = %s, d = %s", c, d)
		}

	}
}

func TestCryptoBlobs(t *testing.T) {
	assert := assert.New(t)

	tests := []struct {
		opts       *crypto.Opts
		passphrase string
	}{
		{opts, passphrase},
		{optsCompat, passphrase},
	}

	for _, test := range tests {
		test.opts.SetPassphrase(test.passphrase)

		dir := filepath.Join(os.TempDir(), "com.senetas.crypto", uuid.New().String())
		size, d, fn, err := mkRandFile(t, dir)
		defer func() {
			if err = os.RemoveAll(dir); err != nil {
				t.Logf(err.Error())
			}
		}()
		if !assert.Nil(err) {
			continue
		}

		encpath := filepath.Join(dir, "enc")
		decpath := filepath.Join(dir, "dec")

		c, err := distribution.NewDecrypto(opts)
		if !assert.Nil(err) {
			continue
		}

		blob := distribution.NewLayer(fn, d, size, c)

		enc, err := blob.EncryptBlob(opts, encpath)
		if !assert.Nil(err) {
			continue
		}

		dec, err := enc.DecryptBlob(opts, decpath)
		if !assert.Nil(err) {
			continue
		}

		if err = blobTest(t, dir, fn, encpath, decpath, blob, enc, dec); err != nil {
			t.Error(err)
		}
	}
}

func TestCompressBlobs(t *testing.T) {
	dir := filepath.Join(os.TempDir(), "com.senetas.crypto", uuid.New().String())
	size, d, fn, err := mkConstFile(t, dir)
	if err != nil {
		t.Error(err)
		return
	}
	compath := filepath.Join(dir, "enc.gz")
	decpath := filepath.Join(dir, "dec")

	defer func() {
		if err = os.RemoveAll(dir); err != nil {
			t.Logf(err.Error())
		}
	}()

	blob := distribution.NewPlainLayer(fn, d, size)

	comp, err := blob.Compress(compath)
	if err != nil {
		t.Error(err)
		return
	}

	dec, err := comp.Decompress(decpath)
	if err != nil {
		t.Error(err)
		return
	}

	if err = blobTest(t, dir, fn, compath, decpath, blob, comp, dec); err != nil {
		t.Error(err)
	}
}

func blobTest(
	t *testing.T,
	dir, filename, convpath, deconvpath string,
	blob, conv, deconv distribution.Blob,
) (err error) {
	fi, err := os.Stat(convpath)
	if err != nil {
		return
	} else if fi.Size() != conv.GetSize() {
		t.Error(errors.Errorf("converted file is incorrect size: %d vs %d", fi.Size(), conv.GetSize()))
	}

	fi, err = os.Stat(deconvpath)
	if err != nil {
		return
	} else if fi.Size() != deconv.GetSize() {
		t.Error(errors.Errorf("decompressed file is incorrect size: %d vs %d", fi.Size(), deconv.GetSize()))
	}

	equal, err := equalfile.CompareFile(filename, deconv.GetFilename())
	if err != nil {
		return
	}

	if !equal {
		showContents(t, filename, deconvpath)
		return
	}

	if blob.GetDigest().String() != deconv.GetDigest().String() {
		err = errors.Errorf(
			"digests do not match: orig: %s decrypted: %s",
			blob.GetDigest(),
			deconv.GetDigest(),
		)
	}
	return
}

func mkConstFile(t *testing.T, dir string) (_ int64, _ digest.Digest, _ string, err error) {
	if err = os.MkdirAll(dir, 0700); err != nil {
		return
	}

	file := filepath.Join(dir, "plain")
	fh, err := os.Create(file)
	if err != nil {
		return
	}
	defer func() {
		if err = fh.Close(); err != nil {
			t.Log(err)
		}
	}()

	digester := digest.Canonical.Digester()
	mw := io.MultiWriter(digester.Hash(), fh)

	z := utils.ConstReader(0)

	n, err := io.CopyN(mw, z, 1024)
	if err != nil {
		return
	}

	return n, digester.Digest(), file, nil
}

func mkRandFile(t *testing.T, dir string) (_ int64, _ digest.Digest, _ string, err error) {
	if err = os.MkdirAll(dir, 0700); err != nil {
		return
	}

	fn := filepath.Join(dir, "plain")
	fh, err := os.Create(fn)
	if err != nil {
		return
	}
	defer func() {
		if err = fh.Close(); err != nil {
			t.Log(err)
		}
	}()

	digester := digest.Canonical.Digester()
	mw := io.MultiWriter(digester.Hash(), fh)

	r := rand.Reader

	n, err := io.CopyN(mw, r, 1024)
	if err != nil {
		return
	}

	return n, digester.Digest(), fn, nil
}

func showContents(t *testing.T, fn, decpath string) error {
	a := readFile(t, fn)
	b := readFile(t, decpath)
	return errors.Errorf("decryption is not inverting encryption:\nPlaintext: %v\nDecrypted: %v", a, b)
}

func readFile(t *testing.T, filename string) []byte {
	fh, err := os.Open(filename)
	if err != nil {
		return []byte(fmt.Sprintf("[could not read %s]", filename))
	}
	contents, err := ioutil.ReadAll(fh)
	if err != nil {
		return []byte(fmt.Sprintf("[could not read %s]", filename))
	}
	return contents
}
