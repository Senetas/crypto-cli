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
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Senetas/crypto-cli/crypto"
	"github.com/Senetas/crypto-cli/distribution"
	"github.com/google/uuid"
	digest "github.com/opencontainers/go-digest"
	"github.com/udhos/equalfile"
)

var (
	passphrase = "196884 = 196883 + 1"
	opts       = &crypto.Opts{
		Salt:    "MgSO4(H2O)x",
		EncType: crypto.Pbkdf2Aes256Gcm,
		Compat:  false,
	}
)

type ConstReader byte

func (r ConstReader) Read(b []byte) (int, error) {
	for i := range b {
		b[i] = byte(r)
	}
	return len(b), nil
}

func TestCrypto(t *testing.T) {
	opts.SetPassphrase(passphrase)

	c, err := distribution.NewDecrypto(opts)
	if err != nil {
		t.Fatal("could not create decrypto")
	}

	e, err := distribution.EncryptKey(*c, opts)
	if err != nil {
		t.Fatal(err)
	}

	d, err := distribution.DecryptKey(e, opts)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(*c, d) {
		t.Fatalf("inversion failed, c = %s, d = %s", c, d)
	}
}

func TestCryptoBlobs(t *testing.T) {
	opts.SetPassphrase(passphrase)

	dir := filepath.Join(os.TempDir(), "com.senetas.crypto", uuid.New().String())
	size, d, fn := mkTempFile(t, dir)
	encpath := filepath.Join(dir, "enc")
	decpath := filepath.Join(dir, "dec")

	c, err := distribution.NewDecrypto(opts)
	if err != nil {
		t.Fatal(err)
	}

	blob := distribution.NewLayer(fn, d, size, c)

	enc, err := blob.EncryptBlob(opts, encpath+"file")
	if err != nil {
		t.Error(err)
	}

	dec, err := enc.DecryptBlob(opts, encpath+"file")
	if err != nil {
		t.Error(err)
	}

	cmp := equalfile.New(nil, equalfile.Options{})
	equal, err := cmp.CompareFile(fn, dec.GetFilename())
	if err != nil {
		t.Error(err)
	}

	if !equal {
		handleError(t, fn, decpath)
	}

	if blob.GetDigest().String() != dec.GetDigest().String() {
		t.Errorf("digests do not match: orig: %s decrypted: %s", blob.GetDigest(), dec.GetDigest())
	}

	if err = os.RemoveAll(dir); err != nil {
		t.Logf(err.Error())
	}
}

func TestCompressBlobs(t *testing.T) {
	opts.SetPassphrase(passphrase)

	dir := filepath.Join(os.TempDir(), "com.senetas.crypto", uuid.New().String())
	size, d, fn := createTempFile(t, dir)
	compath := filepath.Join(dir, "enc.gz")
	decpath := filepath.Join(dir, "dec")

	blob := distribution.NewPlainLayer(fn, d, size)

	com, err := blob.Compress(compath)
	if err != nil {
		t.Fatal(err)
	}

	dec, err := com.Decompress(decpath)
	if err != nil {
		t.Fatal(err)
	}

	cmp := equalfile.New(nil, equalfile.Options{})
	equal, err := cmp.CompareFile(fn, dec.GetFilename())
	if err != nil {
		t.Fatal(err)
	}

	if !equal {
		handleError(t, fn, decpath)
	}

	if blob.GetDigest().String() != dec.GetDigest().String() {
		t.Errorf("digests do not match: orig: %s decrypted: %s", blob.GetDigest(), dec.GetDigest())
	}

	if err = os.RemoveAll(dir); err != nil {
		t.Logf(err.Error())
	}
}

func createTempFile(t *testing.T, dir string) (int64, digest.Digest, string) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}

	file := filepath.Join(dir, "plain")
	fh, err := os.Create(file)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err = fh.Close(); err != nil {
			t.Log(err)
		}
	}()

	digester := digest.Canonical.Digester()
	mw := io.MultiWriter(digester.Hash(), fh)

	z := ConstReader(0)

	n, err := io.CopyN(mw, z, 1024)
	if err != nil {
		t.Fatal(err)
	}

	return n, digester.Digest(), file
}

func mkTempFile(t *testing.T, dir string) (int64, digest.Digest, string) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Error(err)
	}

	fn := filepath.Join(dir, "plain")
	fh, err := os.Create(fn)
	if err != nil {
		t.Error(err)
	}
	defer func() {
		if err = fh.Close(); err != nil {
			t.Log(err)
		}
	}()

	digester := digest.Canonical.Digester()
	mw := io.MultiWriter(digester.Hash(), fh)

	r := rand.Reader
	_, err = io.CopyN(mw, r, 1024)
	if err != nil {
		t.Error(err)
	}

	return 1024, digester.Digest(), fn
}

func handleError(t *testing.T, fn, decpath string) {
	fha, err := os.Open(fn)
	if err != nil {
		t.Error(err)
	}
	a, err := ioutil.ReadAll(fha)
	if err != nil {
		t.Error(err)
	}
	fhb, err := os.Open(decpath)
	if err != nil {
		t.Error(err)
	}
	b, err := ioutil.ReadAll(fhb)
	if err != nil {
		t.Error(err)
	}
	t.Errorf("decryption is not inverting encryption:\nPlaintext: %v\nDecrypted: %v", a, b)
}
