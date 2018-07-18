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
	"crypto/rand"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/udhos/equalfile"

	"github.com/Senetas/crypto-cli/crypto"
)

func TestFile(t *testing.T) {
	dir := filepath.Join(os.TempDir(), "com.senetas.crypto")

	fn := mkTempFile(t, dir)

	encpath := filepath.Join(dir, "enc")
	decpath := filepath.Join(dir, "dec")

	key, err := crypto.GenDataKey()
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err = crypto.EncFile(fn, filepath.Join(dir, "enc"), key); err != nil {
		t.Error(err)
	}

	t.Logf("%v\n", key)

	if err = crypto.DecFile(encpath, decpath, key); err != nil {
		t.Error(err)
	}

	cmp := equalfile.New(nil, equalfile.Options{})
	equal, err := cmp.CompareFile(fn, decpath)
	if err != nil {
		t.Error(err)
	}

	if !equal {
		handleError(t, fn, decpath)
	}

	if err = os.RemoveAll(dir); err != nil {
		t.Logf(err.Error())
	}

}

func mkTempFile(t *testing.T, dir string) string {
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Error(err)
	}

	fn := filepath.Join(dir, "plain")
	fh, err := os.Create(fn)
	if err != nil {
		t.Error(err)
	}

	r := rand.Reader
	_, err = io.CopyN(fh, r, 1024)
	if err != nil {
		t.Error(err)
	}

	if err = fh.Close(); err != nil {
		t.Log(err)
	}
	return fn
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
