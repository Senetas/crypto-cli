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
	"testing"

	"github.com/udhos/equalfile"

	"github.com/Senetas/crypto-cli/crypto"
)

func TestFile(t *testing.T) {
	dir, err := ioutil.TempDir("", "com.senetas.crypto")
	fn := dir + "/plain"
	fh, err := os.Create(fn)
	r := rand.Reader
	_, err = io.CopyN(fh, r, 1024)
	if err != nil {
		t.Errorf("Could not read random data into file")
	}

	if err = fh.Close(); err != nil {
		t.Logf(err.Error())
	}

	key, _, _, err := crypto.EncFile(fn, dir+"/enc")
	if err != nil {
		t.Errorf(err.Error())
	}

	t.Logf("%v\n", key)

	if err = crypto.DecFile(dir+"/enc", dir+"/dec", key); err != nil {
		t.Errorf(err.Error())
	}

	cmp := equalfile.New(nil, equalfile.Options{})
	equal, err := cmp.CompareFile(dir+"/plain", dir+"/dec")
	if err != nil {
		t.Errorf("%v\n", err)
	}
	if !equal {
		fha, err := os.Open(dir + "/plain")
		if err != nil {
			t.Errorf(err.Error())
		}
		a, err := ioutil.ReadAll(fha)
		if err != nil {
			t.Errorf(err.Error())
		}
		fhb, err := os.Open(dir + "/dec")
		if err != nil {
			t.Errorf(err.Error())
		}
		b, err := ioutil.ReadAll(fhb)
		if err != nil {
			t.Errorf(err.Error())
		}
		t.Errorf("decryption is not inverting encryption:\nPlaintext: %v\nDecrypted: %v", a, b)
	}

	if err = os.RemoveAll(dir); err != nil {
		t.Logf(err.Error())
	}
}
