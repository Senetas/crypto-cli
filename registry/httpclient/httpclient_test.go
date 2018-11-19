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

package httpclient_test

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/Senetas/crypto-cli/registry/httpclient"
)

func TestHTTPClient(t *testing.T) {
	assert := assert.New(t)

	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		assert.Equal(req.URL.String(), "/")
		_, _ = rw.Write([]byte(`OK`))
	}))
	defer server.Close()

	req, err := http.NewRequest("GET", server.URL, nil)
	assert.Nil(err)

	resp, err := httpclient.DoRequest(httpclient.DefaultClient, req, true, true)
	assert.Nil(err)

	body := bytes.NewBuffer([]byte{})

	_, err = io.Copy(body, resp.Body)
	defer resp.Body.Close()
	assert.Nil(err)

	assert.Equal(body.String(), "OK")
}
