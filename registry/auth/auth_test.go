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

package auth_test

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Senetas/crypto-cli/registry/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreds(t *testing.T) {
	require := require.New(t)

	user := "ahab"
	pass := "hunter2"
	encoded := base64.URLEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", user, pass)))

	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := ioutil.ReadAll(r.Body)
			require.NoError(err)
			if r.Header.Get("Authorization") == fmt.Sprintf("Basic %s", encoded) {
				w.WriteHeader(http.StatusOK)
			} else {
				w.WriteHeader(http.StatusForbidden)
			}
		}),
	)
	defer server.Close()

	creds := auth.NewCreds(user, pass)
	req, err := http.NewRequest("GET", server.URL, nil)
	require.NoError(err)

	creds.SetAuth(req)
	client := http.DefaultClient

	resp, err := client.Do(req)
	require.NoError(err)

	defer func() { require.NoError(resp.Body.Close()) }()

	require.Equal(http.StatusOK, resp.StatusCode)
}

func TestChallengerLoc(t *testing.T) {
	assert := assert.New(t)
	invalidHeader := `Bearer realm=,service=,scope="repository:my-repo/my-alpine:pull,push"`

	tests := []struct {
		header string
		errMsg string
	}{
		{
			`Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:my-repo/my-alpine:pull,push"`,
			"",
		},
		{
			invalidHeader,
			fmt.Sprintf("malformed challenge header: %s", invalidHeader),
		},
	}

	for _, test := range tests {
		_, err := auth.ParseChallengeHeader(test.header)
		if err != nil {
			assert.EqualError(err, test.errMsg)
		} else {
			assert.Equal("", test.errMsg)
		}
	}
}
