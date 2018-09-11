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
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/docker/distribution/reference"
	dregistry "github.com/docker/docker/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Senetas/crypto-cli/registry"
	"github.com/Senetas/crypto-cli/registry/auth"
	"github.com/Senetas/crypto-cli/registry/httpclient"
	"github.com/Senetas/crypto-cli/registry/names"
)

const imageName = "cryptocli/alpine:test"

func TestAuthenticator(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := ioutil.ReadAll(r.Body)
			require.NoError(err)
			w.WriteHeader(http.StatusUnauthorized)
		}),
	)
	defer server.Close()

	tests := []struct {
		challenge string
		errMsg    string
	}{
		{
			`Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:cryptocli:pull,push"`,
			"",
		},
		{
			fmt.Sprintf(
				`Bearer realm="%s",service="registry.docker.io",scope="repository:cryptocli:pull,push"`,
				server.URL,
			),
			fmt.Sprintf(
				"authentication failed with status: %d %s",
				http.StatusUnauthorized,
				http.StatusText(http.StatusUnauthorized),
			),
		},
	}

	for _, test := range tests {
		ref, err := reference.ParseNormalizedNamed(imageName)
		if !assert.NoError(err) {
			continue
		}

		repoInfo, err := dregistry.ParseRepositoryInfo(ref)
		if !assert.NoError(err) {
			continue
		}

		creds, err := auth.NewDefaultCreds(repoInfo)
		if !assert.NoError(err) {
			continue
		}

		ch, err := auth.ParseChallengeHeader(test.challenge)
		if !assert.NoError(err) {
			continue
		}

		_, err = auth.NewAuthenticator(httpclient.DefaultClient, creds).Authenticate(ch)
		if err != nil {
			assert.EqualError(err, test.errMsg)
		} else {
			assert.Equal(test.errMsg, "")
		}
	}
}

func TestChallenger(t *testing.T) {
	require := require.New(t)

	ref, err := reference.ParseNormalizedNamed(imageName)
	require.NoError(err)

	nTRep, err := names.CastToTagged(ref)
	require.NoError(err)

	repoInfo, err := dregistry.ParseRepositoryInfo(ref)
	require.NoError(err)

	endpoint, err := registry.GetEndpoint(ref, *repoInfo)
	require.NoError(err)

	creds, err := auth.NewDefaultCreds(repoInfo)
	require.NoError(err)

	header, err := auth.ChallengeHeader(nTRep, *repoInfo, endpoint, creds)
	require.NoError(err)

	ch, err := auth.ParseChallengeHeader(header)
	require.NoError(err)

	_, err = auth.NewAuthenticator(httpclient.DefaultClient, creds).Authenticate(ch)
	require.NoError(err)
}
