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
	"net/http"
	"os"
	"testing"

	"github.com/Senetas/crypto-cli/registry"
	"github.com/Senetas/crypto-cli/registry/auth"
	"github.com/docker/distribution/reference"
	dregistry "github.com/docker/docker/registry"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func TestAuthenticator(t *testing.T) {
	ref, err := reference.ParseNormalizedNamed("narthanaepa1/my-alpine:test")
	if err != nil {
		t.Fatal(err)
	}

	repoInfo, err := dregistry.ParseRepositoryInfo(ref)
	if err != nil {
		t.Fatal(err)
	}

	creds, err := auth.NewDefaultCreds(repoInfo)
	if err != nil {
		t.Fatal(err)
	}

	a := auth.NewAuthenticator(http.DefaultClient, creds)
	ch, err := auth.ParseChallengeHeader(`Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:narthanaepa1:pull,push"`)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := a.Authenticate(ch)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(tok)
}

func TestChallenger(t *testing.T) {
	ref, err := reference.ParseNormalizedNamed("narthanaepa1/my-alpine:test")
	if err != nil {
		t.Fatal(err)
	}

	nTRep, err := registry.ResolveNamed(ref)
	if err != nil {
		t.Fatal(err)
	}

	repoInfo, err := dregistry.ParseRepositoryInfo(ref)
	if err != nil {
		t.Fatal(err)
	}

	endpoint, err := registry.GetEndpoint(ref, *repoInfo)
	if err != nil {
		t.Fatal(err)
	}

	creds, err := auth.NewDefaultCreds(repoInfo)
	if err != nil {
		t.Fatal(err)
	}

	header, err := auth.ChallengeHeader(nTRep, *repoInfo, endpoint, creds)

	a := auth.NewAuthenticator(registry.DefaultClient, creds)
	ch, err := auth.ParseChallengeHeader(header)
	if err != nil {
		t.Fatal(err)
	}

	tok, err := a.Authenticate(ch)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(tok)
}

func init() {
	// use UNIX time for logs
	zerolog.TimeFieldFormat = ""

	// use a prettier logger
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
}
