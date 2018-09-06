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

package images

import (
	"net/http"
	"net/url"

	"github.com/docker/distribution/reference"
	"github.com/docker/distribution/registry/api/v2"
	dregistry "github.com/docker/docker/registry"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"

	"github.com/Senetas/crypto-cli/registry"
	"github.com/Senetas/crypto-cli/registry/auth"
	"github.com/Senetas/crypto-cli/registry/httpclient"
	"github.com/Senetas/crypto-cli/registry/names"
	"github.com/Senetas/crypto-cli/utils"
)

// useTLS determines whether the registry requires TLS
func useTLS(
	ref names.NamedRepository,
	repoInfo dregistry.RepositoryInfo,
	endpoint dregistry.APIEndpoint,
) (_ bool, err error) {
	endpoint.URL.Scheme = "http"
	bldr := v2.NewURLBuilder(endpoint.URL, false)

	urlStr, err := bldr.BuildBaseURL()
	if err != nil {
		err = errors.Wrapf(err, "base = %s", endpoint.URL)
		return
	}

	req, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		err = errors.Wrapf(err, "url = %s", urlStr)
		return
	}

	httpClient := *httpclient.DefaultClient
	httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	resp, err := httpclient.DoRequest(&httpClient, req, true, false)
	if resp != nil {
		defer func() { err = utils.CheckedClose(resp.Body, err) }()
	}
	if err != nil {
		return
	}

	switch resp.StatusCode {
	case http.StatusMovedPermanently:
		loc := resp.Header.Get("Location")
		u, err := url.Parse(loc)
		if err != nil {
			return false, errors.WithStack(err)
		}
		if u.Scheme == "https" {
			endpoint.URL.Scheme = "https"
			return true, nil
		}
		return false, nil
	case http.StatusOK:
		return false, nil
	default:
		return false, errors.Errorf("status code %s from server", resp.Status)
	}
}

func authProcedure(ref reference.Named) (
	_ auth.Token,
	_ names.NamedTaggedRepository,
	_ *dregistry.APIEndpoint,
	err error,
) {
	nTRep, err := names.CastToTagged(ref)
	if err != nil {
		return
	}

	repoInfo, err := dregistry.ParseRepositoryInfo(ref)
	if err != nil {
		err = errors.Wrapf(err, "could not parse ref = %v", ref)
		return
	}

	endpoint, err := registry.GetEndpoint(ref, *repoInfo)
	if err != nil {
		err = errors.Wrapf(err, "could not get endpoint ref = %v, repoInfo = %v", ref, *repoInfo)
		return
	}

	tls, err := useTLS(nTRep, *repoInfo, endpoint)
	if err != nil {
		return
	}
	if !tls {
		return nil, nTRep, &endpoint, nil
	}

	creds, err := auth.NewDefaultCreds(repoInfo)
	if err != nil {
		return
	}

	authenticator := auth.NewAuthenticator(httpclient.DefaultClient, creds)
	header, err := auth.ChallengeHeader(nTRep, *repoInfo, endpoint, creds)
	if err != nil {
		return
	}

	ch, err := auth.ParseChallengeHeader(header)
	if err != nil {
		return
	}

	token, err := authenticator.Authenticate(ch)
	if err != nil {
		return
	}

	log.Info().Msg("Authentication successful.")

	return token, nTRep, &endpoint, nil
}
