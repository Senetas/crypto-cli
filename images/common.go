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
	"os"
	"path/filepath"

	"github.com/docker/distribution/reference"
	"github.com/docker/distribution/registry/api/v2"
	dregistry "github.com/docker/docker/registry"
	"github.com/pkg/errors"

	"github.com/Senetas/crypto-cli/registry"
	"github.com/Senetas/crypto-cli/registry/auth"
	"github.com/Senetas/crypto-cli/registry/types"
	"github.com/Senetas/crypto-cli/utils"
)

const (
	labelString = "LABEL com.senetas.crypto.enabled=true"
	saltBase    = "com.senetas.crypto/%s/%s"
	configSalt  = saltBase + "/config"
	layerSalt   = saltBase + "/layer%d"
)

var tempRoot = filepath.Join(os.TempDir(), "com.senetas.crypto")

// useTLS determines whether the registry requires TLS
func useTLS(
	ref types.NamedRepository,
	repoInfo dregistry.RepositoryInfo,
	endpoint dregistry.APIEndpoint,
) (bool, error) {
	endpoint.URL.Scheme = "http"
	bldr := v2.NewURLBuilder(endpoint.URL, false)

	urlStr, err := bldr.BuildBaseURL()
	if err != nil {
		return false, errors.Wrapf(err, "base = %s", endpoint.URL)
	}

	req, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		return false, errors.Wrapf(err, "url = %s", urlStr)
	}

	httpClient := *registry.DefaultClient
	httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	resp, err := registry.DoRequest(&httpClient, req, true, false)
	if err != nil {
		return false, err
	}
	defer func() { err = utils.CheckedClose(resp.Body, err) }()

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
	auth.Token,
	types.NamedTaggedRepository,
	*dregistry.APIEndpoint,
	error,
) {
	nTRep, err := types.CastToTagged(ref)
	if err != nil {
		return nil, nil, nil, err
	}

	repoInfo, err := dregistry.ParseRepositoryInfo(ref)
	if err != nil {
		return nil, nil, nil, errors.Wrapf(err, "could not parse ref = %v", ref)
	}

	endpoint, err := registry.GetEndpoint(ref, *repoInfo)
	if err != nil {
		return nil, nil, nil,
			errors.Wrapf(err, "could not get endpoint ref = %v, repoInfo = %v", ref, *repoInfo)
	}

	tls, err := useTLS(nTRep, *repoInfo, endpoint)
	if err != nil {
		return nil, nil, nil, err
	}
	if !tls {
		return nil, nTRep, &endpoint, nil
	}

	creds, err := auth.NewDefaultCreds(repoInfo)
	if err != nil {
		return nil, nil, nil, err
	}

	authenticator := auth.NewAuthenticator(registry.DefaultClient, creds)
	header, err := auth.ChallengeHeader(nTRep, *repoInfo, endpoint, creds)
	ch, err := auth.ParseChallengeHeader(header)
	if err != nil {
		return nil, nil, nil, err
	}

	token, err := authenticator.Authenticate(ch)
	if err != nil {
		return nil, nil, nil, err
	}

	return token, nTRep, &endpoint, nil
}

// cleanup temporary files
func cleanup(dir string, err error) error {
	if dir == "" {
		return err
	}
	if err2 := os.RemoveAll(dir); err2 != nil {
		err2 = errors.Wrapf(err, "could not clean up temp files in: %s", dir)
		if err == nil {
			return err2
		}
		return utils.Errors{err, err2}
	}
	return err
}
