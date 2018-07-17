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

package auth

import (
	"net/http"
	"net/http/httputil"

	"github.com/Senetas/crypto-cli/utils"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
)

// Authenticator produces a Bearer token to authenticate with the HTTP API
type Authenticator interface {
	Authenticate(c *Challenge) (Token, error)
}

type authenticator struct {
	httpClient  *http.Client
	credentials Credentials
}

// NewAuthenticator creates a new Authenticator
func NewAuthenticator(client *http.Client, credentials Credentials) Authenticator {
	return &authenticator{
		httpClient:  client,
		credentials: credentials,
	}
}

func doRequest(client *http.Client, req *http.Request, dumpReqBody, dumpRespBody bool) (*http.Response, error) {
	dump, err := httputil.DumpRequestOut(req, dumpReqBody)
	if err != nil {
		return nil, errors.Wrapf(err, "%#v", req)
	}
	log.Debug().Msg(req.URL.String())
	log.Debug().Msgf("%s", dump)

	resp, err := client.Do(req)
	if err != nil {
		err = errors.Wrapf(err, "%#v", req)
	}

	dump, err = httputil.DumpResponse(resp, dumpRespBody)
	if err != nil {
		return nil, errors.Wrapf(err, "%#v", resp)
	}
	log.Debug().Msgf("%s", dump)

	return resp, err
}

func (a *authenticator) Authenticate(c *Challenge) (Token, error) {
	reqURL := c.buildURL()
	req, err := http.NewRequest("GET", reqURL.String(), nil)
	if err != nil {
		return nil, errors.Wrapf(err, "url = %s", reqURL)
	}

	req, err = a.credentials.SetAuth(req)
	if err != nil {
		return nil, err
	}

	//resp, err := a.httpClient.Do(req)
	resp, err := doRequest(a.httpClient, req, true, true)
	if err != nil {
		return nil, errors.Wrapf(err, "req = %#v", req)
	}

	if resp.Close {
		defer func() { err = utils.CheckedClose(resp.Body, err) }()
	}

	if resp.StatusCode != http.StatusOK {
		return nil, errors.Errorf("authentication failed with status: %s", resp.Status)
	}

	decodedResp, err := decodeRespose(resp.Body)
	if err != nil {
		return nil, errors.Wrapf(err, "error decoding response: %#v", resp)
	}

	return newToken(decodedResp.Token, true), nil
}
