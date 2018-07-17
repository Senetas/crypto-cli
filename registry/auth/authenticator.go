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

	"github.com/Senetas/crypto-cli/registry"
	"github.com/Senetas/crypto-cli/utils"
	"github.com/pkg/errors"
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

func (a *authenticator) Authenticate(c *Challenge) (Token, error) {
	reqURL := c.buildURL()
	req, err := http.NewRequest("GET", reqURL.String(), nil)
	if err != nil {
		return nil, errors.Wrapf(err, "url = %s", reqURL)
	}

	req = a.credentials.SetAuth(req)

	resp, err := registry.DoRequest(a.httpClient, req, true, true)
	if err != nil {
		return nil, errors.Wrapf(err, "req = %#v", req)
	}

	if resp.Close {
		defer func() { err = utils.CheckedClose(resp.Body, err) }()
	}

	if resp.StatusCode != http.StatusOK {
		return nil, errors.Errorf("authentication failed with status: %s", resp.Status)
	}

	return decodeRespose(resp.Body)
}
