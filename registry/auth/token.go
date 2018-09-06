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
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/docker/distribution/registry/client/auth"
	"github.com/pkg/errors"
)

// Token is the Bearer token to be used with API calls
type Token interface {
	String() string
	Fresh() bool
}

type token struct {
	Token string `json:"token"`
	fresh bool
}

func (t *token) String() string {
	return t.Token
}

func (t *token) Fresh() bool {
	return t.fresh
}

func decodeRespose(respBody io.Reader) (Token, error) {
	t := &token{}
	if err := json.NewDecoder(respBody).Decode(&t); err != nil {
		return nil, errors.Wrapf(err, "could not decode response from auth server")
	}
	if t.Token == "" {
		return nil, errors.New("malformed response from auth server")
	}
	return t, nil
}

// AddToReqest adds a token as a Bearer Authorization of a request
func AddToReqest(t auth.Scope, req *http.Request) {
	if t != nil && t.String() != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", t))
	}
}
