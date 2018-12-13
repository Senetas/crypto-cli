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

	"github.com/docker/cli/cli/config"
	"github.com/docker/docker/api/types"
	dregistry "github.com/docker/docker/registry"

	"github.com/pkg/errors"
)

// Credentials represents a username password pair
type Credentials interface {
	SetAuth(r *http.Request) *http.Request
}

type credentials struct {
	types.AuthConfig
}

// NewCreds creates a new Credentials with a username and password
func NewCreds(username, password string) Credentials {
	return &credentials{
		types.AuthConfig{
			Username: username,
			Password: password,
		},
	}
}

// NewDefaultCreds creates a credentials struct from the credentials in
// the default conf file, typically ~/.docker/config.json. the struct is lazy,
// i.e. the file is only read if the username or password is accessed
func NewDefaultCreds(repoInfo *dregistry.RepositoryInfo) (creds Credentials, err error) {
	confFile, err := config.Load("")
	if err != nil {
		err = errors.WithStack(err)
		return
	}

	serverAddress := dregistry.IndexServer
	store := confFile.GetCredentialsStore(serverAddress)

	authConfig, err := store.Get(serverAddress)
	if err != nil {
		err = errors.WithStack(err)
		return
	}

	creds = NewCreds(authConfig.Username, authConfig.Password)

	return
}

func (c *credentials) SetAuth(req *http.Request) *http.Request {
	req.SetBasicAuth(c.Username, c.Password)
	q := req.URL.Query()
	q.Set("account", c.Username)
	req.URL.RawQuery = q.Encode()
	return req
}
